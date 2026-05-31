import os
import re
import time
import ipaddress
from functools import wraps
from flask import request, abort, session
from flask_login import current_user

# FIX: now_pst was never imported here — block_ip() called it and crashed
# silently on every honeypot hit, meaning no IP was ever written to blocked_ips.
from app.models.logs import now_pst

# ── Paths to skip activity logging ───────────────────────────────────────────
_SKIP_LOGGING_PREFIXES = (
    "/api/",
    "/static/",
    "/camera/stream",
    "/camera/status",
    "/logout",   # logout is logged explicitly in the route with the correct username
)

# ── Action label map ──────────────────────────────────────────────────────────
_ACTION_MAP = [
    ("POST", r"^/login$",                      "Login attempt"),
    ("POST", r"^/register$",                   "Registration"),
    ("GET",  r"^/logout$",                     "Logged out"),
    ("GET",  r"^/dashboard$",                  "Viewed Dashboard"),
    ("GET",  r"^/dashboard/activity",          "Viewed Activity Log"),
    ("GET",  r"^/dashboard/alerts",            "Viewed Alerts"),
    ("GET",  r"^/camera/?$",                   "Viewed Camera Feed"),
    ("GET",  r"^/admin/?$",                    "Opened Admin Panel"),
    ("GET",  r"^/admin/logs",                  "Viewed Access Logs"),
    ("POST", r"^/admin/users/\d+/approve",     "Approved a user"),
    ("POST", r"^/admin/users/\d+/revoke",      "Revoked user access"),
    ("POST", r"^/admin/users/\d+/delete",      "Deleted a user"),
    ("POST", r"^/admin/ip/add",                "Added IP to allowlist"),
    ("POST", r"^/admin/ip/\d+/delete",         "Removed IP from allowlist"),
    ("POST", r"^/admin/alerts/\d+/resolve",    "Resolved an alert"),
    ("POST", r"^/camera/ingest",               "Camera frame received"),
]

def _get_action_label(method, path):
    for m, pattern, label in _ACTION_MAP:
        if method == m and re.match(pattern, path):
            return label
    if method == "GET":
        return f"Viewed {path}"
    if method == "POST":
        return f"Submitted {path}"
    return f"{method} {path}"

def _should_log(path):
    for prefix in _SKIP_LOGGING_PREFIXES:
        if path.startswith(prefix):
            return False
    return True


# ── IP detection ──────────────────────────────────────────────────────────────
def _get_real_ip():
    # Railway sits behind a load balancer — the real client IP is in
    # X-Forwarded-For. ProxyFix(x_for=1) in __init__.py rewrites
    # request.remote_addr for most code paths, but calling this helper
    # directly (e.g. from camera.py before the middleware rewrites it)
    # would return the load-balancer address. Read XFF explicitly so
    # every caller gets the true client IP regardless of call site.
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

_COMMON_PASSWORDS = {
    "password", "password1", "123456789", "qwerty123", "iloveyou",
    "admin123", "welcome1", "shecure2025", "shecure@2025", "shecure@2025!",
}

def validate_password_strength(password: str, username: str = "", email: str = "") -> list[str]:
    errors = []
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long.")
    if not re.search(r"[A-Z]", password):
        errors.append("Must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("Must contain at least one digit.")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password):
        errors.append("Must contain at least one special character.")
    if re.search(r"(.)\1{3,}", password):
        errors.append("Must not contain 4+ repeated characters in a row.")
    if password.lower() in _COMMON_PASSWORDS:
        errors.append("Password is too common.")
    if username and username.lower() in password.lower():
        errors.append("Password must not contain your username.")
    if email:
        local = email.split("@")[0].lower()
        if local and local in password.lower():
            errors.append("Password must not contain part of your email.")
    return errors

# ── IP allowlist ──────────────────────────────────────────────────────────────
def is_ip_allowed(ip):
    from app.models.user import AllowedIP
    enforce = os.environ.get("ENFORCE_IP_ALLOWLIST", "false").lower() == "true"
    if not enforce:
        return True

    if not ip or ip == "unknown":
        return False
    try:
        client = ipaddress.ip_address(ip)
    except ValueError:
        return False

    entries = AllowedIP.query.filter_by(is_active=True).all()
    for entry in entries:
        try:
            if "/" not in entry.ip_address and ipaddress.ip_address(entry.ip_address) == client:
                return True
            if "/" in entry.ip_address and client in ipaddress.ip_network(entry.ip_address, strict=False):
                return True
        except ValueError:
            continue
    return False


# ── AI threat scoring ─────────────────────────────────────────────────────────
def _ai_threat_score(ip, endpoint, method, user_agent, combined_payload):
    score = 0
    reasons = []

    bot_patterns = ["sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster",
                    "gobuster", "wfuzz", "hydra", "burpsuite", "python-requests"]
    ua_lower = (user_agent or "").lower()
    for bot in bot_patterns:
        if bot in ua_lower:
            score += 40
            reasons.append(f"Known attack tool UA: {bot}")
            break

    high_risk = ["union select", "' or '1'='1", "exec(", "eval(", "/etc/passwd",
                 "/bin/sh", "cmd.exe", "base64_decode", "<script>", "javascript:"]
    for pattern in high_risk:
        if pattern in combined_payload.lower():
            score += 35
            reasons.append(f"High-risk payload: {pattern}")
            break

    if endpoint in ["/login", "/register"] and method == "POST":
        score += 10
        reasons.append("Auth endpoint probing")

    scan_paths = ["/wp-admin", "/phpmyadmin", "/.env", "/admin.php",
                  "/config", "/.git", "/backup", "/shell"]
    for p in scan_paths:
        if endpoint.startswith(p):
            score += 30
            reasons.append(f"Known scan path: {p}")
            break

    if not user_agent or len(user_agent.strip()) < 10:
        score += 15
        reasons.append("Suspicious user agent")

    score = min(score, 100)
    reason = "; ".join(reasons) if reasons else "General policy violation"
    return score, reason


# ── Logging helpers ───────────────────────────────────────────────────────────
def log_access(username_attempted, status, reason=None, user_id=None):
    from app import db
    from app.models.logs import AccessLog
    # FIX: store an HMAC hash of the attempted username rather than the plaintext,
    # so access logs don't become a second source of PII plaintext in the DB.
    # The hash is keyed with USERNAME_HMAC_KEY so it can't be reversed without the key.
    hashed_username = username_attempted
    if username_attempted and username_attempted not in ("unknown", ""):
        try:
            from app.utils.username_enc import hash_username
            hashed_username = hash_username(username_attempted)
        except Exception:
            hashed_username = username_attempted  # fallback: store as-is
    ip = _get_real_ip()
    entry = AccessLog(
        user_id=user_id,
        username_attempted=hashed_username,
        ip_address=ip,
        user_agent=request.user_agent.string[:512],
        status=status,
        reason=reason,
        is_unauthorized=(status == "blocked"),
    )
    db.session.add(entry)
    db.session.commit()


def log_activity(description=None, suspicious=False, action=None, username=None, user_id=None):
    from app import db
    from app.models.logs import ActivityLog
    try:
        # Use explicitly passed values first, fallback to current_user
        uid = user_id if user_id is not None else (current_user.id if current_user.is_authenticated else None)
        uname = username if username is not None else (current_user.username if current_user.is_authenticated else None)
        if uname and uname not in ("unknown", ""):
            try:
                from app.utils.username_enc import hash_username
                uname = hash_username(uname)
            except Exception:
                pass
        path = request.path
        method = request.method
        resolved_action = action or _get_action_label(method, path)
        entry = ActivityLog(
            user_id=uid,
            username=uname,
            ip_address=_get_real_ip(),
            method=method,
            endpoint=path[:256],
            action=resolved_action[:100],
            description=description,
            is_suspicious=suspicious,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[log_activity error] {e}")

def log_unauthorized_alert(ip, endpoint, method, user_agent, cached_body=""):
    from app import db
    from app.models.logs import UnauthorizedAlert
    qs = request.query_string.decode("utf-8", errors="ignore")
    combined = f"{endpoint} {qs} {cached_body}"
    score, reason = _ai_threat_score(ip, endpoint, method, user_agent, combined)
    alert = UnauthorizedAlert(
        ip_address=ip,
        user_agent=user_agent[:512] if user_agent else "",
        endpoint=endpoint[:256],
        method=method,
        threat_score=score,
        threat_reason=reason[:300],
    )
    db.session.add(alert)
    db.session.commit()


# ── Exempt endpoints (no IP check) ───────────────────────────────────────────
EXEMPT_ENDPOINTS = {
    "auth.health",
    "auth.banned",
    "static",
    "auth.register",
    "auth.logout",
    "api.alert_count",
    "api.unresolved_alerts",
    "api.recent_access",
    "api.access_stats",
    "api.recent_activity",
    "api.suspicious_activity",
    "camera.ingest",
    "camera.stream",
    "camera.status",
    "camera.broadcast_proxy",
    "camera.clear_broadcast_proxy",
    # FIX: broadcaster_status must be reachable even after the broadcaster's IP
    # is removed — that's the whole point of the endpoint. Without this exemption
    # the IP-removal warning modal can never fire because the poll itself gets 403'd.
    "camera.broadcaster_status",
     "ws_ingest",
}

# Path-prefix fallback for /api/ and /camera/ in case endpoint resolution fails
_EXEMPT_PATH_PREFIXES = (
    "/api/",
    "/camera/stream",
    "/camera/status",
    "/camera/broadcaster-status",   # FIX: path-level fallback for broadcaster_status
    "/static/",
    "/register",
    "/logout",
    "/banned",          # dead-end page for honeypot-banned IPs — must be reachable
    "/health",          # Railway healthcheck endpoint — must always be reachable
    # NOTE: honeypot paths are intentionally NOT listed here.
    # A banned IP must be blocked even before reaching a honeypot route.
    "/ws/ingest",
)

# ── Suspicious payload patterns ───────────────────────────────────────────────
SUSPICIOUS_PATTERNS = [
    "../", "..\\/", "etc/passwd", "etc/shadow",
    "<script", "javascript:", "onload=", "onerror=",
    "UNION SELECT", "' OR '1'='1", "EXEC(",
    "document.cookie", "window.location",
    "base64,", "eval(", "setTimeout(", "setInterval(",
    "/bin/sh", "/bin/bash", "cmd.exe", "powershell",
    "nc -e", "ncat ",
]

# ── Session key used as a fallback ban flag ───────────────────────────────────
_SESSION_HONEYPOT_KEY = "_hp_banned"

# ── In-memory ban set (last-resort fallback if DB and session both fail) ──────
# Cleared on restart, but covers the same-process same-request-cycle gap.
_INMEMORY_BANNED_IPS: set = set()


# ── Railway emergency unblock ─────────────────────────────────────────────────
def _process_railway_unblock(app):
    """
    Reads the UNBLOCK_IP environment variable and immediately clears those IPs
    from both the DB blocklist and the in-memory ban set.

    Usage (Railway dashboard → Variables):
        UNBLOCK_IP=192.168.1.10
        UNBLOCK_IP=192.168.1.10,10.0.0.5   # comma-separated for multiple IPs

    After redeploying, the listed IPs are unblocked before the first request.
    Delete the variable afterwards so it doesn't repeat on the next restart.
    """
    raw = os.environ.get("UNBLOCK_IP", "").strip()
    if not raw:
        return

    import logging
    _log = logging.getLogger(__name__)

    with app.app_context():
        try:
            from app import db
            from app.models.user import BlockedIP

            ips = [ip.strip() for ip in raw.split(",") if ip.strip()]
            for ip in ips:
                entry = BlockedIP.query.filter_by(ip_address=ip).first()
                if entry:
                    entry.is_active = False
                _INMEMORY_BANNED_IPS.discard(ip)

            db.session.commit()
            _log.warning(
                "[railway-unblock] Unblocked %d IP(s) via UNBLOCK_IP env var: %s",
                len(ips), ", ".join(ips),
            )
        except Exception as exc:
            _log.error("[railway-unblock] Failed to process UNBLOCK_IP: %s", exc)


# ── Security middleware ───────────────────────────────────────────────────────
def register_security_middleware(app):
    # ── Railway env-var unblock (runs once at startup) ────────────────────────
    _process_railway_unblock(app)

    # Interactive paths: show decoy on GET, ban only on POST
    _HONEYPOT_INTERACTIVE_PATHS = frozenset({
        "/wp-admin", "/wp-admin/", "/wp-login.php",
        "/phpmyadmin", "/phpmyadmin/", "/pma", "/pma/", "/mysql",
        "/admin.php", "/administrator", "/administrator/", "/panel", "/cpanel",
        "/webadmin", "/manage", "/portal",
        "/shell.php", "/backdoor.php", "/cmd.php", "/c99.php", "/r57.php",
        "/setup.php", "/install.php", "/backup",
        "/xmlrpc.php",
    })

    # File paths: no form to submit, ban immediately on GET
    _HONEYPOT_FILE_PATHS = frozenset({
        "/wp-config.php",
        "/.env", "/.env.local", "/.env.production",
        "/config.php", "/config.yaml", "/settings.php",
        "/.git/config", "/.git/HEAD",
        "/backup.zip", "/db.sql", "/server-status", "/server-info",
    })

    _HONEYPOT_PATHS = _HONEYPOT_INTERACTIVE_PATHS | _HONEYPOT_FILE_PATHS

    # Cookie name set on the browser when a honeypot route is hit.
    _BAN_COOKIE = "_hp_block"

    @app.before_request
    def enforce_security():
        from flask import make_response
        ip = _get_real_ip()
        path = request.path
        # ── Healthcheck — bypass everything for Railway healthcheck ────────
        if path == "/health":
            return


        # ── Collect ALL possible client IPs (handles Railway proxy headers) ───
        all_ips = set(filter(None, [
            ip,
            request.remote_addr,
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip(),
            request.headers.get("X-Real-IP", "").strip(),
        ]))

        # ── Step 1: honeypot path hit ─────────────────────────────────────────
        if path in _HONEYPOT_PATHS:
            # Ban ALL IP variants immediately regardless of GET or POST.
            # For interactive paths the blueprint will still serve the decoy
            # page on GET so the attacker doesn't know they're caught — but
            # the ban is already in place so /login is blocked from this point.
            for _ban_ip in all_ips:
                _INMEMORY_BANNED_IPS.add(_ban_ip)
                try:
                    block_ip(_ban_ip, reason=f"Honeypot auto-ban: probed '{path}'", hours=24)
                except Exception:
                    pass
            try:
                log_access("unknown", "blocked", reason=f"Honeypot route hit: {path}")
            except Exception:
                pass
            # For interactive paths, fall through to the blueprint which serves
            # the convincing decoy page (already banned, cookie set by blueprint).
            # For file paths, return the banned page immediately.
            if path not in _HONEYPOT_INTERACTIVE_PATHS:
                _secure_cookie = (
                    os.environ.get("RAILWAY_ENVIRONMENT") is not None
                    or os.environ.get("FLASK_ENV") == "production"
                )
                from flask import render_template
                resp = make_response(render_template("errors/403.html", client_ip=ip), 403)
                resp.set_cookie(
                    "_hp_block", "1",
                    max_age=86400,
                    httponly=True,
                    samesite="Lax",
                    secure=_secure_cookie,
                )
                return resp

        # ── Step 2: check all ban signals — cookie, memory, DB ───────────────
        # Skip the ban-check for interactive honeypot paths: the ban was just
        # applied above in Step 1, but we still want the blueprint to serve the
        # convincing decoy page on GET so the attacker doesn't know they're
        # caught. The blueprint handler will return 403.html on POST.
        if path in _HONEYPOT_INTERACTIVE_PATHS:
            return  # fall through to blueprint — it handles the response

        cookie_banned = request.cookies.get(_BAN_COOKIE) == "1"
        mem_banned    = any(i in _INMEMORY_BANNED_IPS for i in all_ips)
        db_banned     = False
        try:
            db_banned = any(is_ip_blocked(i) for i in all_ips)
        except Exception:
            pass

        if cookie_banned or mem_banned or db_banned:
            try:
                log_access("unknown", "blocked", reason="IP on honeypot blocklist")
            except Exception:
                pass
            # Render 403.html inline — no redirect at all.
            # There is NO URL they can type that will ever show a login form.
            if path == "/banned":
                return  # let /banned route render normally, no loop
            from flask import render_template as _rt
            _secure_cookie = (
                os.environ.get("RAILWAY_ENVIRONMENT") is not None
                or os.environ.get("FLASK_ENV") == "production"
            )
            resp = make_response(_rt("errors/403.html", client_ip=ip), 403)
            resp.set_cookie(
                "_hp_block", "1",
                max_age=86400,
                httponly=True,
                samesite="Lax",
                secure=_secure_cookie,
            )
            return resp

        # Always allow if endpoint is exempt or can't be resolved
        if request.endpoint is None or request.endpoint in EXEMPT_ENDPOINTS:
            return
        if any(request.path.startswith(p) for p in _EXEMPT_PATH_PREFIXES):
            return

        # ── IP allowlist ──────────────────────────────────────────────────────
        if not is_ip_allowed(ip):
            log_unauthorized_alert(ip, request.path,
                                   request.method, request.user_agent.string,
                                   cached_body="")
            log_access("unknown", "blocked", reason="IP not in allow-list")
            time.sleep(15)
            abort(403)

        if request.content_length and request.content_length > 10 * 1024 * 1024:
            log_unauthorized_alert(ip, request.path,
                                   request.method, request.user_agent.string,
                                   cached_body="")
            abort(413)

        raw_body = request.get_data(cache=True, as_text=True)

        qs = request.query_string.decode("utf-8", errors="ignore")
        combined = f"{qs} {raw_body}"
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.lower() in combined.lower():
                try:
                    log_activity(
                        description=f"Attack pattern detected: {pattern}",
                        suspicious=True,
                        action="Attack pattern detected",
                    )
                    log_unauthorized_alert(ip, request.path,
                                           request.method, request.user_agent.string,
                                           cached_body=raw_body)
                except Exception:
                    pass
                time.sleep(20)
                abort(400)

        ua = request.user_agent.string.strip()
        if not ua or len(ua) < 5:
            log_unauthorized_alert(ip, request.path,
                                   request.method, request.user_agent.string,
                                   cached_body="")
            abort(400)

    @app.after_request
    def track_activity(response):
        if request.endpoint and _should_log(request.path):
            try:
                log_activity(
                    description=f"{request.method} {request.path} → {response.status_code}",
                )
            except Exception:
                try:
                    from app import db
                    db.session.rollback()
                except Exception:
                    pass
        return response

    @app.errorhandler(400)
    def bad_request(e):
        from flask import render_template
        return render_template("errors/403.html"), 400

    @app.errorhandler(403)
    def forbidden(e):
        from flask import render_template
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template
        return render_template("errors/404.html"), 404

    @app.errorhandler(413)
    def too_large(e):
        from flask import jsonify
        return jsonify({"error": "Request too large"}), 413

    @app.errorhandler(429)
    def rate_limited(e):
        from flask import render_template
        return render_template("errors/429.html"), 429

    @app.errorhandler(500)
    def internal_error(e):
        import traceback
        app.logger.error("500 Internal Server Error:\n%s", traceback.format_exc())
        from flask import render_template
        try:
            return render_template("errors/500.html"), 500
        except Exception:
            return "<h1>500 Internal Server Error</h1>", 500


# ── Decorators ────────────────────────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated


def approved_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_approved:
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ── IP blocklist (honeypot auto-ban) ─────────────────────────────────────────

def block_ip(ip: str, reason: str, hours: int = 24) -> None:
    import logging
    from datetime import timedelta
    from app import db
    from app.models.user import BlockedIP

    _log = logging.getLogger(__name__)
    try:
        db.session.rollback()
        existing = BlockedIP.query.filter_by(ip_address=ip).first()
        expires = now_pst() + timedelta(hours=hours)
        if existing:
            existing.reason = reason[:300]
            existing.blocked_at = now_pst()
            existing.expires_at = expires
            existing.is_active = True
        else:
            db.session.add(BlockedIP(
                ip_address=ip,
                reason=reason[:300],
                expires_at=expires,
                is_active=True,
            ))
        db.session.commit()
        _log.warning("[blocklist] %s blocked for %dh — %s", ip, hours, reason)
    except Exception as exc:
        db.session.rollback()
        _log.error("[blocklist] failed to block %s: %s", ip, exc)

    # NOTE: Do NOT set session[_SESSION_HONEYPOT_KEY] here.
    # block_ip() is called for *any* IP being banned (including ones that aren't
    # the current user's IP). Writing to the session here would stamp the ban
    # flag onto whichever user happened to trigger this code path, blocking
    # innocent users. The _hp_block cookie is set directly by enforce_security()
    # only when the *current* request's IP hits a honeypot route.


def is_ip_blocked(ip: str) -> bool:
    from app.models.user import BlockedIP
    if not ip or ip == "unknown":
        return False
    entry = BlockedIP.query.filter_by(ip_address=ip, is_active=True).first()
    if entry is None:
        return False
    return entry.is_currently_blocked()


def unblock_ip(ip: str) -> bool:
    from app import db
    from app.models.user import BlockedIP
    entry = BlockedIP.query.filter_by(ip_address=ip).first()
    if not entry:
        return False
    entry.is_active = False
    db.session.commit()
    return True
