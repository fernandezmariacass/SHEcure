import os
import re
import ipaddress
from functools import wraps
from flask import request, abort
from flask_login import current_user

# ── Paths to skip activity logging ───────────────────────────────────────────
_SKIP_LOGGING_PREFIXES = (
    "/api/",
    "/static/",
    "/camera/stream",
    "/camera/status",
    "/debug-ip",
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
    ip = _get_real_ip()
    entry = AccessLog(
        user_id=user_id,
        username_attempted=username_attempted,
        ip_address=ip,
        user_agent=request.user_agent.string[:512],
        status=status,
        reason=reason,
        is_unauthorized=(status == "blocked"),
    )
    db.session.add(entry)
    db.session.commit()


def log_activity(description=None, suspicious=False, action=None):
    from app import db
    from app.models.logs import ActivityLog
    uid = current_user.id if current_user.is_authenticated else None
    uname = current_user.username if current_user.is_authenticated else None
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


def log_unauthorized_alert(ip, endpoint, method, user_agent, cached_body=""):
    """Log an unauthorized access alert.

    cached_body: pre-read request body string, passed in to avoid consuming
    the stream a second time (request.get_data() can only be read once without
    stream caching, which interferes with form parsing downstream).
    """
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
    "static",
    "auth.login",
    "auth.register",
    "auth.logout",
    "auth.debug_ip",
    # API polling endpoints — authenticated via session, must not trigger alerts
    "api.alert_count",
    "api.unresolved_alerts",
    "api.recent_access",
    "api.access_stats",
    "api.recent_activity",
    "api.suspicious_activity",
    # Camera endpoints
    "camera.ingest",
    "camera.stream",
    "camera.status",
}

# Path-prefix fallback for /api/ and /camera/ in case endpoint resolution fails
_EXEMPT_PATH_PREFIXES = (
    "/api/",
    "/camera/stream",
    "/camera/status",
    "/static/",
    "/login",
    "/register",
    "/logout",
    "/debug-ip",
)

# ── Suspicious payload patterns ───────────────────────────────────────────────
# NOTE: Patterns like "SELECT ", "DELETE ", "UPDATE " etc. are intentionally
# removed — they are too broad and match legitimate admin/log page content.
# Only unambiguous attack payloads are kept here.
SUSPICIOUS_PATTERNS = [
    "../", "..\\/", "etc/passwd", "etc/shadow",
    "<script", "javascript:", "onload=", "onerror=",
    "UNION SELECT", "' OR '1'='1", "EXEC(",
    "document.cookie", "window.location",
    "base64,", "eval(", "setTimeout(", "setInterval(",
    "/bin/sh", "/bin/bash", "cmd.exe", "powershell",
    "nc -e", "ncat ",
]


# ── Security middleware ───────────────────────────────────────────────────────
def register_security_middleware(app):

    @app.before_request
    def enforce_security():
        # Always allow if endpoint is exempt or can't be resolved
        if request.endpoint is None or request.endpoint in EXEMPT_ENDPOINTS:
            return
        # Also exempt by path prefix in case endpoint resolution fails
        if any(request.path.startswith(p) for p in _EXEMPT_PATH_PREFIXES):
            return

        ip = _get_real_ip()

        if not is_ip_allowed(ip):
            # Don't call get_data() here — body not needed for IP block alerts
            log_unauthorized_alert(ip, request.path,
                                   request.method, request.user_agent.string,
                                   cached_body="")
            log_access("unknown", "blocked", reason="IP not in allow-list")
            abort(403)

        if request.content_length and request.content_length > 10 * 1024 * 1024:
            log_unauthorized_alert(ip, request.path,
                                   request.method, request.user_agent.string,
                                   cached_body="")
            abort(413)

        # FIX: Read body ONCE and cache it so Flask can still parse request.form
        # downstream. get_data(cache=True) stores the raw bytes in request._cached_data
        # and leaves the stream position such that Werkzeug's form parser can re-read it.
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
                abort(400)

        ua = request.user_agent.string.strip()
        if not ua or len(ua) < 5:
            log_unauthorized_alert(ip, request.path,
                                   request.method, request.user_agent.string,
                                   cached_body="")
            abort(400)

    @app.after_request
    def track_activity(response):
        # Skip API polling, static files, camera stream — only log real page visits
        if request.endpoint and _should_log(request.path):
            try:
                log_activity(
                    description=f"{request.method} {request.path} → {response.status_code}",
                )
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
        return render_template("errors/403.html"), 429

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
