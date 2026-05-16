import os
import re
from functools import wraps
from flask import request, abort
from flask_login import current_user

# ── Action label map ─────────────────────────────────────────────────────────
# Maps (method, path_pattern) → human-readable action label
_ACTION_MAP = [
    ("POST",  r"^/login$",                        "Login attempt"),
    ("POST",  r"^/register$",                     "Registration"),
    ("GET",   r"^/logout$",                       "Logged out"),
    ("GET",   r"^/dashboard$",                    "Viewed Dashboard"),
    ("GET",   r"^/dashboard/activity",            "Viewed Activity Log"),
    ("GET",   r"^/dashboard/alerts",              "Viewed Alerts"),
    ("GET",   r"^/camera",                        "Viewed Camera Feed"),
    ("GET",   r"^/admin/$",                       "Opened Admin Panel"),
    ("GET",   r"^/admin/logs",                    "Viewed Access Logs"),
    ("POST",  r"^/admin/users/\d+/approve",       "Approved a user"),
    ("POST",  r"^/admin/users/\d+/revoke",        "Revoked user access"),
    ("POST",  r"^/admin/users/\d+/delete",        "Deleted a user"),
    ("POST",  r"^/admin/ip/add",                  "Added IP to allowlist"),
    ("POST",  r"^/admin/ip/\d+/delete",           "Removed IP from allowlist"),
    ("POST",  r"^/admin/alerts/\d+/resolve",      "Resolved an alert"),
    ("GET",   r"^/api/",                          "API request"),
    ("POST",  r"^/camera/ingest",                 "Camera frame ingested"),
]

def _get_action_label(method, path):
    for m, pattern, label in _ACTION_MAP:
        if method == m and re.match(pattern, path):
            return label
    if method == "GET":
        return f"👁️ Viewed {path}"
    if method == "POST":
        return f"📤 Submitted {path}"
    return f"{method} {path}"


# ── IP detection ─────────────────────────────────────────────────────────────
def _get_real_ip():
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


# ── IP allowlist ─────────────────────────────────────────────────────────────
def is_ip_allowed(ip):
    from app.models.user import AllowedIP
    enforce = os.environ.get("ENFORCE_IP_ALLOWLIST", "false").lower() == "true"
    if not enforce:
        return True
    return AllowedIP.query.filter_by(ip_address=ip, is_active=True).first() is not None


# ── AI threat scoring ─────────────────────────────────────────────────────────
def _ai_threat_score(ip, endpoint, method, user_agent, combined_payload):
    """
    Simple rule-based AI threat scorer (0–100).
    Returns (score, reason). No external API needed.
    High score = more suspicious.
    """
    score = 0
    reasons = []

    # Known scanner/bot user agents
    bot_patterns = ["sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster",
                    "gobuster", "wfuzz", "hydra", "burpsuite", "python-requests"]
    ua_lower = (user_agent or "").lower()
    for bot in bot_patterns:
        if bot in ua_lower:
            score += 40
            reasons.append(f"Known attack tool UA: {bot}")
            break

    # Suspicious payload patterns
    high_risk = ["union select", "' or '1'='1", "exec(", "eval(", "/etc/passwd",
                 "/bin/sh", "cmd.exe", "base64_decode", "<script>", "javascript:"]
    for pattern in high_risk:
        if pattern in combined_payload.lower():
            score += 35
            reasons.append(f"High-risk payload: {pattern}")
            break

    # Repeated failed auth endpoint
    if endpoint in ["/login", "/register"] and method == "POST":
        score += 10
        reasons.append("Auth endpoint probing")

    # Scanning common paths
    scan_paths = ["/wp-admin", "/phpmyadmin", "/.env", "/admin.php",
                  "/config", "/.git", "/backup", "/shell"]
    for p in scan_paths:
        if endpoint.startswith(p):
            score += 30
            reasons.append(f"Known scan path: {p}")
            break

    # Very short or empty user agent
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


def log_unauthorized_alert(ip, endpoint, method, user_agent):
    from app import db
    from app.models.logs import UnauthorizedAlert
    combined = f"{endpoint} {request.query_string.decode('utf-8', errors='ignore')} {request.get_data(as_text=True)}"
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
    "camera.ingest",
    "auth.debug_ip",
}

# ── Suspicious payload patterns ───────────────────────────────────────────────
SUSPICIOUS_PATTERNS = [
    "../", "..\\", "etc/passwd", "etc/shadow",
    "<script", "javascript:", "onload=", "onerror=",
    "SELECT ", "UNION ", "INSERT ", "DROP ", "DELETE ",
    "UPDATE ", "ALTER ", "CREATE ", "EXEC(",
    "alert(", "document.cookie", "window.location",
    "base64,", "eval(", "setTimeout(", "setInterval(",
    "/bin/sh", "/bin/bash", "cmd.exe", "powershell",
    "wget ", "curl ", "nc -e", "ncat ",
    "0x", "char(", "concat(", "sleep(",
]


# ── Security middleware ───────────────────────────────────────────────────────
def register_security_middleware(app):

    @app.before_request
    def enforce_security():
        if request.endpoint in EXEMPT_ENDPOINTS:
            return

        ip = _get_real_ip()

        # Block IPs not in allow-list
        if not is_ip_allowed(ip):
            log_unauthorized_alert(ip, request.path,
                                   request.method, request.user_agent.string)
            log_access("unknown", "blocked", reason="IP not in allow-list")
            abort(403)

        # Block suspiciously large requests
        if request.content_length and request.content_length > 10 * 1024 * 1024:
            log_unauthorized_alert(ip, request.path,
                                   request.method, request.user_agent.string)
            abort(413)

        # Scan query string and body (NOT path — path has legitimate "delete" etc)
        targets = [
            request.query_string.decode("utf-8", errors="ignore"),
            request.get_data(as_text=True),
        ]
        combined = " ".join(targets).lower()
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.lower() in combined:
                try:
                    log_activity(
                        description=f"Attack pattern detected: {pattern}",
                        suspicious=True,
                        action="🚨 Attack pattern detected",
                    )
                    log_unauthorized_alert(ip, request.path,
                                           request.method, request.user_agent.string)
                except Exception:
                    pass
                abort(400)

        # Block empty or missing User-Agent
        ua = request.user_agent.string.strip()
        if not ua or len(ua) < 5:
            log_unauthorized_alert(ip, request.path,
                                   request.method, request.user_agent.string)
            abort(400)

    @app.after_request
    def track_activity(response):
        if request.endpoint and request.endpoint not in {"static"}:
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
