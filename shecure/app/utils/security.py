import os
from functools import wraps
from flask import request, abort, session
from flask_login import current_user


def _get_real_ip():
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_ip_allowed(ip):
    from app.models.user import AllowedIP
    enforce = os.environ.get("ENFORCE_IP_ALLOWLIST", "false").lower() == "true"
    if not enforce:
        return True
    return AllowedIP.query.filter_by(ip_address=ip, is_active=True).first() is not None


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


def log_activity(description=None, suspicious=False):
    from app import db
    from app.models.logs import ActivityLog
    uid = current_user.id if current_user.is_authenticated else None
    entry = ActivityLog(
        user_id=uid,
        ip_address=_get_real_ip(),
        method=request.method,
        endpoint=request.path[:256],
        description=description,
        is_suspicious=suspicious,
    )
    db.session.add(entry)
    db.session.commit()


def log_unauthorized_alert(ip, endpoint, method, user_agent):
    from app import db
    from app.models.logs import UnauthorizedAlert
    alert = UnauthorizedAlert(
        ip_address=ip,
        user_agent=user_agent[:512] if user_agent else "",
        endpoint=endpoint[:256],
        method=method,
    )
    db.session.add(alert)
    db.session.commit()


EXEMPT_ENDPOINTS = {
    "static",
    "auth.login",
    "auth.register",
    "auth.logout",
    "camera.ingest",
    "auth.debug_ip",   # ← add this temporarily
}

# Extended suspicious patterns
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

        # Scan URL, args, and body for attack patterns
        targets = [
            request.path,
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
                    )
                    log_unauthorized_alert(ip, request.path,
                                           request.method, request.user_agent.string)
                except Exception:
                    pass
                abort(400)

        # Block empty or missing User-Agent (common bots/scanners)
        ua = request.user_agent.string.strip()
        if not ua or len(ua) < 5:
            log_unauthorized_alert(ip, request.path,
                                   request.method, request.user_agent.string)
            abort(400)

    @app.after_request
    def track_activity(response):
        if request.endpoint and request.endpoint not in {"static"}:
            try:
                log_activity(description=f"{request.method} {request.path}")
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
