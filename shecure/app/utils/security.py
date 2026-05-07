# ============================================================
# SECURITY-SENSITIVE FILE — DO NOT COMMIT TO PUBLIC REPOS
# This file contains IP allow-list logic, activity tracking,
# and unauthorized-access detection.
# ============================================================

import os
from datetime import datetime
from functools import wraps
from flask import request, redirect, url_for, abort, current_app
from flask_login import current_user


# ---------------------------------------------------------------------------
# Allow-list check
# ---------------------------------------------------------------------------

def _get_real_ip():
    """Return the real client IP, respecting proxy headers."""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_ip_allowed(ip: str) -> bool:
    """Return True if the IP is in the allow-list OR allow-list is disabled."""
    from app.models.user import AllowedIP

    enforce = os.environ.get("ENFORCE_IP_ALLOWLIST", "false").lower() == "true"
    if not enforce:
        return True

    return AllowedIP.query.filter_by(ip_address=ip, is_active=True).first() is not None


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def log_access(username_attempted, status, reason=None, user_id=None):
    """Write an AccessLog row."""
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
    """Write an ActivityLog row for the current request."""
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
    """Write an UnauthorizedAlert row."""
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


# ---------------------------------------------------------------------------
# Middleware registration
# ---------------------------------------------------------------------------

EXEMPT_ENDPOINTS = {"static", "auth.login", "auth.register", "auth.logout"}
SUSPICIOUS_PATTERNS = [
    "../", "etc/passwd", "<script", "SELECT ", "UNION ", "DROP TABLE",
    "alert(", "javascript:", "onload=", "onerror=",
]


def register_security_middleware(app):
    @app.before_request
    def enforce_security():
        # Skip static files
        if request.endpoint in EXEMPT_ENDPOINTS:
            return

        ip = _get_real_ip()

        # --- IP allow-list gate ---
        if not is_ip_allowed(ip):
            log_unauthorized_alert(ip, request.path, request.method, request.user_agent.string)
            log_access("unknown", "blocked", reason="IP not in allow-list")
            abort(403)

        # --- Suspicious payload detection ---
        raw = request.get_data(as_text=True)
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.lower() in raw.lower() or pattern.lower() in request.path.lower():
                log_activity(description=f"Suspicious pattern detected: {pattern}", suspicious=True)
                log_unauthorized_alert(ip, request.path, request.method, request.user_agent.string)
                abort(400)

    @app.after_request
    def track_activity(response):
        if request.endpoint and request.endpoint not in {"static"}:
            try:
                log_activity(description=f"{request.method} {request.path}")
            except Exception:
                pass  # Never block a response due to logging failure
        return response

    @app.errorhandler(403)
    def forbidden(e):
        from flask import render_template
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template
        return render_template("errors/404.html"), 404


# ---------------------------------------------------------------------------
# Role decorators
# ---------------------------------------------------------------------------

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
