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


def _get_real_ip():
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_ip_allowed(ip: str) -> bool:
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
}

SUSPICIOUS_PATTERNS = [
    "../", "etc/passwd", "<script", "SELECT ", "UNION ", "DROP TABLE",
    "alert(", "javascript:", "onload=", "onerror=",
]


def register_security_middleware(app):
    @app.before_request
    def enforce_security():
        if request.endpoint in EXEMPT_ENDPOINTS:
            return
        ip = _get_real_ip()
        if not is_ip_allowed(ip):
            log_unauthorized_alert(ip, request.path, request.method, request.user_agent.string)
            log_access("unknown", "blocked", reason="IP not in allow-list")
            abort(403)
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
                pass
