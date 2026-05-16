from flask import Blueprint, jsonify, request
from flask_login import login_required
from app.models.logs import AccessLog, ActivityLog, UnauthorizedAlert
from app.utils.security import admin_required

api_bp = Blueprint("api", __name__)


@api_bp.route("/alerts/unresolved")
@login_required
def unresolved_alerts():
    alerts = UnauthorizedAlert.query.filter_by(resolved=False)\
        .order_by(UnauthorizedAlert.timestamp.desc()).limit(50).all()
    return jsonify([a.to_dict() for a in alerts])


@api_bp.route("/alerts/count")
@login_required
def alert_count():
    count = UnauthorizedAlert.query.filter_by(resolved=False).count()
    return jsonify({"count": count})


@api_bp.route("/access/recent")
@login_required
def recent_access():
    logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(20).all()
    return jsonify([l.to_dict() for l in logs])


@api_bp.route("/access/stats")
@login_required
def access_stats():
    """All-time login statistics for the dashboard summary cards."""
    total   = AccessLog.query.count()
    success = AccessLog.query.filter_by(status="success").count()
    blocked = AccessLog.query.filter_by(status="blocked").count()
    failed  = AccessLog.query.filter_by(status="failed").count()
    return jsonify({
        "total": total,
        "success": success,
        "blocked": blocked,
        "failed": failed,
    })


@api_bp.route("/activity/recent")
@login_required
def recent_activity():
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(50).all()
    return jsonify([l.to_dict() for l in logs])


@api_bp.route("/activity/suspicious")
@login_required
@admin_required
def suspicious_activity():
    logs = ActivityLog.query.filter_by(is_suspicious=True)\
        .order_by(ActivityLog.timestamp.desc()).limit(100).all()
    return jsonify([l.to_dict() for l in logs])
