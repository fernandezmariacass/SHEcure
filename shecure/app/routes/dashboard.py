from flask import Blueprint, render_template
from flask_login import login_required, current_user
from app.models.logs import AccessLog, ActivityLog, UnauthorizedAlert
from app.utils.security import approved_required

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
@login_required
@approved_required
def home():
    recent_access = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(10).all()
    alert_count = UnauthorizedAlert.query.filter_by(resolved=False).count()
    total_users_online = 0  # placeholder; extend with session tracking
    return render_template(
        "dashboard/home.html",
        recent_access=recent_access,
        alert_count=alert_count,
        total_users_online=total_users_online,
    )


@dashboard_bp.route("/dashboard/activity")
@login_required
@approved_required
def activity():
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(200).all()
    return render_template("dashboard/activity.html", logs=logs)


@dashboard_bp.route("/dashboard/alerts")
@login_required
@approved_required
def alerts():
    alerts = UnauthorizedAlert.query.order_by(UnauthorizedAlert.timestamp.desc()).all()
    return render_template("dashboard/alerts.html", alerts=alerts)
