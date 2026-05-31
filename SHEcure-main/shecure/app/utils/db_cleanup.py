from datetime import datetime, timedelta
from app import db
from app.models.logs import AccessLog, ActivityLog, UnauthorizedAlert


def purge_old_logs(days=90):
    """Delete log entries older than the specified number of days.
    
    For UnauthorizedAlerts, only resolved ones are deleted.
    Unresolved alerts are kept regardless of age.
    """
    cutoff = datetime.utcnow() - timedelta(days=days)

    deleted_access = AccessLog.query.filter(AccessLog.timestamp < cutoff).delete()
    deleted_activity = ActivityLog.query.filter(ActivityLog.timestamp < cutoff).delete()
    deleted_alerts = UnauthorizedAlert.query.filter(
        UnauthorizedAlert.timestamp < cutoff,
        UnauthorizedAlert.resolved == True
    ).delete()

    db.session.commit()

    return {
        "access_logs_deleted": deleted_access,
        "activity_logs_deleted": deleted_activity,
        "alerts_deleted": deleted_alerts,
        "cutoff_date": cutoff.strftime("%Y-%m-%d %H:%M:%S"),
    }
