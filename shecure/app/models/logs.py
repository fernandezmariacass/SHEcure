from datetime import datetime, timezone, timedelta
from app import db

# Philippine Standard Time = UTC+8
PST = timezone(timedelta(hours=8))


def now_pst():
    """Return current time in Philippine Standard Time (stored as UTC+8 offset)."""
    return datetime.now(PST).replace(tzinfo=None)


class AccessLog(db.Model):
    """Records every login attempt (success or failure)."""
    __tablename__ = "access_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username_attempted = db.Column(db.String(80))
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(512))
    status = db.Column(db.String(20))  # success | failed | blocked | logout
    reason = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=now_pst, index=True)
    is_unauthorized = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username_attempted,
            "ip": self.ip_address,
            "status": self.status,
            "reason": self.reason,
            "timestamp": self.timestamp.strftime('%Y-%m-%d %H:%M:%S') + ' PST',
            "unauthorized": self.is_unauthorized,
        }


class ActivityLog(db.Model):
    """Records page-level activity for every authenticated user."""
    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username = db.Column(db.String(80))          # store username directly for display
    ip_address = db.Column(db.String(45))
    method = db.Column(db.String(10))
    endpoint = db.Column(db.String(256))
    status_code = db.Column(db.Integer)
    action = db.Column(db.String(100))           # human-readable action label
    description = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=now_pst, index=True)
    is_suspicious = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.username or "—",
            "ip": self.ip_address,
            "method": self.method,
            "endpoint": self.endpoint,
            "action": self.action or self.description,
            "status_code": self.status_code,
            "description": self.description,
            "timestamp": self.timestamp.strftime('%Y-%m-%d %H:%M:%S') + ' PST',
            "suspicious": self.is_suspicious,
        }


class UnauthorizedAlert(db.Model):
    """Stores alerts for unauthorized access attempts."""
    __tablename__ = "unauthorized_alerts"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(512))
    endpoint = db.Column(db.String(256))
    method = db.Column(db.String(10))
    timestamp = db.Column(db.DateTime, default=now_pst, index=True)
    resolved = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)
    threat_score = db.Column(db.Integer, default=0)   # 0-100 AI risk score
    threat_reason = db.Column(db.String(300))          # AI explanation

    def to_dict(self):
        return {
            "id": self.id,
            "ip": self.ip_address,
            "endpoint": self.endpoint,
            "method": self.method,
            "timestamp": self.timestamp.strftime('%Y-%m-%d %H:%M:%S') + ' PST',
            "resolved": self.resolved,
            "threat_score": self.threat_score,
            "threat_reason": self.threat_reason,
        }
