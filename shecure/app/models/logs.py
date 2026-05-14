from datetime import datetime, timezone
from pytz import timezone as tz
from app import db


class AccessLog(db.Model):
    """Records every login attempt (success or failure)."""
    __tablename__ = "access_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username_attempted = db.Column(db.String(80))
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(512))
    status = db.Column(db.String(20))  # success | failed | blocked
    reason = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_unauthorized = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username_attempted,
            "ip": self.ip_address,
            "status": self.status,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat(),
            "unauthorized": self.is_unauthorized,
        }


class ActivityLog(db.Model):
    """Records page-level activity for every authenticated user."""
    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    ip_address = db.Column(db.String(45))
    method = db.Column(db.String(10))
    endpoint = db.Column(db.String(256))
    status_code = db.Column(db.Integer)
    description = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_suspicious = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "ip": self.ip_address,
            "method": self.method,
            "endpoint": self.endpoint,
            "status_code": self.status_code,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
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
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    resolved = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "ip": self.ip_address,
            "endpoint": self.endpoint,
            "method": self.method,
            "timestamp": self.timestamp.isoformat(),
            "resolved": self.resolved,
        }
