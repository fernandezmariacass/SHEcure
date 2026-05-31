from datetime import datetime, timezone, timedelta
from app import db
from sqlalchemy_utils import StringEncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine
import os

# Philippine Standard Time = UTC+8
PST = timezone(timedelta(hours=8))

# Encryption key from environment variable
secret = os.environ.get("DB_ENCRYPTION_KEY", "")


def now_pst():
    """Return current time in Philippine Standard Time (stored as UTC+8 offset)."""
    return datetime.now(PST).replace(tzinfo=None)


class AccessLog(db.Model):
    """Records every login attempt (success or failure)."""
    __tablename__ = "access_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username_attempted = db.Column(db.String(80))
    ip_address = db.Column(StringEncryptedType(db.String, secret, AesEngine, 'pkcs5'), nullable=False)
    user_agent = db.Column(StringEncryptedType(db.String, secret, AesEngine, 'pkcs5'))
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
    username = db.Column(db.String(80))
    ip_address = db.Column(StringEncryptedType(db.String, secret, AesEngine, 'pkcs5'))
    method = db.Column(db.String(10))
    endpoint = db.Column(db.String(256))
    status_code = db.Column(db.Integer)
    action = db.Column(db.String(100))
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
    ip_address = db.Column(StringEncryptedType(db.String, secret, AesEngine, 'pkcs5'), nullable=False)
    user_agent = db.Column(StringEncryptedType(db.String, secret, AesEngine, 'pkcs5'))
    endpoint = db.Column(db.String(256))
    method = db.Column(db.String(10))
    timestamp = db.Column(db.DateTime, default=now_pst, index=True)
    resolved = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)
    threat_score = db.Column(db.Integer, default=0)
    threat_reason = db.Column(db.String(300))

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


class AdminAuditLog(db.Model):
    """Tamper-evident log of every destructive admin action."""
    __tablename__ = "admin_audit_logs"

    id             = db.Column(db.Integer, primary_key=True)
    actor_id       = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    actor_username = db.Column(db.String(80), nullable=False)
    action         = db.Column(db.String(60), nullable=False)
    target_id      = db.Column(db.Integer, nullable=True)
    target_username = db.Column(db.String(80), nullable=True)
    ip_address     = db.Column(db.String(45))
    user_agent     = db.Column(db.String(512))
    detail         = db.Column(db.String(500))
    timestamp      = db.Column(db.DateTime, default=now_pst, index=True)

    def to_dict(self):
        return {
            "id":        self.id,
            "actor":     self.actor_username,
            "action":    self.action,
            "target":    self.target_username,
            "ip":        self.ip_address,
            "detail":    self.detail,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S") + " PST",
        }


class NetworkDevice(db.Model):
    """Stores LAN devices discovered by the local agent via nmap."""
    __tablename__ = "network_devices"

    id         = db.Column(db.Integer, primary_key=True)
    ip         = db.Column(db.String(45), nullable=False, index=True)
    mac        = db.Column(db.String(17))
    hostname   = db.Column(db.String(255))
    vendor     = db.Column(db.String(128))
    open_ports = db.Column(db.Text)          # JSON list e.g. "[22, 80, 443]"
    os         = db.Column(db.String(128))
    last_seen  = db.Column(db.DateTime, default=now_pst, onupdate=now_pst, index=True)
    first_seen = db.Column(db.DateTime, default=now_pst)

    def to_dict(self):
        import json as _json
        try:
            ports = _json.loads(self.open_ports or "[]")
        except Exception:
            ports = []
        return {
            "id":         self.id,
            "ip":         self.ip,
            "mac":        self.mac or "N/A",
            "hostname":   self.hostname or self.ip,
            "vendor":     self.vendor or "Unknown",
            "open_ports": ports,
            "os":         self.os or "Unknown",
            "last_seen":  self.last_seen.strftime("%Y-%m-%d %H:%M:%S") + " PST",
            "first_seen": self.first_seen.strftime("%Y-%m-%d %H:%M:%S") + " PST",
        }


class UsedTotpCode(db.Model):
    """Replay-attack protection for TOTP codes."""
    __tablename__ = "used_totp_codes"

    id         = db.Column(db.Integer, primary_key=True)
    lookup_key = db.Column(db.String(80), unique=True, nullable=False, index=True)
    used_at    = db.Column(db.DateTime, default=now_pst, nullable=False)
