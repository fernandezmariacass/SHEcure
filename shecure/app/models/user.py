from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager
from app.utils.keyderive import derive_access_key
from app.models.logs import now_pst


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="member")  # admin | member | viewer
    is_approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now_pst)
    last_seen = db.Column(db.DateTime)
    avatar_color = db.Column(db.String(7), default="#e91e8c")

    # ── 2FA (TOTP) ────────────────────────────────────────────────────────────
    # Secret is stored encrypted — see utils/totp_utils.py for encrypt/decrypt.
    totp_secret_enc = db.Column(db.Text, nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)

    # ── Login notification ────────────────────────────────────────────────────
    # SHA-256 hash of "ip:user_agent" from the last successful login.
    # If the next login comes from a different fingerprint, an email alert fires.
    last_login_fingerprint = db.Column(db.String(64), nullable=True)
    notify_on_new_login = db.Column(db.Boolean, default=True)

    logs = db.relationship("AccessLog", backref="user", lazy="dynamic")
    activity_logs = db.relationship("ActivityLog", backref="user", lazy="dynamic")
    password_history = db.relationship(
        "PasswordHistory", backref="user", lazy="dynamic",
        cascade="all, delete-orphan"
    )

    def set_password(self, password):
        """Derive access key then bcrypt-hash it. Also saves to password history."""
        access_key = derive_access_key(password, self.username)
        new_hash = generate_password_hash(access_key)

        # Save old hash to history before overwriting (skip on first set when
        # password_hash is not yet set, e.g. during User() construction).
        if getattr(self, "password_hash", None):
            self._save_password_history(self.password_hash)

        self.password_hash = new_hash

    def check_password(self, password):
        access_key = derive_access_key(password, self.username)
        return check_password_hash(self.password_hash, access_key)

    def is_password_reused(self, password, history_limit=5):
        """Return True if `password` matches any of the last N stored hashes."""
        access_key = derive_access_key(password, self.username)
        recent = (
            PasswordHistory.query
            .filter_by(user_id=self.id)
            .order_by(PasswordHistory.created_at.desc())
            .limit(history_limit)
            .all()
        )
        return any(check_password_hash(h.password_hash, access_key) for h in recent)

    def _save_password_history(self, hash_value):
        from app import db as _db
        entry = PasswordHistory(user_id=self.id, password_hash=hash_value)
        _db.session.add(entry)
        # Trim: keep only the 10 most recent entries to avoid unbounded growth
        old = (
            PasswordHistory.query
            .filter_by(user_id=self.id)
            .order_by(PasswordHistory.created_at.asc())
            .all()
        )
        if len(old) > 10:
            for row in old[: len(old) - 10]:
                _db.session.delete(row)

    def __repr__(self):
        return f"<User {self.username}>"


class PasswordHistory(db.Model):
    """Stores previous derived password hashes to prevent reuse."""
    __tablename__ = "password_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=now_pst)


class AllowedIP(db.Model):
    __tablename__ = "allowed_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    label = db.Column(db.String(100))
    added_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=now_pst)
    is_active = db.Column(db.Boolean, default=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
