from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager
from app.utils.keyderive import derive_access_key
from app.utils.username_enc import encrypt_username, decrypt_username, hash_username
from app.models.logs import now_pst
from sqlalchemy import event

ADMIN_LIMIT = 5


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    # ── Encrypted username storage ─────────────────────────────────────────────
    # `_username_enc` holds the Fernet-encrypted ciphertext (stored in DB).
    # `username_hash` is a keyed HMAC used for WHERE-clause lookups.
    # Never access these columns directly — use the `username` property below.
    _username_enc  = db.Column("username",      db.Text,         unique=True, nullable=False)
    username_hash  = db.Column("username_hash", db.String(64),   unique=True, nullable=False, index=True)

    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(20),  default="member")  # admin | member | viewer
    is_approved   = db.Column(db.Boolean,     default=False)
    created_at    = db.Column(db.DateTime,    default=now_pst)
    last_seen     = db.Column(db.DateTime)
    avatar_color  = db.Column(db.String(7),   default="#e91e8c")

    # ── 2FA (TOTP) ────────────────────────────────────────────────────────────
    totp_secret_enc    = db.Column(db.Text,    nullable=True)
    totp_enabled       = db.Column(db.Boolean, default=False)
    require_2fa_setup  = db.Column(db.Boolean, default=False)

    # ── 2FA reset confirmation token ─────────────────────────────────────────
    reset_2fa_token        = db.Column(db.String(64), nullable=True, unique=True)
    reset_2fa_token_expiry = db.Column(db.DateTime,  nullable=True)

    # ── Login notification ────────────────────────────────────────────────────
    last_login_fingerprint = db.Column(db.String(64), nullable=True)
    notify_on_new_login    = db.Column(db.Boolean,    default=True)

    # Relationships
    logs = db.relationship(
        "AccessLog", backref="user", lazy="dynamic",
        cascade="all, delete-orphan"
    )
    activity_logs = db.relationship(
        "ActivityLog", backref="user", lazy="dynamic",
        cascade="all, delete-orphan"
    )
    password_history = db.relationship(
        "PasswordHistory", backref="user", lazy="dynamic",
        cascade="all, delete-orphan"
    )

    # ── Transparent username property ─────────────────────────────────────────

    @property
    def username(self) -> str:
        """Return the decrypted plaintext username."""
        if self._username_enc is None:
            return ""
        try:
            return decrypt_username(self._username_enc)
        except Exception:
            # Fallback: if decryption fails (e.g. key rotation in progress)
            # return the raw value so the app doesn't crash silently.
            return self._username_enc

    @username.setter
    def username(self, value: str):
        """Encrypt and store the username; also update the lookup hash."""
        if value is None:
            self._username_enc = None
            self.username_hash = None
            return
        self._username_enc = encrypt_username(value)
        self.username_hash  = hash_username(value)

    # ── Class-level lookup helper ─────────────────────────────────────────────

    @classmethod
    def get_by_username(cls, username: str):
        """Lookup a User by plaintext username via the HMAC hash index."""
        return cls.query.filter_by(username_hash=hash_username(username)).first()

    # ── Password helpers ──────────────────────────────────────────────────────

    def set_password(self, password):
        """Derive access key then bcrypt-hash it. Also saves to password history."""
        access_key = derive_access_key(password, self.username)
        new_hash = generate_password_hash(access_key)
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


# ── DB-level admin limit enforcement ──────────────────────────────────────────
# These listeners fire before any INSERT or UPDATE on the users table.
# They prevent the admin count from ever exceeding ADMIN_LIMIT at the
# database layer, regardless of how the change is attempted.

def _check_admin_limit(mapper, connection, target):
    """Raise ValueError if adding this admin would exceed ADMIN_LIMIT."""
    if target.role != "admin":
        return
    # Count current admins, excluding this record if it already exists (update case)
    from sqlalchemy import text
    result = connection.execute(
        text("SELECT COUNT(*) FROM users WHERE role = 'admin' AND id != :id"),
        {"id": target.id or -1}
    )
    current_count = result.scalar()
    if current_count >= ADMIN_LIMIT:
        raise ValueError(
            f"Admin limit of {ADMIN_LIMIT} has been reached. "
            "Cannot add or promote another admin."
        )

event.listen(User, "before_insert", _check_admin_limit)
event.listen(User, "before_update", _check_admin_limit)


class PasswordHistory(db.Model):
    """Stores previous derived password hashes to prevent reuse."""
    __tablename__ = "password_history"

    id            = db.Column(db.Integer,     primary_key=True)
    user_id       = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at    = db.Column(db.DateTime,    default=now_pst)


class AllowedIP(db.Model):
    __tablename__ = "allowed_ips"

    id         = db.Column(db.Integer,    primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    label      = db.Column(db.String(100))
    added_by   = db.Column(db.Integer,    db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = db.Column(db.DateTime,   default=now_pst)
    is_active  = db.Column(db.Boolean,    default=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class BlockedIP(db.Model):
    """IPs temporarily or permanently blocked by the honeypot or an admin.

    block_type values
    -----------------
    "brute_force"  – 30-minute cooldown after MAX_FAILED_ATTEMPTS bad logins.
    "honeypot"     – 24-hour ban triggered by probing a honeypot path.
    "admin"        – Manually added by an administrator (no automatic expiry).
    """
    __tablename__ = "blocked_ips"

    id         = db.Column(db.Integer,    primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason     = db.Column(db.String(300))
    # "brute_force" | "honeypot" | "admin"
    block_type = db.Column(db.String(20), nullable=False, default="honeypot")
    blocked_at = db.Column(db.DateTime,   default=now_pst)
    expires_at = db.Column(db.DateTime,   nullable=True)   # NULL = permanent
    is_active  = db.Column(db.Boolean,    default=True)

    def is_currently_blocked(self):
        if not self.is_active:
            return False
        if self.expires_at is None:
            return True
        return now_pst() < self.expires_at
