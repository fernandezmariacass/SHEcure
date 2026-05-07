from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="member")  # admin | member | viewer
    is_approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime)
    avatar_color = db.Column(db.String(7), default="#e91e8c")

    logs = db.relationship("AccessLog", backref="user", lazy="dynamic")
    activity_logs = db.relationship("ActivityLog", backref="user", lazy="dynamic")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


class AllowedIP(db.Model):
    __tablename__ = "allowed_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    label = db.Column(db.String(100))
    added_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
