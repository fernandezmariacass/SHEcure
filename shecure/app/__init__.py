import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address)


def create_app():
    app = Flask(__name__)

    # Core config
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-in-production")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///shecure.db"
    )
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgres://"):
        app.config["SQLALCHEMY_DATABASE_URI"] = app.config[
            "SQLALCHEMY_DATABASE_URI"
        ].replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB

    # Extensions
    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access SHEcure."
    login_manager.login_message_category = "warning"

    # Blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.admin import admin_bp
    from app.routes.camera import camera_bp
    from app.routes.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(camera_bp, url_prefix="/camera")
    app.register_blueprint(api_bp, url_prefix="/api")

    # Create tables
    with app.app_context():
        db.create_all()
        _seed_default_admin()

    # Register security middleware
    from app.utils.security import register_security_middleware
    register_security_middleware(app)

    return app


def _seed_default_admin():
    from app.models.user import User
    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            email=os.environ.get("ADMIN_EMAIL", "admin@shecure.local"),
            role="admin",
            is_approved=True,
        )
        admin.set_password(os.environ.get("ADMIN_PASSWORD", "SHEcure@2025!"))
        db.session.add(admin)
        db.session.commit()
