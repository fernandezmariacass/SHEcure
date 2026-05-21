import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address)
csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)

    secret_key = os.environ.get("SECRET_KEY", "")
    if not secret_key:
        raise RuntimeError("SECRET_KEY environment variable must be set in production.")
    app.config["SECRET_KEY"] = secret_key
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///shecure.db"
    )
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgres://"):
        app.config["SQLALCHEMY_DATABASE_URI"] = app.config[
            "SQLALCHEMY_DATABASE_URI"
        ].replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

    is_https = (
        os.environ.get("RAILWAY_ENVIRONMENT") is not None
        or os.environ.get("FLASK_ENV") == "production"
    )
    app.config["SESSION_COOKIE_SECURE"] = is_https
    app.wsgi_app = __import__(
        "werkzeug.middleware.proxy_fix", fromlist=["ProxyFix"]
    ).ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = 3600

    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access SHEcure."
    login_manager.login_message_category = "warning"

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

    with app.app_context():
        db.create_all()
        _seed_default_admin()

    from app.utils.security import register_security_middleware
    register_security_middleware(app)

    @app.before_request
    def set_csp_nonce():
        import base64
        from flask import g
        g.csp_nonce = base64.b64encode(os.urandom(16)).decode("utf-8")

    @app.context_processor
    def inject_template_globals():
        from flask import g
        return {
            "recaptcha_site_key": os.environ.get("RECAPTCHA_SITE_KEY", ""),
            "csp_nonce": g.get("csp_nonce", ""),
        }

    # ── Security headers on every response ────────────────────────────────────
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # ADDED: HSTS — tells browsers to only connect over HTTPS for 1 year.
        # Only set in production (where HTTPS is active) to avoid breaking
        # local http:// development.
        if is_https:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        # ADDED: Tightened Permissions-Policy — deny payment, USB, bluetooth,
        # display-capture, and other high-risk browser features.
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(self), "
            "payment=(), usb=(), bluetooth=(), "
            "display-capture=(), idle-detection=(), "
            "serial=(), hid=()"
        )

        from flask import g
        nonce = g.get("csp_nonce", "")
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' "
            "https://www.google.com https://www.gstatic.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
            "frame-src https://www.google.com; "
            "connect-src 'self' https://www.google.com;"
        )
        return response

    return app


def _seed_default_admin():
    from app.models.user import User
    if not User.query.filter_by(username="admin").first():
        admin_email = os.environ.get("ADMIN_EMAIL", "")
        admin_password = os.environ.get("ADMIN_PASSWORD", "")
        if not admin_email or not admin_password:
            raise RuntimeError(
                "ADMIN_EMAIL and ADMIN_PASSWORD must be set to seed the admin account."
            )
        admin = User(
            username="admin",
            email=admin_email,
            role="admin",
            is_approved=True,
        )
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
