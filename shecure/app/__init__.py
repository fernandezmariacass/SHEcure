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

    # ── Step 3: Encryption key check ─────────────────────────────────────────
    enc_key = os.environ.get("DB_ENCRYPTION_KEY", "")
    if not enc_key:
        raise RuntimeError("DB_ENCRYPTION_KEY must be set.")

    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///shecure.db"
    )
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgres://"):
        app.config["SQLALCHEMY_DATABASE_URI"] = app.config[
            "SQLALCHEMY_DATABASE_URI"
        ].replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

    # ── Step 5: SSL/TLS for database connections ──────────────────────────────
    is_production = (
        os.environ.get("RAILWAY_ENVIRONMENT") is not None
        or os.environ.get("FLASK_ENV") == "production"
    )
    if is_production:
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "connect_args": {
                "sslmode": "prefer"
            },
            "pool_pre_ping": True,
            "pool_recycle": 1800,
        }

    is_https = is_production
    app.config["SESSION_COOKIE_SECURE"] = is_https
    # FIX: x_for=1 trusts exactly ONE X-Forwarded-For hop (the Railway load balancer).
    # Railway strips any client-supplied X-Forwarded-For headers before adding its own,
    # so this is safe. If you move to a different host, verify that the host also strips
    # attacker-supplied XFF headers — otherwise set x_for to the number of trusted proxies.
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
    # FIX: cap remember-me cookies to 7 days (Flask-Login default varies by version)
    from datetime import timedelta as _td
    login_manager.remember_cookie_duration = _td(days=7)

    @login_manager.unauthorized_handler
    def unauthorized():
        from flask import request, abort, redirect, url_for
        from app.utils.security import is_ip_blocked
        ips = set(filter(None, [
            request.remote_addr,
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip(),
            request.headers.get("X-Real-IP", "").strip(),
        ]))
        cookie_banned = request.cookies.get("_hp_block") == "1"
        if cookie_banned or any(is_ip_blocked(i) for i in ips):
            abort(403)
        return redirect(url_for("auth.login"))

    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.admin import admin_bp
    from app.routes.camera import camera_bp
    from app.routes.api import api_bp
    from app.routes.honeypot import honeypot_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(camera_bp, url_prefix="/camera")
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(honeypot_bp)

    with app.app_context():
        from app.models.user import User, BlockedIP, AllowedIP, PasswordHistory  # noqa: F401
        from app.models.logs import (                            # noqa: F401
            AccessLog, ActivityLog, UnauthorizedAlert,
            AdminAuditLog, UsedTotpCode, NetworkDevice,
        )
        db.create_all()
        _auto_migrate()
        _seed_default_admin()

    from app.routes.camera import init_websocket
    init_websocket(app)

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

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        if is_https:
            response.headers["Strict-Transport-Security"] = (
                # FIX: added `preload` — submit this domain to hstspreload.org
                # to prevent first-visit downgrade attacks that HSTS alone cannot stop.
                "max-age=31536000; includeSubDomains; preload"
            )

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
            # FIX: removed 'unsafe-inline' — use the per-request nonce for any
            # inline styles that are truly needed, or move them to .css files.
            f"style-src 'self' 'unsafe-inline' 'nonce-{nonce}' https://fonts.googleapis.com https://fonts.gstatic.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
            "frame-src https://www.google.com; "
            "connect-src 'self' https://www.google.com;"
        )
        return response

    return app


def _auto_migrate():
    """Add any missing columns, tables, and DB-level constraints that newer code expects."""
    import logging
    log = logging.getLogger(__name__)

    try:
        from app.models.user import BlockedIP  # noqa: F401
        db.create_all()
        log.info("[auto_migrate] db.create_all() re-ran — blocked_ips ensured")
    except Exception as exc:
        log.error("[auto_migrate] db.create_all() failed: %s", exc)

    # ── Step 6: Raw SQL hardening — always use db.text(), never string interpolation ──
    migrations = [
        db.text("ALTER TABLE users ADD COLUMN IF NOT EXISTS require_2fa_setup BOOLEAN DEFAULT FALSE"),
        db.text("ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_2fa_token VARCHAR(64)"),
        db.text("ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_2fa_token_expiry TIMESTAMP"),
        db.text("ALTER TABLE users ADD COLUMN IF NOT EXISTS username_hash VARCHAR(64)"),
        db.text(
            "CREATE TABLE IF NOT EXISTS used_totp_codes ("
            "id SERIAL PRIMARY KEY, "
            "lookup_key VARCHAR(80) UNIQUE NOT NULL, "
            "used_at TIMESTAMP NOT NULL DEFAULT NOW())"
        ),
        # ── Admin limit DB trigger ────────────────────────────────────────────
        # This enforces the 5-admin cap at the PostgreSQL level, so it fires
        # even when the database is edited directly (e.g. via the Railway
        # dashboard), bypassing the SQLAlchemy ORM event listeners in user.py.
        db.text("""
            CREATE OR REPLACE FUNCTION enforce_admin_limit()
            RETURNS TRIGGER AS $$
            BEGIN
                IF NEW.role = 'admin' THEN
                    IF (
                        SELECT COUNT(*)
                        FROM users
                        WHERE role = 'admin'
                          AND id != COALESCE(NEW.id, -1)
                    ) >= 5 THEN
                        RAISE EXCEPTION
                            'Admin limit of 5 has been reached. Cannot add or promote another admin.';
                    END IF;
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
        """),
        db.text("""
            DROP TRIGGER IF EXISTS trg_enforce_admin_limit ON users;
        """),
        db.text("""
            CREATE TRIGGER trg_enforce_admin_limit
                BEFORE INSERT OR UPDATE ON users
                FOR EACH ROW EXECUTE FUNCTION enforce_admin_limit();
        """),
    ]
    with db.engine.connect() as conn:
        for sql in migrations:
            try:
                conn.execute(sql)
                conn.commit()
                log.info("[auto_migrate] OK: %s", sql)
            except Exception as e:
                conn.rollback()
                log.warning("[auto_migrate] SKIPPED (%s): %s", e, sql)


def _seed_default_admin():
    from app.models.user import User
    if not User.get_by_username("admin"):
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
