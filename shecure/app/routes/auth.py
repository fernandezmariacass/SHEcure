from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import db, limiter
from app.models.user import User
from app.models.logs import AccessLog
from app.utils.security import log_access

auth_bp = Blueprint("auth", __name__)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def _is_locked_out(ip):
    cutoff = datetime.utcnow() - timedelta(minutes=LOCKOUT_MINUTES)
    failures = AccessLog.query.filter(
        AccessLog.ip_address == ip,
        AccessLog.status == "failed",
        AccessLog.timestamp > cutoff,
    ).count()
    return failures >= MAX_FAILED_ATTEMPTS


@auth_bp.route("/", methods=["GET"])
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)

        # --- Brute force lockout ---
        if _is_locked_out(ip):
            log_access(username, "blocked", reason="Brute force lockout")
            flash(f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.", "danger")
            return render_template("auth/login.html")

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            log_access(username, "failed", reason="Invalid credentials")
            remaining = MAX_FAILED_ATTEMPTS - (
                AccessLog.query.filter(
                    AccessLog.ip_address == ip,
                    AccessLog.status == "failed",
                    AccessLog.timestamp > datetime.utcnow() - timedelta(minutes=LOCKOUT_MINUTES),
                ).count()
            )
            flash(f"Invalid username or password. {remaining} attempts remaining.", "danger")
            return render_template("auth/login.html")

        if not user.is_approved:
            log_access(username, "blocked", reason="Account not approved", user_id=user.id)
            flash("Your account is pending approval.", "warning")
            return render_template("auth/login.html")

        login_user(user, remember=remember)
        user.last_seen = datetime.utcnow()
        db.session.commit()
        log_access(username, "success", user_id=user.id)
        flash(f"Welcome back, {user.username}!", "success")
        next_page = request.args.get("next")
        return redirect(next_page or url_for("dashboard.home"))

    return render_template("auth/login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not all([username, email, password, confirm]):
            flash("All fields are required.", "danger")
            return render_template("auth/register.html")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("auth/register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("auth/register.html")

        # Password strength check
        import re
        if not re.search(r'[A-Z]', password):
            flash("Password must contain at least one uppercase letter.", "danger")
            return render_template("auth/register.html")
        if not re.search(r'[0-9]', password):
            flash("Password must contain at least one number.", "danger")
            return render_template("auth/register.html")

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return render_template("auth/register.html")

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return render_template("auth/register.html")

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful! Await admin approval.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")

@auth_bp.route("/logout")
@login_required
def logout():
    log_access(current_user.username, "logout", user_id=current_user.id)
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/debug-ip")
def debug_ip():
    from flask import jsonify
    return jsonify({
        "remote_addr": request.remote_addr,
        "x_forwarded_for": request.headers.get("X-Forwarded-For"),
        "x_real_ip": request.headers.get("X-Real-IP"),
    })
