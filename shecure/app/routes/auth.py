from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db, limiter
from app.models.user import User
from app.utils.security import log_access

auth_bp = Blueprint("auth", __name__)


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

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            log_access(username, "failed", reason="Invalid credentials")
            flash("Invalid username or password.", "danger")
            return render_template("auth/login.html")

        if not user.is_approved:
            log_access(username, "blocked", reason="Account not approved", user_id=user.id)
            flash("Your account is pending approval by an administrator.", "warning")
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

        flash("Registration successful! Await admin approval before logging in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/logout")
@login_required
def logout():
    log_access(current_user.username, "logout", user_id=current_user.id)
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
