import os
import requests as http_requests
from datetime import timedelta
from urllib.parse import urlparse, urljoin
from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db, limiter
from app.models.user import User
from app.models.logs import AccessLog, now_pst
from app.utils.security import log_access, validate_password_strength, admin_required
from app.utils.honeypot import is_honeypot_password, fire_honeypot_alert

auth_bp = Blueprint("auth", __name__)

MAX_FAILED_ATTEMPTS = 3
LOCKOUT_MINUTES = 30
RECAPTCHA_SECRET = os.environ.get("RECAPTCHA_SECRET_KEY", "")
RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
RECAPTCHA_MIN_SCORE = 0.5


def _verify_recaptcha(token):
    """Verify reCAPTCHA v3 token with Google. Returns True if human, False if bot."""
    if not RECAPTCHA_SECRET or not token:
        return True  # If not configured, fail open (don't break login)
    try:
        resp = http_requests.post(RECAPTCHA_VERIFY_URL, data={
            "secret": RECAPTCHA_SECRET,
            "response": token,
            "remoteip": request.remote_addr,
        }, timeout=5)
        result = resp.json()
        return result.get("success") and result.get("score", 0) >= RECAPTCHA_MIN_SCORE
    except Exception:
        return True  # Network error — fail open so real users aren't locked out


def _is_locked_out(ip):
    """Block by IP address."""
    cutoff = now_pst() - timedelta(minutes=LOCKOUT_MINUTES)
    failures = AccessLog.query.filter(
        AccessLog.ip_address == ip,
        AccessLog.status == "failed",
        AccessLog.timestamp > cutoff,
    ).count()
    return failures >= MAX_FAILED_ATTEMPTS


def _is_username_locked(username):
    """Block by username — catches attackers rotating IPs."""
    cutoff = now_pst() - timedelta(minutes=LOCKOUT_MINUTES)
    failures = AccessLog.query.filter(
        AccessLog.username_attempted == username,
        AccessLog.status == "failed",
        AccessLog.timestamp > cutoff,
    ).count()
    return failures >= MAX_FAILED_ATTEMPTS


def _is_safe_url(target):
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, target))
    return test.scheme in ("http", "https") and ref.netloc == test.netloc


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
        recaptcha_token = request.form.get("g-recaptcha-response", "")
        ip = request.remote_addr
        ua = request.user_agent.string

        # --- reCAPTCHA v3 check ---
        if not _verify_recaptcha(recaptcha_token):
            log_access(username, "blocked", reason="Failed reCAPTCHA (bot detected)")
            flash("Verification failed. Please try again.", "danger")
            return render_template("auth/login.html")

        # --- Brute force lockout: by IP ---
        if _is_locked_out(ip):
            log_access(username, "blocked", reason="Brute force lockout (IP)")
            flash(f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.", "danger")
            return render_template("auth/login.html")

        # --- Brute force lockout: by username (catches proxy rotators) ---
        if _is_username_locked(username):
            log_access(username, "blocked", reason="Brute force lockout (username)")
            flash(f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.", "danger")
            return render_template("auth/login.html")

        # --- DB lookup first (before honeypot) to normalise timing ---
        user = User.query.filter_by(username=username).first()

        # --- Honeypot canary check AFTER DB lookup so timing is consistent ---
        if is_honeypot_password(password):
            fire_honeypot_alert(username, ip, ua)
            flash("Invalid username or password. 2 attempts remaining.", "danger")
            return render_template("auth/login.html")

        if not user or not user.check_password(password):
            log_access(username, "failed", reason="Invalid credentials")
            remaining = max(0, MAX_FAILED_ATTEMPTS - (
                AccessLog.query.filter(
                    AccessLog.ip_address == ip,
                    AccessLog.status == "failed",
                    AccessLog.timestamp > now_pst() - timedelta(minutes=LOCKOUT_MINUTES),
                ).count()
            ))
            flash(f"Invalid username or password. {remaining} attempts remaining.", "danger")
            return render_template("auth/login.html")

        # FIX: is_approved check moved AFTER password verification.
        # Correct password but not yet approved → clear "pending approval" message.
        # Wrong password → still just "invalid credentials" (no info leak).
        if not user.is_approved:
            log_access(username, "blocked", reason="Account not approved", user_id=user.id)
            flash("Your account is pending approval by an administrator.", "warning")
            return render_template("auth/login.html")

        # --- Clear session before login to prevent session fixation ---
        session.clear()

        login_user(user, remember=remember)
        user.last_seen = now_pst()
        db.session.commit()
        log_access(username, "success", user_id=user.id)
        flash(f"Welcome back, {user.username}!", "success")

        next_page = request.args.get("next")
        if not next_page or not _is_safe_url(next_page):
            next_page = url_for("dashboard.home")
        return redirect(next_page)

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
        recaptcha_token = request.form.get("g-recaptcha-response", "")

        # --- reCAPTCHA v3 check ---
        if not _verify_recaptcha(recaptcha_token):
            flash("Verification failed. Please try again.", "danger")
            return render_template("auth/register.html")

        if not all([username, email, password, confirm]):
            flash("All fields are required.", "danger")
            return render_template("auth/register.html")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("auth/register.html")

        pw_errors = validate_password_strength(password, username=username, email=email)
        if pw_errors:
            for err in pw_errors:
                flash(err, "danger")
            return render_template("auth/register.html")

        # --- Generic message prevents username/email enumeration ---
        if User.query.filter_by(username=username).first() or \
           User.query.filter_by(email=email).first():
            flash("An account with those details already exists.", "danger")
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
@login_required
@admin_required
def debug_ip():
    return jsonify({
        "remote_addr": request.remote_addr,
        "x_forwarded_for": request.headers.get("X-Forwarded-For"),
        "x_real_ip": request.headers.get("X-Real-IP"),
    })
