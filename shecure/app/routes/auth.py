import os
import hashlib
import requests as http_requests
from datetime import timedelta
from urllib.parse import urlparse, urljoin
from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, jsonify, session)
from flask_login import login_user, logout_user, login_required, current_user
from app import db, limiter
from app.models.user import User
from app.models.logs import AccessLog, now_pst
from app.utils.security import log_access, validate_password_strength, admin_required
from app.utils.honeypot import is_honeypot_password, fire_honeypot_alert
from app.utils.totp_utils import (
    generate_totp_secret, encrypt_secret, get_qr_data_uri, verify_totp
)
from app.utils.email_utils import (
    build_login_fingerprint, is_new_fingerprint, send_new_login_alert
)

auth_bp = Blueprint("auth", __name__)

MAX_FAILED_ATTEMPTS = 3
LOCKOUT_MINUTES = 30
RECAPTCHA_SECRET = os.environ.get("RECAPTCHA_SECRET_KEY", "")
RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
RECAPTCHA_MIN_SCORE = 0.5


# ── reCAPTCHA ─────────────────────────────────────────────────────────────────

def _verify_recaptcha(token):
    if not RECAPTCHA_SECRET or not token:
        return True
    try:
        resp = http_requests.post(RECAPTCHA_VERIFY_URL, data={
            "secret": RECAPTCHA_SECRET,
            "response": token,
            "remoteip": request.remote_addr,
        }, timeout=5)
        result = resp.json()
        return result.get("success") and result.get("score", 0) >= RECAPTCHA_MIN_SCORE
    except Exception:
        return True


# ── Brute-force lockout ───────────────────────────────────────────────────────

def _is_locked_out(ip):
    cutoff = now_pst() - timedelta(minutes=LOCKOUT_MINUTES)
    failures = AccessLog.query.filter(
        AccessLog.ip_address == ip,
        AccessLog.status == "failed",
        AccessLog.timestamp > cutoff,
    ).count()
    return failures >= MAX_FAILED_ATTEMPTS


def _is_username_locked(username):
    from sqlalchemy import func
    cutoff = now_pst() - timedelta(minutes=LOCKOUT_MINUTES)
    failures = AccessLog.query.filter(
        func.lower(AccessLog.username_attempted) == username.lower(),
        AccessLog.status == "failed",
        AccessLog.timestamp > cutoff,
    ).count()
    return failures >= MAX_FAILED_ATTEMPTS


# ── Safe redirect ─────────────────────────────────────────────────────────────

def _is_safe_url(target):
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, target))
    return test.scheme in ("http", "https") and ref.netloc == test.netloc


# ── HaveIBeenPwned k-anonymity breach check ───────────────────────────────────

def _is_pwned(password: str) -> bool:
    """
    Check if `password` appears in known breach dumps via the HIBP k-anonymity
    API. Only the first 5 chars of the SHA-1 hash are sent to HIBP — the full
    hash never leaves the server. Returns True if found, False on any error.
    """
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        resp = http_requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=3,
        )
        if resp.status_code != 200:
            return False
        for line in resp.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0] == suffix:
                return int(parts[1]) > 0
    except Exception:
        pass
    return False


# ── Routes ────────────────────────────────────────────────────────────────────

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
        totp_code = request.form.get("totp_code", "").strip()
        ip = request.remote_addr
        ua = request.user_agent.string

        # reCAPTCHA v3
        if not _verify_recaptcha(recaptcha_token):
            log_access(username, "blocked", reason="Failed reCAPTCHA (bot detected)")
            flash("Verification failed. Please try again.", "danger")
            return render_template("auth/login.html")

        # Brute-force lockout: by IP
        if _is_locked_out(ip):
            log_access(username, "blocked", reason="Brute force lockout (IP)")
            flash(f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.", "danger")
            return render_template("auth/login.html")

        # Brute-force lockout: by username
        if _is_username_locked(username):
            log_access(username, "blocked", reason="Brute force lockout (username)")
            flash(f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.", "danger")
            return render_template("auth/login.html")

        # DB lookup (before honeypot to normalise timing)
        user = User.query.filter_by(username=username).first()

        # Honeypot canary check
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

        if not user.is_approved:
            log_access(username, "blocked", reason="Account not approved", user_id=user.id)
            flash("Your account is pending approval by an administrator.", "warning")
            return render_template("auth/login.html")

        # ── TOTP check (only if enabled for this user) ─────────────────────
        if user.totp_enabled:
            if not totp_code:
                # Password was correct — ask for TOTP code
                # Store a short-lived flag in the session so the form can show
                # the TOTP input field on re-render.
                session["_totp_pending_user"] = user.id
                flash("Enter your 6-digit authenticator code.", "info")
                return render_template("auth/login.html", totp_required=True,
                                       username=username)
            if not verify_totp(user.totp_secret_enc, totp_code):
                log_access(username, "failed", reason="Invalid TOTP code", user_id=user.id)
                flash("Invalid authenticator code. Please try again.", "danger")
                return render_template("auth/login.html", totp_required=True,
                                       username=username)
        # Clear any pending TOTP session flag
        session.pop("_totp_pending_user", None)

        # ── Successful login ───────────────────────────────────────────────
        login_user(user, remember=remember)
        user.last_seen = now_pst()

        # Login notification: alert if new device/IP fingerprint
        new_device = is_new_fingerprint(user, ip, ua)
        user.last_login_fingerprint = build_login_fingerprint(ip, ua)
        db.session.commit()

        if new_device:
            send_new_login_alert(
                user, ip, ua,
                timestamp=now_pst().strftime("%Y-%m-%d %H:%M:%S")
            )

        log_access(username, "success", user_id=user.id)
        flash(f"Welcome back, {user.username}!", "success")

        next_page = request.args.get("next")
        if not next_page or not _is_safe_url(next_page):
            next_page = url_for("dashboard.home")
        return redirect(next_page)

    # GET — check if we're mid-TOTP flow
    totp_required = "_totp_pending_user" in session
    return render_template("auth/login.html", totp_required=totp_required)


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

        # HaveIBeenPwned breach check
        if _is_pwned(password):
            flash(
                "This password has appeared in a known data breach. "
                "Please choose a different password.",
                "danger",
            )
            return render_template("auth/register.html")

        # Generic message to prevent username/email enumeration
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


# ── 2FA setup routes ──────────────────────────────────────────────────────────

@auth_bp.route("/settings/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    """Show a QR code and confirm enrollment with a test code."""
    user = current_user

    if request.method == "POST":
        code = request.form.get("totp_code", "").strip()
        pending_secret_enc = session.get("_totp_setup_secret")
        if not pending_secret_enc:
            flash("Session expired. Please start 2FA setup again.", "danger")
            return redirect(url_for("auth.setup_2fa"))
        if not verify_totp(pending_secret_enc, code):
            flash("Incorrect code. Please scan the QR code again and try once more.", "danger")
            return redirect(url_for("auth.setup_2fa"))
        # Confirmed — save to user
        user.totp_secret_enc = pending_secret_enc
        user.totp_enabled = True
        session.pop("_totp_setup_secret", None)
        db.session.commit()
        flash("Two-factor authentication is now enabled on your account.", "success")
        return redirect(url_for("dashboard.home"))

    # GET — generate a new secret, stash encrypted copy in session
    raw_secret = generate_totp_secret()
    enc_secret = encrypt_secret(raw_secret)
    session["_totp_setup_secret"] = enc_secret
    qr_data_uri = get_qr_data_uri(raw_secret, user.username)
    return render_template("auth/setup_2fa.html", qr_data_uri=qr_data_uri)


@auth_bp.route("/settings/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    """Allow a user to disable 2FA (requires password confirmation)."""
    password = request.form.get("password", "")
    if not current_user.check_password(password):
        flash("Incorrect password. 2FA was not disabled.", "danger")
        return redirect(url_for("dashboard.home"))
    current_user.totp_enabled = False
    current_user.totp_secret_enc = None
    db.session.commit()
    flash("Two-factor authentication has been disabled.", "warning")
    return redirect(url_for("dashboard.home"))


@auth_bp.route("/test-email")
@login_required
@admin_required
def test_email():
    from app.utils.email_utils import _send_email
    _send_email(
        current_user.email,
        "SHEcure Test Email",
        "<h2>It works!</h2><p>SMTP is configured correctly.</p>"
    )
    flash("Test email sent — check your inbox and Railway logs.", "info")
    return redirect(url_for("dashboard.home"))


@auth_bp.route("/debug-ip")
@login_required
@admin_required
def debug_ip():
    return jsonify({
        "remote_addr": request.remote_addr,
        "x_forwarded_for": request.headers.get("X-Forwarded-For"),
        "x_real_ip": request.headers.get("X-Real-IP"),
    })
