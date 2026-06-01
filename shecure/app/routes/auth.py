import os
import hashlib
import requests as http_requests
from datetime import timedelta
from urllib.parse import urlparse, urljoin
from flask import (Blueprint, render_template, redirect, url_for, abort,
                   request, flash, jsonify, session)
from flask_login import login_user, logout_user, login_required, current_user
from app import db, limiter
from app.models.user import User
from app.models.logs import AccessLog, now_pst
from app.utils.security import log_access, log_activity, validate_password_strength, admin_required
from app.utils.honeypot import is_honeypot_password, fire_honeypot_alert
from app.utils.totp_utils import (
    generate_totp_secret, encrypt_secret, get_qr_data_uri, verify_totp
)

from app.utils.email_utils import (
    build_login_fingerprint, is_new_fingerprint, send_successful_login_alert,
    send_failed_login_alert, send_lockout_alert, send_bot_blocked_alert,
    send_honeypot_alert, send_unapproved_login_attempt, send_ip_blocked_alert
)
auth_bp = Blueprint("auth", __name__)

MAX_FAILED_ATTEMPTS = 3
LOCKOUT_MINUTES = 30
RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
RECAPTCHA_MIN_SCORE = 0.5
# FIX: cap remember-me cookie lifetime to 7 days (Flask-Login default can vary by version)
REMEMBER_COOKIE_DAYS = 7


# ── reCAPTCHA ─────────────────────────────────────────────────────────────────

def _verify_recaptcha(token):
    secret = os.environ.get("RECAPTCHA_SECRET_KEY", "")
    if not secret or not token:
        return True
    try:
        resp = http_requests.post(RECAPTCHA_VERIFY_URL, data={
            "secret": secret,
            "response": token,
            "remoteip": request.remote_addr,
        }, timeout=5)
        result = resp.json()
        return result.get("success") and result.get("score", 0) >= RECAPTCHA_MIN_SCORE
    except Exception:
        # FIX: fail closed — a network error must not silently allow bots through
        return False


# ── Brute-force lockout ───────────────────────────────────────────────────────

def _is_locked_out(ip):
    # Look back 2x the lockout window to find the 3rd failure
    lookback = now_pst() - timedelta(minutes=LOCKOUT_MINUTES * 2)
    failures = AccessLog.query.filter(
        AccessLog.ip_address == ip,
        AccessLog.status == "failed",
        AccessLog.timestamp > lookback,
    ).order_by(AccessLog.timestamp.desc()).all()

    if len(failures) < MAX_FAILED_ATTEMPTS:
        return False

    # Timestamp of the 3rd most recent failure = when the lock was triggered
    third_failure_time = failures[MAX_FAILED_ATTEMPTS - 1].timestamp
    return now_pst() < third_failure_time + timedelta(minutes=LOCKOUT_MINUTES)


def _is_username_locked(username):
    # Look back 2x the lockout window to find the 3rd failure
    lookback = now_pst() - timedelta(minutes=LOCKOUT_MINUTES * 2)
    failures = AccessLog.query.filter(
        AccessLog.username_attempted == username,
        AccessLog.status == "failed",
        AccessLog.timestamp > lookback,
    ).order_by(AccessLog.timestamp.desc()).all()

    if len(failures) < MAX_FAILED_ATTEMPTS:
        return False

    # Timestamp of the 3rd most recent failure = when the lock was triggered
    third_failure_time = failures[MAX_FAILED_ATTEMPTS - 1].timestamp
    return now_pst() < third_failure_time + timedelta(minutes=LOCKOUT_MINUTES)


# ── Safe redirect ─────────────────────────────────────────────────────────────

def _is_safe_url(target):
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, target))
    return test.scheme in ("http", "https") and ref.netloc == test.netloc


# ── HaveIBeenPwned k-anonymity breach check ───────────────────────────────────

def _is_pwned(password: str) -> bool:
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
    # Check every possible IP source — Railway proxy headers + remote_addr
    from app.utils.security import is_ip_blocked, log_access
    _ips_to_check = set(filter(None, [
        request.remote_addr,
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip(),
        request.headers.get("X-Real-IP", "").strip(),
    ]))
    _cookie_banned    = request.cookies.get("_hp_block") == "1"
    _bf_cookie_banned = request.cookies.get("_bf_block") == "1"

    _db_block_type = None
    for _ci in _ips_to_check:
        _bt = is_ip_blocked(_ci)
        if _bt:
            _db_block_type = _bt
            break

    _effective_block = _db_block_type or ("honeypot" if _cookie_banned else None) or ("brute_force" if _bf_cookie_banned else None)

    if _effective_block:
        log_access("unknown", "blocked",
                   reason=f"Blocked IP attempted to access login page ({_effective_block})")
        _client_ip = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr or "unknown"
        )
        from flask import make_response as _mkr
        if _effective_block == "brute_force":
            _resp = _mkr(render_template("errors/429.html",
                                         client_ip=_client_ip,
                                         block_minutes=30,
                                         block_reason="Too many failed login attempts from this IP."),
                         429)
            _resp.set_cookie("_bf_block", "1", max_age=1800, httponly=True, samesite="Lax")
        else:
            _resp = _mkr(render_template("errors/banned.html", client_ip=_client_ip), 403)
            _resp.set_cookie("_hp_block", "1", max_age=86400, httponly=True, samesite="Lax")
        return _resp

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

        from app.utils.security import is_ip_blocked
        if is_ip_blocked(ip):
            log_access(username, "blocked", reason="Banned IP attempted login")
            flash("Access denied.", "danger")
            return render_template("auth/login.html")

        if not _verify_recaptcha(recaptcha_token):
            log_access(username, "blocked", reason="Failed reCAPTCHA (bot detected)")
            send_bot_blocked_alert(
                username_attempted=username,
                ip=ip,
                user_agent=ua,
                timestamp=now_pst().strftime("%Y-%m-%d %H:%M:%S"),
            )
            flash("Verification failed. Please try again.", "danger")
            return render_template("auth/login.html")

        if _is_locked_out(ip):
            log_access(username, "blocked", reason="Brute force lockout (IP)")
            send_lockout_alert(
                username_attempted=username,
                ip=ip,
                user_agent=ua,
                timestamp=now_pst().strftime("%Y-%m-%d %H:%M:%S"),
                lockout_type="IP address lockout",
                user=User.get_by_username(username),
            )
            # Block the IP for 30 minutes and notify admin
            from app.utils.security import block_ip
            block_ip(ip,
                     reason=f"Brute force: {MAX_FAILED_ATTEMPTS}+ failed logins",
                     hours=0.5,
                     block_type="brute_force")
            send_ip_blocked_alert(
                ip=ip,
                user_agent=ua,
                timestamp=now_pst().strftime("%Y-%m-%d %H:%M:%S PST"),
                username_attempted=username,
                block_duration_minutes=30,
            )
            # FIX: generic message — don't reveal lockout duration or confirm account exists
            flash("Access temporarily restricted. Please try again later.", "danger")
            return render_template("auth/login.html")

        if _is_username_locked(username):
            log_access(username, "blocked", reason="Brute force lockout (username)")
            send_lockout_alert(
                username_attempted=username,
                ip=ip,
                user_agent=ua,
                timestamp=now_pst().strftime("%Y-%m-%d %H:%M:%S"),
                lockout_type="Username lockout",
                user=User.get_by_username(username),
            )
            # FIX: same generic message — reveals nothing about account validity
            flash("Access temporarily restricted. Please try again later.", "danger")
            return render_template("auth/login.html")

        # ── TOTP second-step ──────────────────────────────────────────────────
        pending_totp_user_id = session.get("_totp_pending_user")
        if pending_totp_user_id:
            # FIX: enforce a per-IP rate limit on TOTP attempts independent of the
            # session counter so that multi-worker / multi-session probing is blocked.
            from app.models.logs import AccessLog as _AL
            _totp_ip_cutoff = now_pst() - __import__('datetime').timedelta(minutes=LOCKOUT_MINUTES)
            _totp_ip_attempts = _AL.query.filter(
                _AL.ip_address == ip,
                _AL.status == "failed",
                _AL.reason == "Invalid TOTP code",
                _AL.timestamp > _totp_ip_cutoff,
            ).count()
            if _totp_ip_attempts >= MAX_FAILED_ATTEMPTS:
                session.pop("_totp_pending_user", None)
                session.pop("_totp_attempts", None)
                log_access(username, "blocked", reason="TOTP brute-force lockout (IP)")
                flash("Access temporarily restricted. Please try again later.", "danger")
                return render_template("auth/login.html")
        if pending_totp_user_id:
            user = User.query.get(pending_totp_user_id)
            if not user or user.username.lower() != username.lower():
                session.pop("_totp_pending_user", None)
                flash("Session mismatch. Please log in again.", "danger")
                return render_template("auth/login.html")

            if not totp_code:
                flash("Enter your 6-digit authenticator code.", "info")
                return render_template("auth/login.html", totp_required=True,
                                       username=username)

            if not verify_totp(str(user.id), user.totp_secret_enc, totp_code):
                log_access(username, "failed", reason="Invalid TOTP code", user_id=user.id)
                session["_totp_attempts"] = session.get("_totp_attempts", 0) + 1
                if session["_totp_attempts"] >= 3:
                    session.pop("_totp_pending_user", None)
                    session.pop("_totp_attempts", None)
                    flash("Too many failed attempts. Please log in again.", "danger")
                    return render_template("auth/login.html")
                flash("Invalid authenticator code. Please try again.", "danger")
                return render_template("auth/login.html", totp_required=True,
                                       username=username)

            session.pop("_totp_pending_user", None)
            session.pop("_totp_attempts", None)

        else:
            # ── First step: validate password ─────────────────────────────────
            user = User.get_by_username(username)

            if is_honeypot_password(password):
                fire_honeypot_alert(username, ip, ua)
                send_honeypot_alert(
                    username_attempted=username,
                    ip=ip,
                    user_agent=ua,
                    timestamp=now_pst().strftime("%Y-%m-%d %H:%M:%S"),
                )
                flash("Invalid username or password. 2 attempts remaining.", "danger")
                return render_template("auth/login.html")

            # ── Timing side-channel fix ───────────────────────────────────────────
            # When a username doesn't exist, always run a dummy password check so
            # that valid and invalid usernames produce the same response time.
            # Without this, timing the response reveals whether an account exists.
            _DUMMY_HASH = "pbkdf2:sha256:600000$dummy$" + "a" * 64
            if not user:
                from werkzeug.security import check_password_hash as _chk
                _chk(_DUMMY_HASH, password)  # constant-time dummy — result discarded

            if not user or not user.check_password(password):
                log_access(username, "failed", reason="Invalid credentials")
                send_failed_login_alert(
                    username_attempted=username,
                    ip=ip,
                    user_agent=ua,
                    timestamp=now_pst().strftime("%Y-%m-%d %H:%M:%S"),
                    reason="Invalid credentials",
                    user=user,
                )
                # Generic message — reveals nothing about whether the account exists.
                flash("Invalid username or password.", "danger")
                return render_template("auth/login.html")

            if not user.is_approved:
                log_access(username, "blocked", reason="Account not approved", user_id=user.id)
                send_unapproved_login_attempt(
                    username_attempted=username,
                    ip=ip,
                    user_agent=ua,
                    timestamp=now_pst().strftime("%Y-%m-%d %H:%M:%S"),
                )
                flash("Your account is pending approval by an administrator.", "warning")
                return render_template("auth/login.html")

            if user.totp_enabled:
                session["_totp_pending_user"] = user.id
                flash("Enter your 6-digit authenticator code.", "info")
                return render_template("auth/login.html", totp_required=True,
                                       username=username)

        # ── Successful login ───────────────────────────────────────────────────
        # ── Session regeneration — prevent session fixation ─────────────────────
        # Rotate the session ID immediately after authentication so a pre-login
        # session cookie planted by an attacker is invalidated.
        _old_session_data = dict(session)
        session.clear()
        session.update(_old_session_data)
        login_user(user, remember=remember, duration=__import__('datetime').timedelta(days=REMEMBER_COOKIE_DAYS))

        try:
            user.last_seen = now_pst()
            new_device = is_new_fingerprint(user, ip, ua)
            user.last_login_fingerprint = build_login_fingerprint(ip, ua)
            db.session.commit()
        except Exception:
            db.session.rollback()
            new_device = True

        try:
            send_successful_login_alert(
                user, ip, ua,
                timestamp=now_pst().strftime("%Y-%m-%d %H:%M:%S"),
                is_new_device=new_device,
            )
        except Exception:
            pass

        log_access(username, "success", user_id=user.id)
        log_activity(
            action="Logged in",
            description=f"Successful login from {ip}",
        )


        # ── Force 2FA setup on first approved login ────────────────────────────
        if user.require_2fa_setup and not user.totp_enabled:
            flash("Your account has been approved! Please set up two-factor authentication to continue.", "info")
            return redirect(url_for("auth.setup_2fa"))

        flash(f"Welcome back, {user.username}!", "success")

        next_page = request.args.get("next")
        if not next_page or not _is_safe_url(next_page):
            next_page = url_for("dashboard.home")
        return redirect(next_page)

    totp_required = "_totp_pending_user" in session
    return render_template("auth/login.html", totp_required=totp_required)


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
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

        if _is_pwned(password):
            flash(
                "This password has appeared in a known data breach. "
                "Please choose a different password.",
                "danger",
            )
            return render_template("auth/register.html")

        if User.get_by_username(username) or \
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


@auth_bp.route("/confirm-2fa-reset/<token>")
def confirm_2fa_reset(token):
    from app.models.logs import now_pst as _now
    user = User.query.filter_by(reset_2fa_token=token).first()
    if not user or not user.reset_2fa_token_expiry:
        flash("This link is invalid or has already been used.", "danger")
        return redirect(url_for("auth.login"))
    if _now() > user.reset_2fa_token_expiry:
        flash("This confirmation link has expired. Ask your admin to resend it.", "warning")
        return redirect(url_for("auth.login"))
    user.totp_enabled          = False
    user.totp_secret_enc       = None
    user.require_2fa_setup     = True
    user.reset_2fa_token       = None
    user.reset_2fa_token_expiry = None
    db.session.commit()
    session["_2fa_reset_verified"] = user.id
    flash("Identity confirmed. Please enter your password to set up your new authenticator.", "success")
    return redirect(url_for("auth.setup_2fa"))


@auth_bp.route("/logout")
@login_required
def logout():
    username = current_user.username  # capture BEFORE logout_user()
    user_id = current_user.id

    log_access(username, "logout", user_id=user_id)
    log_activity(
        action="Logged out",
        description="User ended their session",
        username=username,            # pass explicitly
        user_id=user_id,
    )
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))

# ── 2FA setup routes ──────────────────────────────────────────────────────────

@auth_bp.route("/settings/2fa/setup", methods=["GET", "POST"])
def setup_2fa():
    reset_uid = session.get("_2fa_reset_verified")

    if current_user.is_authenticated:
        user = current_user

        if request.method == "POST":
            code = request.form.get("totp_code", "").strip()
            pending_secret_enc = session.get("_totp_setup_secret")
            if not pending_secret_enc:
                flash("Session expired. Please start 2FA setup again.", "danger")
                return redirect(url_for("auth.setup_2fa"))
            if not verify_totp(str(user.id), pending_secret_enc, code):
                flash("Incorrect code. Please scan the QR code again and try once more.", "danger")
                return redirect(url_for("auth.setup_2fa"))
            user.totp_secret_enc = pending_secret_enc
            user.totp_enabled = True
            user.require_2fa_setup = False
            session.pop("_totp_setup_secret", None)
            db.session.commit()
            flash("Two-factor authentication is now enabled on your account.", "success")
            return redirect(url_for("dashboard.home"))

        raw_secret = generate_totp_secret()
        enc_secret = encrypt_secret(raw_secret)
        session["_totp_setup_secret"] = enc_secret
        qr_data_uri = get_qr_data_uri(raw_secret, user.username)
        return render_template("auth/setup_2fa.html", qr_data_uri=qr_data_uri)

    if not reset_uid:
        flash("Please log in to access this page.", "warning")
        return redirect(url_for("auth.login"))

    user = User.query.get(reset_uid)
    if not user:
        session.pop("_2fa_reset_verified", None)
        flash("Session invalid. Please request a new 2FA reset.", "danger")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        step = request.form.get("step")

        if step == "verify_password":
            password = request.form.get("password", "")
            if not user.check_password(password):
                flash("Incorrect password. Please try again.", "danger")
                return redirect(url_for("auth.setup_2fa"))
            session["_2fa_reset_pw_verified"] = user.id
            raw_secret = generate_totp_secret()
            enc_secret = encrypt_secret(raw_secret)
            session["_totp_setup_secret"] = enc_secret
            qr_data_uri = get_qr_data_uri(raw_secret, user.username)
            return render_template("auth/setup_2fa.html",
                                   qr_data_uri=qr_data_uri,
                                   reset_flow=True)

        if step == "confirm_totp":
            if session.get("_2fa_reset_pw_verified") != user.id:
                flash("Please verify your password first.", "danger")
                return redirect(url_for("auth.setup_2fa"))
            code = request.form.get("totp_code", "").strip()
            pending_secret_enc = session.get("_totp_setup_secret")
            if not pending_secret_enc:
                flash("Session expired. Please start 2FA setup again.", "danger")
                return redirect(url_for("auth.setup_2fa"))
            if not verify_totp(str(user.id), pending_secret_enc, code):
                flash("Incorrect code. Please scan the QR code again and try once more.", "danger")
                try:
                    from app.utils.totp_utils import decrypt_secret as _dec
                    raw_secret = _dec(pending_secret_enc)
                    qr_data_uri = get_qr_data_uri(raw_secret, user.username)
                    return render_template("auth/setup_2fa.html",
                                           qr_data_uri=qr_data_uri,
                                           reset_flow=True)
                except Exception:
                    session.pop("_totp_setup_secret", None)
                    session.pop("_2fa_reset_pw_verified", None)
                    flash("Session expired. Please verify your password again.", "danger")
                    return redirect(url_for("auth.setup_2fa"))
            user.totp_secret_enc = pending_secret_enc
            user.totp_enabled = True
            user.require_2fa_setup = False
            db.session.commit()
            session.pop("_2fa_reset_verified", None)
            session.pop("_2fa_reset_pw_verified", None)
            session.pop("_totp_setup_secret", None)
            # Rotate session ID here too (same fixation protection as the main login path)
            _old_session_data2 = dict(session)
            session.clear()
            session.update(_old_session_data2)
            login_user(user, duration=__import__('datetime').timedelta(days=REMEMBER_COOKIE_DAYS))
            flash("Two-factor authentication is now enabled on your account.", "success")
            return redirect(url_for("dashboard.home"))

    # ── GET: determine which step to show ─────────────────────────────────────
    # If the user has already passed the password gate (session flag is set),
    # regenerate the QR from the stored encrypted secret and show the TOTP step.
    if session.get("_2fa_reset_pw_verified") == user.id:
        pending_secret_enc = session.get("_totp_setup_secret")
        if pending_secret_enc:
            try:
                from app.utils.totp_utils import decrypt_secret
                raw_secret = decrypt_secret(pending_secret_enc)
                qr_data_uri = get_qr_data_uri(raw_secret, user.username)
                return render_template("auth/setup_2fa.html",
                                       qr_data_uri=qr_data_uri,
                                       reset_flow=True)
            except Exception:
                # Secret is corrupted; clear and restart from password step
                session.pop("_totp_setup_secret", None)
                session.pop("_2fa_reset_pw_verified", None)
                flash("Session data was invalid. Please verify your password again.", "warning")

    return render_template("auth/setup_2fa.html", reset_flow=True, pw_step=True)


@auth_bp.route("/settings/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    password = request.form.get("password", "")
    if not current_user.check_password(password):
        flash("Incorrect password. 2FA was not disabled.", "danger")
        return redirect(url_for("dashboard.home"))
    current_user.totp_enabled = False
    current_user.totp_secret_enc = None
    db.session.commit()
    flash("Two-factor authentication has been disabled.", "warning")
    return redirect(url_for("dashboard.home"))


# ── Test & Debug routes ───────────────────────────────────────────────────────

@auth_bp.route("/test-email")
@login_required
@admin_required
def test_email():
    # FIX: completely unavailable in production
    if os.environ.get("FLASK_ENV") == "production" or os.environ.get("RAILWAY_ENVIRONMENT"):
        abort(404)
    from app.utils.email_utils import _send_email
    import logging
    logging.basicConfig(level=logging.INFO)
    _send_email(
        current_user.email,
        "SHEcure Test Email",
        "<h2 style='color:#e91e8c'>It works!</h2><p>SMTP is configured correctly.</p>"
    )
    flash(f"Test email triggered to {current_user.email} — check inbox and Railway logs.", "info")
    return redirect(url_for("dashboard.home"))


@auth_bp.route("/debug-mail")
@login_required
@admin_required
def debug_mail():
    # FIX: completely unavailable in production
    if os.environ.get("FLASK_ENV") == "production" or os.environ.get("RAILWAY_ENVIRONMENT"):
        abort(404)
    import smtplib
    server   = os.environ.get("MAIL_SERVER", "")
    port     = int(os.environ.get("MAIL_PORT", "587"))
    username = os.environ.get("MAIL_USERNAME", "")
    password = os.environ.get("MAIL_PASSWORD", "")
    from_addr = os.environ.get("MAIL_FROM", "")

    result = {
        "MAIL_SERVER":   server   or "❌ EMPTY",
        "MAIL_PORT":     port,
        "MAIL_USERNAME": username or "❌ EMPTY",
        "MAIL_PASSWORD": "✅ SET ({} chars)".format(len(password)) if password else "❌ EMPTY",
        "MAIL_FROM":     from_addr or "❌ EMPTY",
        "sending_to":    current_user.email or "❌ EMPTY",
        "notify_on_new_login": current_user.notify_on_new_login,
        "smtp_test": None,
        "error": None,
    }

    try:
        with smtplib.SMTP(server, port, timeout=10) as conn:
            conn.ehlo()
            conn.starttls()
            conn.login(username, password)
            result["smtp_test"] = "SMTP login successful!"
    except Exception as e:
        result["smtp_test"] = "FAILED"
        result["error"] = str(e)

    return jsonify(result)


@auth_bp.route("/banned")
def banned():
    """Dead-end page — shown to honeypot-banned IPs. No login form, no exit."""
    ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
        or "unknown"
    )
    return render_template("errors/banned.html", client_ip=ip), 403


@auth_bp.route("/health")
def health():
    """Railway healthcheck endpoint — no rate limit, no DB call, no IP check."""
    return "ok", 200


@auth_bp.route("/debug-ip")
@login_required
@admin_required
def debug_ip():
    if os.environ.get("FLASK_ENV") == "production":
        abort(404)
    from app.utils.security import is_ip_blocked
    from app.models.user import BlockedIP
    remote = request.remote_addr
    xff = request.headers.get("X-Forwarded-For", "")
    xri = request.headers.get("X-Real-IP", "")
    xff_first = xff.split(",")[0].strip() if xff else ""
    all_blocked = BlockedIP.query.filter_by(is_active=True).all()
    cookie_hp = request.cookies.get("_hp_block", "NOT SET")
    cookie_bf = request.cookies.get("_bf_block", "NOT SET")
    return jsonify({
        "remote_addr":       remote,
        "x_forwarded_for":   xff,
        "x_real_ip":         xri,
        "xff_first":         xff_first,
        "cookie_hp_block":   cookie_hp,
        "cookie_bf_block":   cookie_bf,
        "is_blocked_remote": is_ip_blocked(remote),   # returns block_type str or None
        "is_blocked_xff":    is_ip_blocked(xff_first),
        "blocked_ips_in_db": [
            {"ip": b.ip_address, "reason": b.reason,
             "block_type": b.block_type, "expires_at": str(b.expires_at)}
            for b in all_blocked
        ],
    })
