"""
email_utils.py — Transactional email helpers for SHEcure.

Handles:
  • Failed login attempts (wrong password, invalid TOTP, honeypot trigger)
  • Account lockout (IP or username brute-forced)
  • Successful login from any device (always, not just new devices)
  • Account not yet approved attempts
  • reCAPTCHA / bot-blocked attempts
  • Suspicious camera frame pushes
  • Suspicious movement detected by the camera agent

Every admin-facing alert function also writes an UnauthorizedAlert row so the
event appears in the Security Alerts tab without any extra call-site changes.

SETUP (Railway Dashboard → Variables)
--------------------------------------
    BREVO_API_KEY  = xkeysib-xxxxxxxxxxxxxxxx   ← from brevo.com
    MAIL_FROM      = SHEcure <shecureemailservice@gmail.com>
    ALERT_EMAIL    = admin@example.com  ← optional, falls back to MAIL_FROM address

WHY BREVO:
  Railway blocks outbound SMTP on free/hobby plans (Errno 101).
  Brevo's HTTP API uses port 443 (always open) and allows sending
  from any email address without domain verification.
  Free tier: 300 emails/day, 9,000/month.

NOTE ON SENDER = RECIPIENT (shecureemailservice@gmail.com):
  Brevo rejects a message whose sender address also appears in the To list.
  _send_email automatically filters out the sender from the recipient list, so
  if all admin accounts share that address the email is silently skipped but
  the UnauthorizedAlert DB row is still written.
"""

import os
import json
import logging
import hashlib
import traceback
import urllib.request
import urllib.error

log = logging.getLogger(__name__)

# ── Shared style ──────────────────────────────────────────────────────────────

_BASE_STYLE = """
  font-family: sans-serif;
  max-width: 560px;
  margin: auto;
  color: #222;
"""

_TABLE_STYLE = "border-collapse:collapse;width:100%;font-size:14px"
_TD_LABEL = "padding:6px 0;color:#666;width:130px;vertical-align:top"
_TD_VALUE = "padding:6px 0;vertical-align:top"

def _row(label, value):
    return (
        f"<tr>"
        f"<td style='{_TD_LABEL}'>{label}</td>"
        f"<td style='{_TD_VALUE}'>{value}</td>"
        f"</tr>"
    )

def _wrap(heading, color, body_html):
    return f"""
    <div style="{_BASE_STYLE}">
      <h2 style="color:{color}">{heading}</h2>
      {body_html}
      <hr style="border:none;border-top:1px solid #eee;margin:1.5rem 0">
      <p style="font-size:12px;color:#999">
        This is an automated security alert from SHEcure. Do not reply.
      </p>
    </div>
    """


# ── User-Agent parser ─────────────────────────────────────────────────────────

def parse_device(user_agent: str) -> str:
    """
    Convert a raw User-Agent string into a human-readable device description.
    Returns e.g. "Chrome 148 on Windows 10 (Desktop)" or
                 "Safari on iPhone (iOS 17) — Mobile".
    Falls back to the raw UA (truncated) if nothing matches.
    """
    import re
    ua = user_agent or ""

    if re.search(r"bot|crawl|spider|slurp|facebookexternalhit|python-requests|curl|wget|httpclient",
                 ua, re.I):
        name = re.search(r"^[^\s/]+", ua)
        return f"Bot / Crawler ({name.group(0) if name else 'unknown'})"

    os_name = "Unknown OS"
    if re.search(r"Windows NT 10", ua):
        os_name = "Windows 10/11"
    elif re.search(r"Windows NT 6\.3", ua):
        os_name = "Windows 8.1"
    elif re.search(r"Windows NT 6\.1", ua):
        os_name = "Windows 7"
    elif re.search(r"Windows", ua, re.I):
        os_name = "Windows"
    elif re.search(r"iPhone", ua):
        m = re.search(r"CPU iPhone OS ([\d_]+)", ua)
        ver = m.group(1).replace("_", ".") if m else ""
        os_name = f"iOS {ver}" if ver else "iOS"
    elif re.search(r"iPad", ua):
        m = re.search(r"CPU OS ([\d_]+)", ua)
        ver = m.group(1).replace("_", ".") if m else ""
        os_name = f"iPadOS {ver}" if ver else "iPadOS"
    elif re.search(r"Android", ua):
        m = re.search(r"Android ([\d.]+)", ua)
        ver = m.group(1) if m else ""
        os_name = f"Android {ver}" if ver else "Android"
    elif re.search(r"Mac OS X", ua):
        m = re.search(r"Mac OS X ([\d_]+)", ua)
        ver = m.group(1).replace("_", ".") if m else ""
        os_name = f"macOS {ver}" if ver else "macOS"
    elif re.search(r"Linux", ua):
        os_name = "Linux"
    elif re.search(r"CrOS", ua):
        os_name = "Chrome OS"

    device_brand = ""
    if re.search(r"iPhone", ua):
        device_brand = "iPhone"
    elif re.search(r"iPad", ua):
        device_brand = "iPad"
    else:
        m = re.search(r";\s*([^;)]+?)\s+Build/", ua)
        if m:
            model = m.group(1).strip()
            brand_map = {
                "SM-": "Samsung", "Pixel": "Google", "Redmi": "Xiaomi",
                "Mi ": "Xiaomi", "POCO": "Xiaomi", "HUAWEI": "Huawei",
                "HW-": "Huawei", "HONOR": "Honor", "moto": "Motorola",
                "XT": "Motorola", "LM-": "LG", "LG-": "LG",
                "Nokia": "Nokia", "HTC": "HTC", "OnePlus": "OnePlus",
                "ONEPLUS": "OnePlus", "vivo": "Vivo", "OPPO": "OPPO",
                "CPH": "OPPO", "realme": "Realme", "RMX": "Realme",
                "Infinix": "Infinix", "Tecno": "Tecno", "itel": "itel",
            }
            for prefix, brand in brand_map.items():
                if model.upper().startswith(prefix.upper()) or model.lower().startswith(prefix.lower()):
                    device_brand = f"{brand} ({model})"
                    break
            if not device_brand and model:
                device_brand = model

    browser = "Unknown Browser"
    if re.search(r"Edg/|Edge/", ua):
        m = re.search(r"Edg(?:e)?/([\d.]+)", ua)
        browser = f"Microsoft Edge {m.group(1).split('.')[0]}" if m else "Microsoft Edge"
    elif re.search(r"OPR/|Opera/", ua):
        m = re.search(r"(?:OPR|Opera)/([\d.]+)", ua)
        browser = f"Opera {m.group(1).split('.')[0]}" if m else "Opera"
    elif re.search(r"SamsungBrowser/", ua):
        m = re.search(r"SamsungBrowser/([\d.]+)", ua)
        browser = f"Samsung Internet {m.group(1).split('.')[0]}" if m else "Samsung Internet"
    elif re.search(r"YaBrowser/", ua):
        browser = "Yandex Browser"
    elif re.search(r"UCBrowser/", ua):
        browser = "UC Browser"
    elif re.search(r"FBAV/|FBAN/", ua):
        browser = "Facebook In-App Browser"
    elif re.search(r"Instagram", ua):
        browser = "Instagram In-App Browser"
    elif re.search(r"Chrome/", ua) and not re.search(r"Chromium/", ua):
        m = re.search(r"Chrome/([\d.]+)", ua)
        browser = f"Chrome {m.group(1).split('.')[0]}" if m else "Chrome"
    elif re.search(r"Chromium/", ua):
        m = re.search(r"Chromium/([\d.]+)", ua)
        browser = f"Chromium {m.group(1).split('.')[0]}" if m else "Chromium"
    elif re.search(r"Firefox/", ua):
        m = re.search(r"Firefox/([\d.]+)", ua)
        browser = f"Firefox {m.group(1).split('.')[0]}" if m else "Firefox"
    elif re.search(r"Safari/", ua) and re.search(r"Version/", ua):
        m = re.search(r"Version/([\d.]+)", ua)
        browser = f"Safari {m.group(1).split('.')[0]}" if m else "Safari"
    elif re.search(r"Safari/", ua):
        browser = "Safari"

    if re.search(r"Mobi|Android|iPhone|iPad|tablet", ua, re.I):
        device_type = "Mobile" if not re.search(r"iPad|tablet", ua, re.I) else "Tablet"
    else:
        device_type = "Desktop"

    parts = [browser, "on"]
    if device_brand:
        parts.append(device_brand)
    parts.append(f"({os_name})")
    parts.append(f"— {device_type}")
    return " ".join(parts)


# ── Fingerprint helpers ───────────────────────────────────────────────────────

def build_login_fingerprint(ip: str, user_agent: str) -> str:
    """Return a SHA-256 hex digest of 'ip:user_agent' for comparison."""
    raw = f"{ip}:{user_agent}"
    return hashlib.sha256(raw.encode()).hexdigest()


def is_new_fingerprint(user, ip: str, user_agent: str) -> bool:
    """True if this IP+UA combination has not been seen before for this user."""
    current = build_login_fingerprint(ip, user_agent)
    return user.last_login_fingerprint != current


# ── UnauthorizedAlert logger ──────────────────────────────────────────────────

def _log_alert(
    alert_type: str,
    ip: str,
    user_agent: str = "",
    endpoint: str = "",
    method: str = "POST",
    threat_score: int = 50,
    threat_reason: str = "",
    notes: str = "",
    username_attempted: str = "",
) -> None:
    """Write an UnauthorizedAlert row to the database.

    Called internally by every admin-facing alert function so that each
    security event appears in the Security Alerts tab automatically.
    Errors are swallowed so a DB hiccup never blocks the email path.
    """
    try:
        from app import db
        from app.models.logs import UnauthorizedAlert
        alert = UnauthorizedAlert(
            alert_type=alert_type,
            ip_address=ip or "unknown",
            user_agent=(user_agent or "")[:512],
            endpoint=endpoint or "",
            method=method,
            threat_score=threat_score,
            threat_reason=threat_reason or "",
            notes=notes or "",
            username_attempted=username_attempted or "",
            resolved=False,
        )
        db.session.add(alert)
        db.session.commit()
    except Exception as exc:
        log.warning("_log_alert DB write failed (%s): %s", alert_type, exc)
        try:
            from app import db as _db
            _db.session.rollback()
        except Exception:
            pass


# ── Low-level send via Brevo HTTP API ─────────────────────────────────────────

def _parse_from_addr(mail_from: str):
    """Parse 'Name <email>' or plain 'email' into (name, email) tuple."""
    if "<" in mail_from and ">" in mail_from:
        name  = mail_from.split("<")[0].strip()
        email = mail_from.split("<")[1].rstrip(">").strip()
        return name, email
    return "SHEcure", mail_from.strip()


def _send_email(to_address, subject: str, html_body: str) -> None:
    """Send email via Brevo (formerly Sendinblue) HTTP API.

    ``to_address`` may be a single address string or a list of address strings.
    Duplicates (case-insensitive) are collapsed before sending.
    Brevo rejects messages where sender == recipient, so the MAIL_FROM address
    is automatically filtered out from the To list.
    """
    api_key   = os.environ.get("BREVO_API_KEY", "")
    mail_from = os.environ.get("MAIL_FROM", "SHEcure <shecureemailservice@gmail.com>")

    if not api_key:
        log.warning("Email NOT sent — BREVO_API_KEY is not set. Subject: %s", subject)
        return

    # Normalise to a deduplicated list
    if isinstance(to_address, str):
        recipients = [to_address] if to_address else []
    else:
        recipients = list(to_address)

    seen: set = set()
    unique_recipients = []
    for addr in recipients:
        if addr and addr.lower() not in seen:
            seen.add(addr.lower())
            unique_recipients.append(addr)

    if not unique_recipients:
        log.warning("Email NOT sent — no recipient address. Subject: %s", subject)
        return

    sender_name, sender_email = _parse_from_addr(mail_from)

    # Brevo forbids sender appearing in To
    to_list = [
        {"email": addr} for addr in unique_recipients
        if addr.lower() != sender_email.lower()
    ]

    if not to_list:
        log.warning(
            "Email NOT sent — all recipients match the Brevo sender (%s). "
            "The alert was still logged in the database. Subject: %s",
            sender_email, subject,
        )
        return

    payload = json.dumps({
        "sender":      {"name": sender_name, "email": sender_email},
        "to":          to_list,
        "subject":     subject,
        "htmlContent": html_body,
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=payload,
        headers={
            "api-key":      api_key,
            "Content-Type": "application/json",
            "Accept":       "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            log.info(
                "Email sent via Brevo → %s | %s",
                ", ".join(r["email"] for r in to_list),
                subject,
            )

    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if exc.code == 401:
            log.error("Brevo auth failed — check BREVO_API_KEY: %s", body)
        elif exc.code == 400:
            log.error("Brevo rejected request (bad sender/recipient?): %s", body)
        else:
            log.error("Brevo API error %s: %s", exc.code, body)

    except urllib.error.URLError as exc:
        log.error("Brevo network error: %s\n%s", exc, traceback.format_exc())

    except Exception as exc:
        log.error("Email send failed (unexpected): %s\n%s", exc, traceback.format_exc())


def _send_async(to_address, subject: str, html_body: str) -> None:
    """Send email asynchronously (gevent if available, otherwise threading).

    ``to_address`` may be a single address string or a list of address strings.
    """
    try:
        import gevent
        gevent.spawn(_send_email, to_address, subject, html_body)
    except ImportError:
        import threading
        threading.Thread(
            target=_send_email,
            args=(to_address, subject, html_body),
            daemon=True,
        ).start()


# ── Admin recipient resolution ────────────────────────────────────────────────

def _alert_emails() -> list:
    """Return all admin email addresses for security alerts.

    Priority:
      1. DB query — every User with role='admin' that has an email.
      2. ALERT_EMAIL env-var (comma-separated list supported).
      3. MAIL_FROM sender address as last resort.

    Always returns a list (possibly empty).
    """
    try:
        from app.models.user import User
        admins = User.query.filter_by(role="admin").all()
        emails = [u.email for u in admins if u.email]
        if emails:
            return emails
    except Exception as exc:
        log.warning("Could not query admin emails from DB: %s", exc)

    alert_env = os.environ.get("ALERT_EMAIL", "")
    if alert_env:
        parsed = [e.strip() for e in alert_env.split(",") if e.strip()]
        if parsed:
            return parsed

    mail_from = os.environ.get("MAIL_FROM", "")
    _, sender_email = _parse_from_addr(mail_from)
    return [sender_email] if sender_email else []


def _alert_email() -> str:
    """Backward-compat shim — returns the first alert email as a string."""
    emails = _alert_emails()
    return emails[0] if emails else ""


# ── Public helpers ────────────────────────────────────────────────────────────

def send_failed_login_alert(username_attempted: str, ip: str, user_agent: str,
                             timestamp: str, reason: str, user=None) -> None:
    to = user.email if user else _alert_emails()
    if not to:
        return
    subject = "SHEcure — Failed login attempt on your account"
    table = f"""
    <table style='{_TABLE_STYLE}'>
      {_row("Username", f"<strong>{username_attempted}</strong>")}
      {_row("IP address", ip)}
      {_row("Device", f"{parse_device(user_agent)}<br><span style='font-size:11px;color:#999'>UA: {user_agent[:120]}</span>")}
      {_row("Time (PST)", timestamp)}
      {_row("Reason", reason)}
    </table>
    <p>If this was you, no action is needed.<br>
       If you did not attempt to log in, consider changing your password immediately.</p>
    """
    html = _wrap("⚠️ Failed login attempt", "#e65100", table)
    _send_async(to, subject, html)


def send_lockout_alert(username_attempted: str, ip: str, user_agent: str,
                        timestamp: str, lockout_type: str, user=None) -> None:
    to = user.email if user else _alert_emails()
    if not to:
        return
    subject = "SHEcure — Account locked out due to repeated failures"
    table = f"""
    <table style='{_TABLE_STYLE}'>
      {_row("Username", f"<strong>{username_attempted}</strong>")}
      {_row("IP address", ip)}
      {_row("Device", f"{parse_device(user_agent)}<br><span style='font-size:11px;color:#999'>UA: {user_agent[:120]}</span>")}
      {_row("Time (PST)", timestamp)}
      {_row("Lockout type", lockout_type)}
    </table>
    <p>Too many consecutive failed login attempts triggered an automatic lockout.<br>
       If this was not you, contact your administrator immediately.</p>
    """
    html = _wrap("🔒 Account Locked Out", "#b71c1c", table)
    _send_async(to, subject, html)


def send_successful_login_alert(user, ip: str, user_agent: str,
                                 timestamp: str, is_new_device: bool) -> None:
    if not user.email:
        return
    if not getattr(user, "notify_on_new_login", True):
        return
    device_note = (
        "<strong style='color:#b71c1c'>⚠️ This is a new device or location we haven't seen before.</strong><br>"
        if is_new_device else
        "This login came from a recognised device."
    )
    subject = (
        "SHEcure — New device login detected" if is_new_device
        else "SHEcure — Successful login to your account"
    )
    table = f"""
    <table style='{_TABLE_STYLE}'>
      {_row("Username", f"<strong>{user.username}</strong>")}
      {_row("IP address", ip)}
      {_row("Device", f"{parse_device(user_agent)}<br><span style='font-size:11px;color:#999'>UA: {user_agent[:120]}</span>")}
      {_row("Time (PST)", timestamp)}
    </table>
    <p>{device_note}<br>
       If you did not sign in, contact your administrator immediately and change your password.</p>
    """
    color   = "#b71c1c" if is_new_device else "#1b5e20"
    heading = "🔐 New Device Login" if is_new_device else "✅ Successful Login"
    html = _wrap(heading, color, html_body=table)
    _send_async(user.email, subject, html)


def send_bot_blocked_alert(username_attempted: str, ip: str, user_agent: str,
                            timestamp: str) -> None:
    to = _alert_emails()
    if not to:
        return
    subject = "SHEcure — Bot/automated login attempt blocked"
    table = f"""
    <table style='{_TABLE_STYLE}'>
      {_row("Username attempted", username_attempted or "(none)")}
      {_row("IP address", ip)}
      {_row("Device", f"{parse_device(user_agent)}<br><span style='font-size:11px;color:#999'>UA: {user_agent[:120]}</span>")}
      {_row("Time (PST)", timestamp)}
    </table>
    <p>A login attempt was blocked because it failed reCAPTCHA verification.<br>
       No credentials were checked — this was likely an automated attack.</p>
    """
    html = _wrap("🤖 Bot Login Blocked", "#4a148c", table)
    _send_async(to, subject, html)
    _log_alert(
        alert_type="invalid_credentials",
        ip=ip,
        user_agent=user_agent,
        endpoint="/login",
        method="POST",
        threat_score=60,
        threat_reason="Bot/automated login attempt blocked by reCAPTCHA",
        notes=f"Username attempted: {username_attempted or '(none)'}",
        username_attempted=username_attempted,
    )


def send_honeypot_alert(username_attempted: str, ip: str, user_agent: str,
                         timestamp: str) -> None:
    to = _alert_emails()
    if not to:
        return
    subject = "SHEcure 🍯 HONEYPOT TRIGGERED — Possible credential-stuffing attack"
    table = f"""
    <table style='{_TABLE_STYLE}'>
      {_row("Username attempted", f"<strong>{username_attempted}</strong>")}
      {_row("IP address", f"<strong style='color:#b71c1c'>{ip}</strong>")}
      {_row("Device", f"{parse_device(user_agent)}<br><span style='font-size:11px;color:#999'>UA: {user_agent[:120]}</span>")}
      {_row("Time (PST)", timestamp)}
    </table>
    <p><strong>The honeypot canary password was used.</strong> This strongly indicates
       a credential-stuffing or insider attack. Investigate this IP immediately.</p>
    """
    html = _wrap("🍯 Honeypot Triggered", "#b71c1c", table)
    _send_async(to, subject, html)
    # Note: honeypot.py already writes its own UnauthorizedAlert row with full
    # detail; we skip a duplicate here to avoid double entries.


def send_2fa_reset_email(user, admin_username: str, timestamp: str,
                         confirm_url: str) -> None:
    """Email the user a confirmation link to approve their own 2FA reset."""
    if not user.email:
        return
    subject = "SHEcure — Action required: confirm your 2FA reset"
    body = f"""
    <table style='{_TABLE_STYLE}'>
      {_row("Account", f"<strong>{user.username}</strong>")}
      {_row("Requested by", admin_username)}
      {_row("Time (PST)", timestamp)}
    </table>
    <p>An administrator has requested a reset of your two-factor authentication (2FA).<br>
       To confirm and set up a new authenticator, click the button below.</p>
    <div style="text-align:center;margin:1.5rem 0">
      <a href="{confirm_url}"
         style="display:inline-block;background:#e91e8c;color:#fff;text-decoration:none;
                padding:.75rem 2rem;border-radius:8px;font-weight:600;font-size:1rem">
        ✓ Confirm &amp; Set Up New 2FA
      </a>
    </div>
    <p style="font-size:.82rem;color:#999">
      This link expires in <strong>24 hours</strong>. If you did not expect this,
      ignore this email and contact your administrator immediately.
    </p>
    """
    html = _wrap("🔐 Confirm Your 2FA Reset", "#e91e8c", body)
    _send_async(user.email, subject, html)


def send_ip_blocked_alert(ip: str, user_agent: str, timestamp: str,
                          username_attempted: str = "", block_duration_minutes: int = 30) -> None:
    """Email all admins when an IP is automatically blocked after repeated failed logins."""
    to = _alert_emails()
    if not to:
        return
    subject = f"SHEcure — IP Blocked: {ip}"
    duration_str = f"{block_duration_minutes} minutes"
    device_str = (
        f"{parse_device(user_agent)}<br><span style='font-size:11px;color:#999'>UA: {user_agent[:120]}</span>"
        if user_agent else "Unknown"
    )
    user_str = username_attempted if username_attempted else "Unknown"
    table = f"""
    <table style='{_TABLE_STYLE}'>
      {_row("Blocked IP", f"<strong style='color:#b71c1c'>{ip}</strong>")}
      {_row("Blocked At", timestamp)}
      {_row("Block Duration", duration_str)}
      {_row("Username Attempted", user_str)}
      {_row("Device / User Agent", device_str)}
    </table>
    <p>An IP was automatically blocked after <strong>5</strong> consecutive failed login attempts.<br>
       No secrets, tokens, or credentials are included in this notification.</p>
    """
    html = _wrap("⚠️ IP Address Blocked", "#b71c1c", table)
    _send_async(to, subject, html)
    _log_alert(
        alert_type="invalid_credentials",
        ip=ip,
        user_agent=user_agent,
        endpoint="/login",
        method="POST",
        threat_score=80,
        threat_reason=f"IP auto-blocked after repeated failed logins (duration: {duration_str})",
        notes=f"Username attempted: {user_str}",
        username_attempted=username_attempted,
    )


def send_unapproved_login_attempt(username_attempted: str, ip: str, user_agent: str,
                                   timestamp: str) -> None:
    to = _alert_emails()
    if not to:
        return
    subject = "SHEcure — Unapproved account login attempt"
    table = f"""
    <table style='{_TABLE_STYLE}'>
      {_row("Username", f"<strong>{username_attempted}</strong>")}
      {_row("IP address", ip)}
      {_row("Device", f"{parse_device(user_agent)}<br><span style='font-size:11px;color:#999'>UA: {user_agent[:120]}</span>")}
      {_row("Time (PST)", timestamp)}
    </table>
    <p>A user whose account is pending approval attempted to log in.<br>
       You may want to approve or reject this account in the admin panel.</p>
    """
    html = _wrap("👤 Unapproved Account Login Attempt", "#e65100", table)
    _send_async(to, subject, html)
    _log_alert(
        alert_type="invalid_credentials",
        ip=ip,
        user_agent=user_agent,
        endpoint="/login",
        method="POST",
        threat_score=30,
        threat_reason="Login attempted on an account pending admin approval",
        notes=f"Username: {username_attempted}",
        username_attempted=username_attempted,
    )


def send_suspicious_push_alert(ip: str, user_agent: str, timestamp: str,
                                reason: str = "", frame_size_kb: float = 0) -> None:
    """Email all admins when a suspicious frame push is detected on the camera ingest."""
    to = _alert_emails()
    if not to:
        return
    subject = "SHEcure 📷 SUSPICIOUS FRAME PUSH — Camera ingest anomaly detected"
    size_str = f"{frame_size_kb:.1f} KB" if frame_size_kb else "Unknown"
    table = f"""
    <table style='{_TABLE_STYLE}'>
      {_row("Source IP", f"<strong style='color:#b71c1c'>{ip}</strong>")}
      {_row("Device / UA", f"{parse_device(user_agent)}<br><span style='font-size:11px;color:#999'>UA: {user_agent[:120]}</span>")}
      {_row("Time (PST)", timestamp)}
      {_row("Frame size", size_str)}
      {_row("Reason", reason or "Anomalous frame ingest detected")}
    </table>
    <p><strong>An unusual frame was pushed to the camera feed.</strong><br>
       This may indicate a replay attack, an unauthorised broadcaster, or a
       payload injection attempt. Review the ingest logs immediately.</p>
    """
    html = _wrap("📷 Suspicious Frame Push", "#b71c1c", table)
    _send_async(to, subject, html)
    _log_alert(
        alert_type="suspicious_push",
        ip=ip,
        user_agent=user_agent,
        endpoint="/camera/ingest",
        method="POST",
        threat_score=85,
        threat_reason=reason or "Anomalous frame ingest detected",
        notes=f"Frame size: {size_str}",
    )


def send_suspicious_movement_alert(camera_label: str, timestamp: str,
                                    snapshot_b64: str = "",
                                    confidence: float = 0.0) -> None:
    """Email all admins when suspicious movement is detected by the camera."""
    to = _alert_emails()
    if not to:
        return
    subject = "SHEcure 🚨 SUSPICIOUS MOVEMENT DETECTED"
    confidence_str = f"{confidence:.0%}" if confidence else "N/A"
    snapshot_html = (
        f"<br><img src='data:image/jpeg;base64,{snapshot_b64}' "
        f"style='max-width:480px;border:2px solid #b71c1c;border-radius:4px;margin-top:8px' "
        f"alt='Motion snapshot'>"
        if snapshot_b64 else ""
    )
    table = f"""
    <table style='{_TABLE_STYLE}'>
      {_row("Camera", f"<strong>{camera_label}</strong>")}
      {_row("Time (PST)", timestamp)}
      {_row("Confidence", confidence_str)}
    </table>
    <p><strong>Unusual movement was detected on the camera feed.</strong><br>
       Please review the live stream or recent recordings immediately.{snapshot_html}</p>
    """
    html = _wrap("🚨 Suspicious Movement Detected", "#b71c1c", table)
    _send_async(to, subject, html)
    _log_alert(
        alert_type="suspicious_movement",
        ip="camera-agent",
        user_agent="",
        endpoint="/camera/motion-alert",
        method="POST",
        threat_score=75,
        threat_reason=f"Suspicious movement on {camera_label} (confidence: {confidence_str})",
        notes=f"Camera: {camera_label} | Confidence: {confidence_str}",
    )
