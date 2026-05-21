"""
email_utils.py — Transactional email helpers for SHEcure.

Currently handles:
  • New-device / new-IP login alerts

SETUP (Railway Dashboard → Variables)
--------------------------------------
    MAIL_SERVER   = smtp.gmail.com        (or your SMTP host)
    MAIL_PORT     = 587
    MAIL_USERNAME = your@gmail.com
    MAIL_PASSWORD = <app password>
    MAIL_FROM     = SHEcure <your@gmail.com>

All sending is fire-and-forget in a background thread so it never blocks
the login response. Errors are logged but do not affect the login flow.
"""

import os
import hashlib
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# ── Fingerprint helpers ───────────────────────────────────────────────────────

def build_login_fingerprint(ip: str, user_agent: str) -> str:
    """Return a SHA-256 hex digest of 'ip:user_agent' for comparison."""
    raw = f"{ip}:{user_agent}"
    return hashlib.sha256(raw.encode()).hexdigest()


def is_new_fingerprint(user, ip: str, user_agent: str) -> bool:
    """True if this IP+UA combination has not been seen before for this user."""
    if not user.notify_on_new_login:
        return False
    current = build_login_fingerprint(ip, user_agent)
    return user.last_login_fingerprint != current


# ── Sending ───────────────────────────────────────────────────────────────────

def _send_email(to_address: str, subject: str, html_body: str) -> None:
    """Low-level SMTP send. Called in a background thread."""
    server = os.environ.get("MAIL_SERVER", "")
    port = int(os.environ.get("MAIL_PORT", "587"))
    username = os.environ.get("MAIL_USERNAME", "")
    password = os.environ.get("MAIL_PASSWORD", "")
    from_addr = os.environ.get("MAIL_FROM", username)

    if not all([server, username, password, to_address]):
        # Email not configured — silently skip rather than crash
        return

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_address
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(server, port, timeout=10) as conn:
            conn.ehlo()
            conn.starttls()
            conn.login(username, password)
            conn.sendmail(from_addr, to_address, msg.as_string())
    except Exception as exc:
        # Log but never propagate — email failure must not break login
        import logging
        logging.getLogger(__name__).warning("Email send failed: %s", exc)


def send_new_login_alert(user, ip: str, user_agent: str, timestamp: str) -> None:
    """
    Fire a background email alerting the user of a login from an unrecognised
    device or IP. Called after a successful login when is_new_fingerprint() is True.
    """
    subject = "SHEcure — New login detected on your account"
    html_body = f"""
    <div style="font-family:sans-serif;max-width:560px;margin:auto;color:#222">
      <h2 style="color:#e91e8c">New login to your SHEcure account</h2>
      <p>We noticed a sign-in from a device or location we haven't seen before.</p>
      <table style="border-collapse:collapse;width:100%;font-size:14px">
        <tr><td style="padding:6px 0;color:#666">Username</td><td style="padding:6px 0"><strong>{user.username}</strong></td></tr>
        <tr><td style="padding:6px 0;color:#666">IP address</td><td style="padding:6px 0">{ip}</td></tr>
        <tr><td style="padding:6px 0;color:#666">Device</td><td style="padding:6px 0">{user_agent[:120]}</td></tr>
        <tr><td style="padding:6px 0;color:#666">Time (PST)</td><td style="padding:6px 0">{timestamp}</td></tr>
      </table>
      <p style="margin-top:1.5rem">
        If this was you, no action is needed.<br>
        If you did not sign in, contact your administrator immediately and change your password.
      </p>
      <hr style="border:none;border-top:1px solid #eee;margin:1.5rem 0">
      <p style="font-size:12px;color:#999">This alert was sent by SHEcure. Do not reply to this email.</p>
    </div>
    """
    thread = threading.Thread(
        target=_send_email,
        args=(user.email, subject, html_body),
        daemon=True,
    )
    thread.start()
