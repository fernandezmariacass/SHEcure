import os
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def build_login_fingerprint(ip: str, user_agent: str) -> str:
    """Return a SHA-256 hex digest of 'ip:user_agent'."""
    raw = f"{ip}:{user_agent}"
    return hashlib.sha256(raw.encode()).hexdigest()


def is_new_fingerprint(user, ip: str, user_agent: str) -> bool:
    """Return True if this login comes from a different IP/device than last time.
    Also returns True on the very first login (no stored fingerprint yet).
    Only fires if the user has notifications enabled.
    """
    if not getattr(user, "notify_on_new_login", True):
        return False
    current = build_login_fingerprint(ip, user_agent)
    stored = getattr(user, "last_login_fingerprint", None)
    # First-ever login — don't alert, just record
    if not stored:
        return False
    return current != stored


def send_new_login_alert(user, ip: str, user_agent: str,
                         timestamp: str = "") -> None:
    """Send a login-from-new-device email alert.
    Silently skips if mail env vars are not configured.
    """
    mail_server = os.environ.get("MAIL_SERVER", "")
    mail_port = int(os.environ.get("MAIL_PORT", 587))
    mail_username = os.environ.get("MAIL_USERNAME", "")
    mail_password = os.environ.get("MAIL_PASSWORD", "")
    mail_from = os.environ.get("MAIL_FROM", mail_username)

    # Skip gracefully if mail is not configured
    if not all([mail_server, mail_username, mail_password]):
        return

    recipient = getattr(user, "email", None)
    if not recipient:
        return

    subject = "SHEcure: New login detected on your account"
    body = f"""Hello {user.username},

We noticed a login to your SHEcure account from a new device or location.

  Time:       {timestamp or "just now"}
  IP address: {ip}
  Device:     {user_agent[:120]}

If this was you, no action is needed.

If you did NOT log in, please contact your administrator immediately and
consider changing your password.

— The SHEcure Security Team
"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = mail_from
    msg["To"] = recipient
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(mail_server, mail_port, timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(mail_username, mail_password)
            smtp.sendmail(mail_from, [recipient], msg.as_string())
    except Exception:
        # Never crash the login flow because of a mail failure
        pass
