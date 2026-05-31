"""
honeypot.py — Canary password detection.

How it works:
- You set a HONEYPOT_PASSWORD environment variable on Railway (never in code).
- When someone submits that exact password at login, it silently fires a
  maximum-severity UnauthorizedAlert. The attacker sees a normal "invalid
  credentials" response — no indication they tripped a wire.
- Nothing about the honeypot is stored in the DB, rendered in HTML,
  or sent to the browser. The check is pure server-side Python.

Setup (Railway dashboard → Variables):
    HONEYPOT_PASSWORD=<choose something a hacker might guess, e.g. "Admin@1234">
"""

import os
import hmac
import hashlib


def _get_honeypot_hash():
    """Read and hash the honeypot password from the env var at call time.

    Reading at call time (not import time) means Railway env var changes
    take effect immediately on next request without needing a redeploy.
    Returns None if the env var is not set, which disables the feature.
    """
    raw = os.environ.get("HONEYPOT_PASSWORD", "").strip()
    if not raw:
        return None
    return hashlib.sha256(raw.encode()).digest()


def is_honeypot_password(password: str) -> bool:
    """Return True if the submitted password matches the honeypot canary.

    Uses hmac.compare_digest to prevent timing-based side-channel leaks.
    """
    honeypot_hash = _get_honeypot_hash()
    if honeypot_hash is None:
        return False
    submitted = hashlib.sha256(password.encode()).digest()
    return hmac.compare_digest(submitted, honeypot_hash)


def fire_honeypot_alert(username_attempted: str, ip: str, user_agent: str) -> None:
    """Log a maximum-severity alert for a honeypot password submission."""
    from app import db
    from app.models.logs import UnauthorizedAlert, AccessLog
    from app.models.logs import now_pst

    reason = (
        f"CANARY PASSWORD ENTERED — username attempted: '{username_attempted}'. "
        "A likely attacker tested a known/guessed credential. "
        "Immediate investigation recommended."
    )

    alert = UnauthorizedAlert(
        ip_address=ip,
        user_agent=(user_agent or "")[:512],
        endpoint="/login",
        method="POST",
        threat_score=100,
        threat_reason=reason[:300],
        notes=(
            f"Honeypot canary triggered at {now_pst()}. "
            f"Username attempted: '{username_attempted}'. "
            "The attacker was shown a normal 'invalid credentials' response."
        ),
        resolved=False,
    )
    db.session.add(alert)

    # Also write a blocked AccessLog entry so it shows in the access log view
    log_entry = AccessLog(
        username_attempted=username_attempted,
        ip_address=ip,
        user_agent=(user_agent or "")[:512],
        status="blocked",
        reason="Honeypot canary password submitted",
        is_unauthorized=True,
    )
    db.session.add(log_entry)

    db.session.commit()
