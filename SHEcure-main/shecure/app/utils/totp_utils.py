"""
totp_utils.py — TOTP (Time-based One-Time Password) helpers for 2FA.

HOW IT WORKS
------------
1. On enrollment, generate a random base32 secret with pyotp.
2. Encrypt it with AES (via Fernet) using TOTP_ENC_KEY from env before storing.
3. Present a QR code URI so the user can scan it into an authenticator app
   (Google Authenticator, Authy, etc.).
4. At login, after password verification, call verify_totp() with the 6-digit code.

SETUP (Railway Dashboard → Variables)
--------------------------------------
    TOTP_ENC_KEY = <run once: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">

DEPENDENCIES (add to requirements.txt)
----------------------------------------
    pyotp==2.9.0
    cryptography==42.0.8
    qrcode==7.4.2
    Pillow==10.4.0
"""

import os
import io
import time
import base64
import logging
import pyotp
from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger(__name__)


# ── Encryption helpers ────────────────────────────────────────────────────────

def _get_fernet() -> Fernet:
    key = os.environ.get("TOTP_ENC_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "TOTP_ENC_KEY environment variable must be set. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode())


def encrypt_secret(secret: str) -> str:
    """Encrypt a plaintext TOTP secret for DB storage."""
    return _get_fernet().encrypt(secret.encode()).decode()


def decrypt_secret(encrypted: str) -> str:
    """Decrypt a stored TOTP secret. Raises InvalidToken if tampered."""
    return _get_fernet().decrypt(encrypted.encode()).decode()


# ── Replay-attack protection (DB-backed, multi-worker safe) ──────────────────
# CHANGED: replaced the in-memory dict with database reads/writes so that
# used codes are shared across all Gunicorn workers.

_REPLAY_WINDOW_SECONDS = 90  # 1 TOTP step (30s) + 1 grace step each side


def _prune_totp_cache() -> None:
    """Delete DB rows older than the replay window to keep the table small."""
    # NEW: DB-based pruning instead of dict pruning
    try:
        from app import db
        from app.models.logs import UsedTotpCode, now_pst
        from datetime import timedelta
        cutoff = now_pst() - timedelta(seconds=_REPLAY_WINDOW_SECONDS)
        UsedTotpCode.query.filter(UsedTotpCode.used_at < cutoff).delete()
        db.session.commit()
    except Exception as exc:
        log.warning("[totp] prune failed (non-fatal): %s", exc)
        try:
            from app import db
            db.session.rollback()
        except Exception:
            pass


def _is_code_used(lookup_key: str) -> bool:
    """Return True if this user+code combo was used within the replay window."""
    # NEW: DB lookup instead of dict lookup
    try:
        from app.models.logs import UsedTotpCode, now_pst
        from datetime import timedelta
        cutoff = now_pst() - timedelta(seconds=_REPLAY_WINDOW_SECONDS)
        return UsedTotpCode.query.filter(
            UsedTotpCode.lookup_key == lookup_key,
            UsedTotpCode.used_at >= cutoff,
        ).first() is not None
    except Exception as exc:
        # If the DB is unreachable, fail OPEN (allow) rather than locking
        # every user out — but log it loudly.
        log.error("[totp] replay-check DB error (failing open): %s", exc)
        return False


def _mark_code_used(lookup_key: str) -> None:
    """Record that this user+code combo was just used successfully."""
    # NEW: DB insert instead of dict write
    try:
        from app import db
        from app.models.logs import UsedTotpCode
        # Use merge-style: if a duplicate key somehow exists, update used_at
        existing = UsedTotpCode.query.filter_by(lookup_key=lookup_key).first()
        if existing:
            from app.models.logs import now_pst
            existing.used_at = now_pst()
        else:
            db.session.add(UsedTotpCode(lookup_key=lookup_key))
        db.session.commit()
    except Exception as exc:
        log.error("[totp] failed to record used code in DB: %s", exc)
        try:
            from app import db
            db.session.rollback()
        except Exception:
            pass


# ── TOTP lifecycle ────────────────────────────────────────────────────────────

def generate_totp_secret() -> str:
    """Generate a fresh random base32 TOTP secret (plaintext)."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = "SHEcure") -> str:
    """Return the otpauth:// URI for QR code generation."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def get_qr_data_uri(secret: str, username: str) -> str:
    """
    Return a base64 PNG data URI of the QR code for inline HTML embedding.
    Uses segno as primary generator (more reliable on Railway than qrcode+Pillow),
    falls back to qrcode if segno is not installed.
    """
    uri = get_totp_uri(secret, username)

    # ── Try segno first (pure Python, no Pillow dependency) ──────────────────
    try:
        import segno
        buf = io.BytesIO()
        qr = segno.make(uri, error="M")
        qr.save(buf, kind="png", scale=6)
        b64 = base64.b64encode(buf.getvalue()).decode()
        return f"data:image/png;base64,{b64}"
    except ImportError:
        pass

    # ── Fallback: qrcode + Pillow ─────────────────────────────────────────────
    try:
        import qrcode
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b64 = base64.b64encode(buf.getvalue()).decode()
        return f"data:image/png;base64,{b64}"
    except Exception as exc:
        raise RuntimeError(
            f"QR code generation failed. "
            f"Make sure 'segno' or 'qrcode[pil]+Pillow' is in requirements.txt. Error: {exc}"
        )


def verify_totp(user_id: str, encrypted_secret: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a 6-digit TOTP code against an encrypted stored secret.

    Includes replay-attack protection via the database: each code is recorded
    for 90 seconds and rejected if presented again — even on a different worker.

    user_id must be a stable identifier (DB primary key as a string).
    """
    # CHANGED: _prune_totp_cache and replay check now use DB, not in-memory dict
    _prune_totp_cache()

    lookup_key = f"{user_id}:{code}"

    if _is_code_used(lookup_key):
        log.warning("[totp] replay attempt blocked for user_id=%s", user_id)
        return False

    try:
        secret = decrypt_secret(encrypted_secret)
    except (InvalidToken, Exception):
        return False

    totp = pyotp.TOTP(secret)
    if totp.verify(code, valid_window=valid_window):
        _mark_code_used(lookup_key)   # CHANGED: DB write instead of dict write
        return True
    return False
