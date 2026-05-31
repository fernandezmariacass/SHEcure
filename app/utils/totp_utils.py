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
    qrcode[pil]==7.4.2
"""

import os
import io
import base64
import pyotp
from cryptography.fernet import Fernet, InvalidToken


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


# ── TOTP lifecycle ────────────────────────────────────────────────────────────

def generate_totp_secret() -> str:
    """Generate a fresh random base32 TOTP secret (plaintext)."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = "SHEcure") -> str:
    """Return the otpauth:// URI for QR code generation."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def get_qr_data_uri(secret: str, username: str) -> str:
    """Return a base64 PNG data URI of the QR code for inline HTML embedding."""
    import qrcode
    uri = get_totp_uri(secret, username)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"


def verify_totp(encrypted_secret: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a 6-digit TOTP code against an encrypted stored secret.

    valid_window=1 allows one 30-second step on either side of the current
    time to account for clock drift — standard practice.
    Returns False (rather than raising) if the secret can't be decrypted,
    so a corrupted DB entry doesn't crash the login flow.
    """
    try:
        secret = decrypt_secret(encrypted_secret)
    except (InvalidToken, Exception):
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=valid_window)
