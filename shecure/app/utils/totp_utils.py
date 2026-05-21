import os
import pyotp
import qrcode
import base64
from io import BytesIO
from cryptography.fernet import Fernet


def _get_fernet():
    """Return a Fernet instance using TOTP_ENC_KEY from environment."""
    key = os.environ.get("TOTP_ENC_KEY", "")
    if not key:
        raise RuntimeError("TOTP_ENC_KEY environment variable must be set.")
    return Fernet(key.encode() if isinstance(key, str) else key)


def generate_totp_secret() -> str:
    """Generate a new random base32 TOTP secret."""
    return pyotp.random_base32()


def encrypt_secret(raw_secret: str) -> str:
    """Encrypt a plain TOTP secret for storage."""
    f = _get_fernet()
    return f.encrypt(raw_secret.encode()).decode()


def decrypt_secret(enc_secret: str) -> str:
    """Decrypt a stored TOTP secret."""
    f = _get_fernet()
    return f.decrypt(enc_secret.encode()).decode()


def verify_totp(enc_secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code against an encrypted secret.
    Accepts the current window ±1 (30 s grace) to handle clock skew.
    """
    if not enc_secret or not code:
        return False
    try:
        raw_secret = decrypt_secret(enc_secret)
        totp = pyotp.TOTP(raw_secret)
        return totp.verify(code, valid_window=1)
    except Exception:
        return False


def get_qr_data_uri(raw_secret: str, username: str,
                    issuer: str = "SHEcure") -> str:
    """Return a base64 PNG data URI of the QR code for the given secret."""
    uri = pyotp.TOTP(raw_secret).provisioning_uri(
        name=username, issuer_name=issuer
    )
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"
