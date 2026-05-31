"""
username_enc.py — Transparent Fernet encryption for usernames at rest.

HOW IT WORKS
------------
Usernames are sensitive PII. This module encrypts them before they are
stored in the database and decrypts them on read, so anyone who obtains
a raw DB dump sees only ciphertext instead of real usernames.

Because Fernet encryption is non-deterministic (each call produces a
different token), we also store a keyed HMAC-SHA256 digest of the
lowercased username in a separate `username_hash` column. This hash is
used for all DB lookup queries (WHERE username_hash = ?), while the
encrypted column stores the display/login value.

SETUP (Railway Dashboard → Variables → Add)
-------------------------------------------
    USERNAME_ENC_KEY = <run once:
        python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">

    USERNAME_HMAC_KEY = <run once:
        python -c "import secrets; print(secrets.token_hex(32))">

If either key is absent, a RuntimeError is raised at startup so the
misconfiguration is caught immediately rather than silently storing
plaintext usernames.
"""

import os
import hmac as _hmac
import hashlib
from cryptography.fernet import Fernet, InvalidToken


# ── key loaders (read at call-time so Railway env changes take effect) ─────────

def _get_fernet() -> Fernet:
    key = os.environ.get("USERNAME_ENC_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "USERNAME_ENC_KEY environment variable must be set. "
            "Generate with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode())


def _get_hmac_key() -> bytes:
    key = os.environ.get("USERNAME_HMAC_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "USERNAME_HMAC_KEY environment variable must be set. "
            "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return key.encode()


# ── public API ────────────────────────────────────────────────────────────────

def encrypt_username(username: str) -> str:
    """Encrypt a plaintext username for DB storage."""
    return _get_fernet().encrypt(username.encode("utf-8")).decode()


def decrypt_username(encrypted: str) -> str:
    """Decrypt a stored username. Raises InvalidToken if tampered/key mismatch."""
    return _get_fernet().decrypt(encrypted.encode()).decode("utf-8")


def hash_username(username: str) -> str:
    """Return a keyed HMAC-SHA256 hex digest of the lowercased username.

    This digest is stored in `username_hash` and used for all DB lookups.
    It is deterministic (same input → same output) so queries work, but
    it is keyed so it cannot be reversed without knowing USERNAME_HMAC_KEY.
    """
    return _hmac.new(
        _get_hmac_key(),
        username.lower().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
