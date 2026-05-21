"""
keyderive.py — Server-side password-to-key transformation.

HOW IT WORKS
------------
When a user types their password, that raw string is NEVER stored or compared
directly. Instead it goes through this pipeline:

    raw password
        ↓
    PBKDF2-HMAC-SHA256  (100,000 rounds + secret server pepper)
        ↓
    derived access key  (32 bytes, looks like random noise)
        ↓
    bcrypt/werkzeug hash  (stored in DB)

A hacker who gets the DB sees only the final bcrypt hash.
Even if they somehow cracked that, they'd get the derived key — not the
original password, and not useful without also knowing the secret pepper.
The pepper lives ONLY in the Railway environment variable KEY_PEPPER.

WHY THIS IS SAFE FROM PAGE SOURCE INSPECTION
--------------------------------------------
This file is pure Python running on the server. It is never sent to the
browser. Right-clicking and viewing page source shows only HTML/CSS/JS —
none of this logic is visible there.

SETUP (Railway Dashboard → Variables → Add)
-------------------------------------------
    KEY_PEPPER = <long random string, e.g. output of: python -c "import secrets; print(secrets.token_hex(32))">

If KEY_PEPPER is not set, the system falls back to a warning and uses a
default — but you MUST set it in production for real security.
"""

import os
import hashlib
import warnings

# ── pepper ────────────────────────────────────────────────────────────────────
# Read at call time (not import time) so Railway env var changes take effect
# without a redeploy.
def _get_pepper() -> bytes:
    pepper = os.environ.get("KEY_PEPPER", "").strip()
    if not pepper:
        warnings.warn(
            "KEY_PEPPER env var is not set. Password key derivation is weakened. "
            "Set KEY_PEPPER in your Railway environment variables immediately.",
            RuntimeWarning,
            stacklevel=3,
        )
        # Fallback so the app still runs, but this should never be used in prod
        pepper = "shecure-default-pepper-change-me"
    return pepper.encode()


# ── derivation ────────────────────────────────────────────────────────────────
_ITERATIONS = 100_000   # PBKDF2 rounds — high enough to slow brute force
_KEY_LENGTH  = 32       # bytes → 64 hex chars


def derive_access_key(password: str, username: str) -> str:
    """Transform a raw password into a derived access key.

    The username is used as a per-user salt mixed with the server pepper,
    so two users with the same password produce completely different keys.

    Returns a hex string that looks like random noise — this is what gets
    passed to werkzeug's generate_password_hash / check_password_hash.
    """
    pepper = _get_pepper()

    # Salt = pepper + username  (username is unique per user in the DB)
    salt = pepper + username.lower().encode()

    derived = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt,
        iterations=_ITERATIONS,
        dklen=_KEY_LENGTH,
    )
    return derived.hex()
