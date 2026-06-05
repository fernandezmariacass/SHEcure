"""
geo_utils.py — IP geolocation helper for SHEcure
==================================================
Resolves an IP address to a human-readable location string
(e.g. "Quezon City, Metro Manila, PH") using the free ip-api.com service.

• No API key required.
• Private / reserved IPs are short-circuited and returned as "Local / Private".
• All network errors are caught so a geo failure never breaks a login.
• Results are cached in-process (LRU, 512 entries) to avoid hitting the
  external API on every request from the same IP.
"""

import ipaddress
import logging
from functools import lru_cache

import requests

log = logging.getLogger(__name__)

# ip-api.com free tier: 45 requests/min per IP, no key needed.
# fields=city,regionName,countryCode keeps the response tiny.
_GEO_URL = "http://ip-api.com/json/{ip}?fields=status,city,regionName,countryCode"
_TIMEOUT = 2  # seconds — must be short so it never slows down login


def _is_private(ip: str) -> bool:
    """Return True if *ip* is a loopback, private, or link-local address."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified
    except ValueError:
        return False


@lru_cache(maxsize=512)
def _fetch_location(ip: str) -> str:
    """
    Internal cached lookup.  Only called for public IPs.
    Returns a formatted location string or a fallback on any error.
    """
    try:
        resp = requests.get(_GEO_URL.format(ip=ip), timeout=_TIMEOUT)
        data = resp.json()
        if data.get("status") == "success":
            city    = data.get("city", "")
            region  = data.get("regionName", "")
            country = data.get("countryCode", "")
            parts = [p for p in [city, region, country] if p]
            return ", ".join(parts) if parts else "Unknown"
        return "Unknown"
    except Exception as exc:
        log.debug("geo_utils: lookup failed for %s — %s", ip, exc)
        return "Unknown"


def get_location(ip: str) -> str:
    """
    Return a location string for *ip*.

    Examples
    --------
    "Quezon City, Metro Manila, PH"
    "Frankfurt, Hesse, DE"
    "Local / Private"
    "Unknown"
    """
    if not ip or _is_private(ip):
        return "Local / Private"
    return _fetch_location(ip)
