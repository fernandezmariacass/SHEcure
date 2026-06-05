"""
geo_utils.py — IP geolocation helper for SHEcure
==================================================
Resolves an IP address to a human-readable location string
(e.g. "Quezon City, Metro Manila, PH") using the free ip-api.com service.

• No API key required.
• Private / reserved IPs are short-circuited and returned as "Local / Private".
• All network errors are caught so a geo failure never breaks a login.
• Results are cached in-process (dict-based, 512 entries) to avoid hitting the
  external API on every request from the same IP.

FIX: Replaced lru_cache with a plain dict cache to avoid the known issue where
lru_cache can cache raised exceptions in some CPython builds, poisoning all
future lookups for a given IP after a single network failure.
"""

import ipaddress
import logging

log = logging.getLogger(__name__)

# ip-api.com free tier: 45 requests/min per IP, no key needed.
# fields=city,regionName,countryCode keeps the response tiny.
_GEO_URL = "http://ip-api.com/json/{ip}?fields=status,city,regionName,countryCode"
_TIMEOUT = 2  # seconds — must be short so it never slows down login

# Simple bounded dict cache — avoids lru_cache exception-caching bug
_cache: dict = {}
_CACHE_MAX = 512


def _is_private(ip: str) -> bool:
    """Return True if *ip* is a loopback, private, or link-local address."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified
    except ValueError:
        return False


def _fetch_location(ip: str) -> str:
    """
    Internal cached lookup.  Only called for public IPs.
    Returns a formatted location string or a fallback on any error.
    Uses a plain dict cache instead of lru_cache to avoid exception-caching bugs.
    """
    if ip in _cache:
        return _cache[ip]

    result = "Unknown"
    try:
        # Import here to avoid any module-level import issues
        import requests as _requests
        resp = _requests.get(_GEO_URL.format(ip=ip), timeout=_TIMEOUT)
        data = resp.json()
        if data.get("status") == "success":
            city    = data.get("city", "")
            region  = data.get("regionName", "")
            country = data.get("countryCode", "")
            parts = [p for p in [city, region, country] if p]
            result = ", ".join(parts) if parts else "Unknown"
    except Exception as exc:
        log.debug("geo_utils: lookup failed for %s — %s", ip, exc)
        result = "Unknown"

    # Evict oldest entry if cache is full
    if len(_cache) >= _CACHE_MAX:
        try:
            oldest_key = next(iter(_cache))
            del _cache[oldest_key]
        except (StopIteration, RuntimeError):
            pass

    _cache[ip] = result
    return result


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
