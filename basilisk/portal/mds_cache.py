"""Same-origin cache/proxy for the FIDO Metadata Service (MDS3) JWT BLOB.

Browsers cannot fetch MDS directly under Basilisk CSP (connect-src 'self').
This endpoint pulls the public BLOB server-side and caches it in memory.
"""

from __future__ import annotations

import logging
import threading
import time
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

MDS3_URL = "https://mds3.fidoalliance.org/"
# FIDO suggests refreshing about monthly; keep a week of in-process cache.
CACHE_TTL_SEC = 7 * 24 * 60 * 60
FETCH_TIMEOUT_SEC = 30

_lock = threading.Lock()
_cached_jwt: str | None = None
_cached_at: float = 0.0


def get_mds_blob(*, force_refresh: bool = False) -> str:
    """Return the MDS3 JWT string, refreshing from FIDO when stale."""
    global _cached_jwt, _cached_at
    now = time.time()
    with _lock:
        if (
            not force_refresh
            and _cached_jwt
            and now - _cached_at < CACHE_TTL_SEC
        ):
            return _cached_jwt

    jwt = _fetch_mds_jwt()
    with _lock:
        _cached_jwt = jwt
        _cached_at = time.time()
        return _cached_jwt


def _fetch_mds_jwt() -> str:
    req = urllib.request.Request(
        MDS3_URL,
        headers={
            "Accept": "application/jwt, application/json, text/plain, */*",
            "User-Agent": "basilisk-mds-proxy/1.0",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_SEC) as resp:
            body = resp.read()
    except urllib.error.HTTPError as exc:
        logger.warning("MDS fetch HTTP %s", exc.code)
        raise
    except Exception:
        logger.exception("MDS fetch failed")
        raise

    text = body.decode("utf-8", errors="strict").strip()
    if text.count(".") < 2:
        raise ValueError("MDS response does not look like a JWT")
    return text
