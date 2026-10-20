from __future__ import annotations

import threading
import time


class RateLimitError(Exception):
    def __init__(self, message: str = "Rate limit exceeded") -> None:
        super().__init__(message)
        self.status = 429


# One process, unbounded keys: a caller who can vary the bucket name (or just
# a lot of real clients) grows these dicts without limit. Past this, the
# oldest half is dropped. A dropped key starts a fresh window, which is a
# small loosening, not a way to pin the process to RAM.
_MAX_BUCKETS = 100_000


class RateLimiter:
    """In-memory sliding-window limiter (Hagrid-style)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last: dict[str, float] = {}
        self._buckets: dict[str, tuple[float, float]] = {}

    def _trim(self, table: dict) -> None:
        if len(table) <= _MAX_BUCKETS:
            return
        ranked = sorted(
            table.items(),
            key=lambda item: item[1] if isinstance(item[1], float) else item[1][1],
        )
        for key, _value in ranked[: len(table) // 2]:
            table.pop(key, None)

    def allow(self, key: str, interval_sec: float) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._last.get(key)
            if last is not None and (now - last) < interval_sec:
                return False
            self._last[key] = now
            self._trim(self._last)
            return True

    def allow_burst(self, key: str, capacity: int, refill_sec: float) -> bool:
        """Token bucket: `capacity` calls may land together, then one more
        every `refill_sec`.

        ``allow`` enforces a minimum gap, which suits a caller acting alone —
        one person publishing one key. It cannot express a workload where
        several legitimate callers act at the same instant under one key, and
        refusing those is not a delay when the refusal aborts the operation.
        A bucket separates the two questions a gap conflates: how many may
        arrive together, and how fast they may keep coming.
        """
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (float(capacity), now))
            tokens = min(float(capacity), tokens + (now - last) / refill_sec)
            if tokens < 1.0:
                # Refused calls still advance the refill clock but spend
                # nothing, so hammering cannot push the recovery further away.
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1.0, now)
            self._trim(self._buckets)
            return True

    def check_or_raise(self, key: str, interval_sec: float) -> None:
        if not self.allow(key, interval_sec):
            raise RateLimitError()


_limiter = RateLimiter()


def reset_limiter() -> None:
    global _limiter
    _limiter = RateLimiter()


def get_limiter() -> RateLimiter:
    return _limiter


def client_ip(headers: dict[str, str], remote_addr: str | None = None) -> str:
    """Resolve the client IP used for rate limiting.

    ``X-Azure-ClientIP`` and ``X-Forwarded-For`` are trusted only when this
    request already carries the configured Front Door id. Azure overwrites
    those headers at the edge; a request that did not come through that edge
    can set them to whatever it likes, and each new value was its own bucket.
    Without a configured edge, the socket address is the only one we have.
    """
    from basilisk.security.edge import expected_afd_id, request_has_trusted_afd

    if expected_afd_id() and request_has_trusted_afd(headers):
        for name in ("X-Azure-ClientIP", "x-azure-clientip"):
            val = headers.get(name)
            if val:
                return val.split(",")[0].strip()
        xff = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                return parts[-1]
    return remote_addr or "unknown"


def _check_interval(limiter: RateLimiter, key: str, interval_sec: float, message: str) -> None:
    if interval_sec <= 0:
        return
    if not limiter.allow(key, interval_sec):
        raise RateLimitError(message)


def check_lookup_rate(ip: str) -> None:
    from basilisk.config import get_settings

    settings = get_settings()
    _check_interval(
        get_limiter(),
        f"lookup:ip:{ip}",
        settings.lookup_rate_limit_sec,
        "Lookup rate limit exceeded for this IP",
    )


def check_upload_rate(ip: str, fingerprint: str | None = None) -> None:
    from basilisk.config import get_settings

    settings = get_settings()
    limiter = get_limiter()
    _check_interval(
        limiter,
        f"upload:ip:{ip}",
        settings.upload_rate_limit_sec,
        "Upload rate limit exceeded for this IP",
    )
    if fingerprint:
        _check_interval(
            limiter,
            f"upload:fpr:{fingerprint.upper()}",
            settings.upload_fingerprint_rate_limit_sec,
            "Upload rate limit exceeded for this key",
        )


def check_sendtoken_rate(ip: str, email: str) -> None:
    from basilisk.config import get_settings

    settings = get_settings()
    limiter = get_limiter()
    _check_interval(limiter, f"sendtoken:ip:{ip}", settings.upload_rate_limit_sec, "Rate limit exceeded")
    _check_interval(
        limiter,
        f"sendtoken:email:{email.lower()}",
        settings.sendtoken_rate_limit_sec,
        "Sendtoken rate limit exceeded for this email",
    )
