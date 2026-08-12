from __future__ import annotations

import threading
import time


class RateLimitError(Exception):
    def __init__(self, message: str = "Rate limit exceeded") -> None:
        super().__init__(message)
        self.status = 429


class RateLimiter:
    """In-memory sliding-window limiter (Hagrid-style)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last: dict[str, float] = {}
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str, interval_sec: float) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._last.get(key)
            if last is not None and (now - last) < interval_sec:
                return False
            self._last[key] = now
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
    """
    Resolve client IP for rate limiting.

    Prefer platform-provided addresses. When X-Forwarded-For is present (Front Door),
    use the *last* hop — the one appended by the trusted reverse proxy — rather than
    the first (client-controlled) entry.
    """
    # `X-Azure-ClientIP` only: Azure sets it at the edge, so a client cannot
    # forge one past Front Door. `X-Client-IP` used to be in this tuple and is
    # not an Azure header at all — nothing in terraform/, infra/ or .github/
    # sets or strips it, and Front Door has no request-header rules, so it
    # forwarded whatever the caller sent. Being checked *before* the hardened
    # branch below, it let any caller pick their own bucket and made every
    # per-IP limiter — lookup, upload, sendtoken, negotiate, TURN — a header
    # away from unlimited. Measured at 100/100 uploads through a 3600 s gap
    # from one client. `require_front_door` does not help: a request *through*
    # Front Door still carries whatever the client set.
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
