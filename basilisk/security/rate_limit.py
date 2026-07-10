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

    def allow(self, key: str, interval_sec: float) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._last.get(key)
            if last is not None and (now - last) < interval_sec:
                return False
            self._last[key] = now
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
    xff = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
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
