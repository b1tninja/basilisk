from __future__ import annotations

import threading
import time
from collections import defaultdict


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


def check_upload_rate(ip: str, fingerprint: str | None = None) -> None:
    from basilisk.config import get_settings

    settings = get_settings()
    limiter = get_limiter()
    if not limiter.allow(f"upload:ip:{ip}", settings.upload_rate_limit_sec):
        raise RateLimitError("Upload rate limit exceeded for this IP")
    if fingerprint and not limiter.allow(
        f"upload:fpr:{fingerprint.upper()}",
        settings.upload_fingerprint_rate_limit_sec,
    ):
        raise RateLimitError("Upload rate limit exceeded for this key")


def check_sendtoken_rate(ip: str, email: str) -> None:
    from basilisk.config import get_settings

    settings = get_settings()
    limiter = get_limiter()
    if not limiter.allow(f"sendtoken:ip:{ip}", settings.upload_rate_limit_sec):
        raise RateLimitError("Rate limit exceeded")
    if not limiter.allow(f"sendtoken:email:{email.lower()}", settings.sendtoken_rate_limit_sec):
        raise RateLimitError("Sendtoken rate limit exceeded for this email")
