import pytest

from basilisk.security.rate_limit import (
    RateLimitError,
    RateLimiter,
    check_lookup_rate,
    check_upload_rate,
    reset_limiter,
)


@pytest.mark.unit
def test_rate_limiter_blocks_rapid_requests():
    limiter = RateLimiter()
    assert limiter.allow("test:key", 60) is True
    assert limiter.allow("test:key", 60) is False


@pytest.mark.unit
def test_check_upload_rate_raises(monkeypatch):
    monkeypatch.setenv("BASILISK_UPLOAD_RATE_LIMIT_SEC", "60")
    from basilisk.config import get_settings

    get_settings.cache_clear()
    reset_limiter()
    ip = "203.0.113.99"
    check_upload_rate(ip)
    with pytest.raises(RateLimitError) as exc:
        check_upload_rate(ip)
    assert exc.value.status == 429
    get_settings.cache_clear()


@pytest.mark.unit
def test_check_lookup_rate_independent_of_upload(monkeypatch):
    monkeypatch.setenv("BASILISK_UPLOAD_RATE_LIMIT_SEC", "60")
    monkeypatch.setenv("BASILISK_LOOKUP_RATE_LIMIT_SEC", "0")
    from basilisk.config import get_settings

    get_settings.cache_clear()
    reset_limiter()
    ip = "203.0.113.100"
    check_upload_rate(ip)
    for _ in range(5):
        check_lookup_rate(ip)
    get_settings.cache_clear()


@pytest.mark.unit
def test_check_lookup_rate_raises_when_configured(monkeypatch):
    monkeypatch.setenv("BASILISK_LOOKUP_RATE_LIMIT_SEC", "60")
    from basilisk.config import get_settings

    get_settings.cache_clear()
    reset_limiter()
    ip = "203.0.113.101"
    check_lookup_rate(ip)
    with pytest.raises(RateLimitError):
        check_lookup_rate(ip)
    get_settings.cache_clear()
