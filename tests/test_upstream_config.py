"""Unit tests for BASILISK_UPSTREAM_* settings helpers."""

from __future__ import annotations

import os

import pytest

from basilisk.config import (
    Settings,
    _normalize_keyserver_host,
    _parse_upstream_allowlist,
    get_settings,
)


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_normalize_keyserver_host():
    assert _normalize_keyserver_host("keys.openpgp.org") == "keys.openpgp.org"
    assert _normalize_keyserver_host("hkps://Keys.OpenPGP.org/pks") == "keys.openpgp.org"
    assert _normalize_keyserver_host("keys.mailvelope.com:443") == "keys.mailvelope.com"
    assert _normalize_keyserver_host("127.0.0.1") is None
    assert _normalize_keyserver_host("localhost") is None
    assert _normalize_keyserver_host("http://user@evil.com") is None


def test_parse_allowlist_defaults():
    assert "keys.openpgp.org" in _parse_upstream_allowlist(None)
    assert "keys.mailvelope.com" in _parse_upstream_allowlist("")
    custom = _parse_upstream_allowlist("keys.openpgp.org, evil..bad, keys.mailvelope.com")
    assert custom == ("keys.openpgp.org", "keys.mailvelope.com")


def test_settings_upstream_public(monkeypatch):
    monkeypatch.setenv("BASILISK_TOKEN_SECRET", "test-secret-for-upstream-config")
    monkeypatch.setenv("BASILISK_ALLOW_DEV_SECRET", "1")
    monkeypatch.setenv("BASILISK_UPSTREAM_ENABLED", "1")
    monkeypatch.setenv(
        "BASILISK_UPSTREAM_ALLOWLIST", "keys.openpgp.org,keys.mailvelope.com"
    )
    monkeypatch.setenv("BASILISK_UPSTREAM_DEFAULT", "keys.openpgp.org")
    get_settings.cache_clear()
    s = Settings.from_env()
    pub = s.upstream_public()
    assert pub["enabled"] is True
    assert pub["default"] == "keys.openpgp.org"
    assert "keys.openpgp.org" in pub["allowlist"]
    assert "https://keys.openpgp.org" in s.csp_connect_src()
    assert "'self'" in s.csp_connect_src()
