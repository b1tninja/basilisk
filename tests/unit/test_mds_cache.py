"""Tests for FIDO MDS blob proxy/cache."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from basilisk.portal import mds_cache


@pytest.fixture(autouse=True)
def _clear_mds_cache():
    mds_cache._cached_jwt = None
    mds_cache._cached_at = 0.0
    yield
    mds_cache._cached_jwt = None
    mds_cache._cached_at = 0.0


def test_get_mds_blob_caches():
    fake = "aaa.bbb.ccc"
    with patch.object(mds_cache, "_fetch_mds_jwt", return_value=fake) as fetch:
        assert mds_cache.get_mds_blob() == fake
        assert mds_cache.get_mds_blob() == fake
        assert fetch.call_count == 1


def test_get_mds_blob_force_refresh():
    with patch.object(
        mds_cache, "_fetch_mds_jwt", side_effect=["a.b.c", "d.e.f"]
    ) as fetch:
        assert mds_cache.get_mds_blob() == "a.b.c"
        assert mds_cache.get_mds_blob(force_refresh=True) == "d.e.f"
        assert fetch.call_count == 2


def test_fetch_rejects_non_jwt():
    cm = MagicMock()
    cm.__enter__.return_value.read.return_value = b"not-a-jwt"
    cm.__enter__.return_value.__iter__ = lambda self: iter([])
    with patch("urllib.request.urlopen", return_value=cm):
        with pytest.raises(ValueError, match="JWT"):
            mds_cache._fetch_mds_jwt()
