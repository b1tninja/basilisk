import pytest

from basilisk.config import get_settings
from basilisk.hkp.lookup import lookup_get
from basilisk.hkp.add import ingest_keytext
from basilisk.hkp.handlers import get_blob_store, get_store


@pytest.mark.unit
def test_redirect_mode(monkeypatch, sample_armored, sample_fingerprint):
    monkeypatch.setenv("BASILISK_CACHE_MODE", "redirect")
    monkeypatch.setenv("BASILISK_FD_BASE_URL", "https://cdn.example.com")
    get_settings.cache_clear()
    store = get_store()
    blobs = get_blob_store()
    ingest_keytext(store, blobs, sample_armored)
    resp = lookup_get(f"0x{sample_fingerprint}")
    assert resp.status == 302
    assert resp.headers.get("Location", "").startswith("https://cdn.example.com/")
    get_settings.cache_clear()
