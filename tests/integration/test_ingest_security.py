from pathlib import Path

import pytest

from basilisk.hkp.add import ingest_keytext
from basilisk.hkp.handlers import get_blob_store, get_store
from basilisk.openpgp.ingest import IngestError


@pytest.mark.integration
def test_reject_does_not_write_blob(sample_armored, tmp_path, monkeypatch):
    monkeypatch.setenv("BASILISK_BLOB_PATH", str(tmp_path / "blobs"))
    monkeypatch.setenv("BASILISK_DB_PATH", str(tmp_path / "test.db"))
    from basilisk.config import get_settings

    get_settings.cache_clear()
    store = get_store()
    blobs = get_blob_store()
    bad = "not openpgp armor"
    with pytest.raises(IngestError):
        ingest_keytext(store, blobs, bad, path="v1")
    assert store.stats()["total"] == 0
    assert not any((tmp_path / "blobs").rglob("*.asc"))
    get_settings.cache_clear()


@pytest.mark.integration
def test_duplicate_upload_skips_new_blob(sample_armored, tmp_path, monkeypatch):
    monkeypatch.setenv("BASILISK_BLOB_PATH", str(tmp_path / "blobs"))
    monkeypatch.setenv("BASILISK_DB_PATH", str(tmp_path / "test.db"))
    from basilisk.config import get_settings

    get_settings.cache_clear()
    store = get_store()
    blobs = get_blob_store()
    fpr1, _, dup1 = ingest_keytext(store, blobs, sample_armored, path="v1")
    assert dup1 is False
    blob_files = list((tmp_path / "blobs").rglob("*.asc"))
    assert len(blob_files) == 1
    fpr2, _, dup2 = ingest_keytext(store, blobs, sample_armored, path="v1")
    assert fpr1 == fpr2
    assert dup2 is True
    assert len(list((tmp_path / "blobs").rglob("*.asc"))) == 1
    get_settings.cache_clear()
