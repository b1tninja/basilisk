import pytest

from basilisk.hkp.handlers import get_blob_store, get_store, ingest_keytext, lookup_get
from basilisk.openpgp.approve import approve_cert


@pytest.mark.unit
def test_upload_pending_email_404(sample_armored, sample_fingerprint):
    store = get_store()
    blobs = get_blob_store()
    ingest_keytext(store, blobs, sample_armored)
    resp = lookup_get(f"0x{sample_fingerprint}")
    assert resp.status == 200
    resp_email = lookup_get("test@basilisk.local")
    assert resp_email.status == 404


@pytest.mark.unit
def test_approve_enables_email_lookup(sample_armored, sample_fingerprint):
    store = get_store()
    blobs = get_blob_store()
    ingest_keytext(store, blobs, sample_armored)
    approve_cert(store, sample_fingerprint, ["test@basilisk.local"])
    resp = lookup_get("test@basilisk.local")
    assert resp.status == 200
