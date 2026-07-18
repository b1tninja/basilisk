"""Tests for OpenPGP key expiration: mark expired, hide from search, grace-period delete."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from basilisk.db.blob_store import LocalBlobStore
from basilisk.hkp.handlers import get_blob_store, get_store, ingest_keytext
from basilisk.openpgp.approve import approve_cert
from basilisk.portal.search import search_keys


def _past(days: int = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _future(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


@pytest.mark.unit
def test_list_approved_past_expiration(sample_armored, sample_fingerprint):
    store = get_store()
    blobs = get_blob_store()
    ingest_keytext(store, blobs, sample_armored)
    approve_cert(store, sample_fingerprint, ["test@basilisk.local"])

    # Force an expired OpenPGP expiration timestamp on the record.
    store.refresh_approved(
        sample_fingerprint,
        store.get_by_fingerprint(sample_fingerprint).blob_uri,
        store.get_by_fingerprint(sample_fingerprint).sha256,
        store.get_by_fingerprint(sample_fingerprint).key_id,
        expiration=_past(2),
    )

    now = datetime.now(timezone.utc).isoformat()
    past = store.list_approved_past_expiration(now)
    assert any(r.fingerprint == sample_fingerprint for r in past)


@pytest.mark.unit
def test_mark_expired_hides_from_search(sample_armored, sample_fingerprint):
    store = get_store()
    blobs = get_blob_store()
    ingest_keytext(store, blobs, sample_armored)
    uids = ["test@basilisk.local"]
    approve_cert(store, sample_fingerprint, uids)
    store.refresh_approved(
        sample_fingerprint,
        store.get_by_fingerprint(sample_fingerprint).blob_uri,
        store.get_by_fingerprint(sample_fingerprint).sha256,
        store.get_by_fingerprint(sample_fingerprint).key_id,
        expiration=_past(1),
    )

    # Still findable while approved.
    payload = search_keys("test@basilisk.local", store)
    assert any(r["fingerprint"] == sample_fingerprint for r in payload["results"])

    store.mark_expired(sample_fingerprint)
    record = store.get_by_fingerprint(sample_fingerprint)
    assert record is not None
    assert record.approval_state == "expired"

    # Hidden from search after mark_expired.
    payload = search_keys("test@basilisk.local", store)
    assert not any(r["fingerprint"] == sample_fingerprint for r in payload["results"])


@pytest.mark.unit
def test_delete_cert_removes_record_and_blob(sample_armored, sample_fingerprint, tmp_path):
    store = get_store()
    blobs = get_blob_store()
    ingest_keytext(store, blobs, sample_armored)
    approve_cert(store, sample_fingerprint, ["test@basilisk.local"])
    record = store.get_by_fingerprint(sample_fingerprint)
    assert record is not None
    blob_uri = record.blob_uri

    # Confirm blob exists, then delete.
    assert blobs.read(blob_uri)
    removed = store.delete_cert(sample_fingerprint)
    assert removed is not None
    assert store.get_by_fingerprint(sample_fingerprint) is None
    blobs.delete(blob_uri)
    if isinstance(blobs, LocalBlobStore):
        with pytest.raises(FileNotFoundError):
            blobs.read(blob_uri)


@pytest.mark.unit
def test_list_expired_past_grace(sample_armored, sample_fingerprint):
    store = get_store()
    blobs = get_blob_store()
    ingest_keytext(store, blobs, sample_armored)
    approve_cert(store, sample_fingerprint, ["test@basilisk.local"])
    store.refresh_approved(
        sample_fingerprint,
        store.get_by_fingerprint(sample_fingerprint).blob_uri,
        store.get_by_fingerprint(sample_fingerprint).sha256,
        store.get_by_fingerprint(sample_fingerprint).key_id,
        expiration=_past(40),
    )
    store.mark_expired(sample_fingerprint)

    grace_cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    past_grace = store.list_expired_past_grace(grace_cutoff)
    assert any(r.fingerprint == sample_fingerprint for r in past_grace)

    # Too-recent cutoff (100 days ago): a key expired 40 days ago is NOT past it.
    early_cutoff = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    assert not any(
        r.fingerprint == sample_fingerprint
        for r in store.list_expired_past_grace(early_cutoff)
    )


@pytest.mark.integration
def test_api_key_detail_still_serves_expired(sample_armored, sample_fingerprint):
    from basilisk.serve import create_app

    store = get_store()
    blobs = get_blob_store()
    ingest_keytext(store, blobs, sample_armored)
    approve_cert(store, sample_fingerprint, ["test@basilisk.local"])
    store.refresh_approved(
        sample_fingerprint,
        store.get_by_fingerprint(sample_fingerprint).blob_uri,
        store.get_by_fingerprint(sample_fingerprint).sha256,
        store.get_by_fingerprint(sample_fingerprint).key_id,
        expiration=_past(1),
    )
    store.mark_expired(sample_fingerprint)

    client = create_app().test_client()
    r = client.get(f"/api/v1/key/{sample_fingerprint}")
    assert r.status_code == 200
    body = r.get_json()
    assert body["approval_state"] == "expired"
    assert body["fingerprint"] == sample_fingerprint


@pytest.mark.unit
def test_hkp_hides_expired_keys(sample_armored, sample_fingerprint):
    from basilisk.hkp.lookup import lookup_get, lookup_index

    store = get_store()
    blobs = get_blob_store()
    ingest_keytext(store, blobs, sample_armored)
    approve_cert(store, sample_fingerprint, ["test@basilisk.local"])
    store.mark_expired(sample_fingerprint)

    assert lookup_get(f"0x{sample_fingerprint}", store=store, blobs=blobs).status == 404
    assert lookup_get("test@basilisk.local", store=store, blobs=blobs).status == 404
    assert lookup_index(f"0x{sample_fingerprint}", store=store).status == 404


@pytest.mark.unit
def test_timer_logic_hide_then_delete(sample_armored, sample_fingerprint):
    """Simulate the scheduled job: mark expired, then delete past grace."""
    store = get_store()
    blobs = get_blob_store()
    ingest_keytext(store, blobs, sample_armored)
    approve_cert(store, sample_fingerprint, ["test@basilisk.local"])
    store.refresh_approved(
        sample_fingerprint,
        store.get_by_fingerprint(sample_fingerprint).blob_uri,
        store.get_by_fingerprint(sample_fingerprint).sha256,
        store.get_by_fingerprint(sample_fingerprint).key_id,
        expiration=_past(45),
    )

    now = datetime.now(timezone.utc)
    for record in store.list_approved_past_expiration(now.isoformat()):
        store.mark_expired(record.fingerprint)

    assert store.get_by_fingerprint(sample_fingerprint).approval_state == "expired"

    grace_cutoff = (now - timedelta(days=30)).isoformat()
    for record in store.list_expired_past_grace(grace_cutoff):
        if record.blob_uri:
            blobs.delete(record.blob_uri)
        store.delete_cert(record.fingerprint)

    assert store.get_by_fingerprint(sample_fingerprint) is None
