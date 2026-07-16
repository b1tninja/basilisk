"""Tests for owner-settable key labels (PUT /api/v1/me/keys/<fpr>/label)."""
from __future__ import annotations

import pytest

from basilisk.hkp.handlers import get_blob_store, get_store, ingest_keytext
from basilisk.openpgp.approve import approve_cert
from tests.unit.test_claim import _principal_header


# ---------------------------------------------------------------------------
# Store-level unit tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_set_label_round_trips(sample_armored, sample_fingerprint):
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    assert store.get_by_fingerprint(sample_fingerprint).label is None

    store.set_label(sample_fingerprint, "My test key")
    record = store.get_by_fingerprint(sample_fingerprint)
    assert record.label == "My test key"


@pytest.mark.unit
def test_set_label_can_be_cleared(sample_armored, sample_fingerprint):
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    store.set_label(sample_fingerprint, "Temporary")
    store.set_label(sample_fingerprint, None)
    assert store.get_by_fingerprint(sample_fingerprint).label is None


# ---------------------------------------------------------------------------
# API integration tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_label_exposed_in_key_detail(sample_armored, sample_fingerprint):
    from basilisk.serve import create_app

    client = create_app().test_client()
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    store.set_label(sample_fingerprint, "Integration label")

    r = client.get(f"/api/v1/key/{sample_fingerprint}")
    assert r.status_code == 200
    assert r.get_json()["label"] == "Integration label"


@pytest.mark.integration
def test_label_included_in_my_keys(sample_armored, sample_fingerprint):
    from basilisk.serve import create_app

    client = create_app().test_client()
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    store.record_claim(sample_fingerprint, "test@basilisk.local", "oid-1")
    store.set_label(sample_fingerprint, "Claimed key label")

    r = client.get(
        "/api/v1/me/keys",
        headers=_principal_header("test@basilisk.local"),
    )
    assert r.status_code == 200
    keys = r.get_json()["keys"]
    assert any(k["label"] == "Claimed key label" for k in keys)


@pytest.mark.integration
def test_put_label_requires_auth(sample_armored, sample_fingerprint):
    from basilisk.serve import create_app

    client = create_app().test_client()
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)

    r = client.put(
        f"/api/v1/me/keys/{sample_fingerprint}/label",
        json={"label": "Should fail"},
    )
    assert r.status_code == 401


@pytest.mark.integration
def test_put_label_requires_ownership(sample_armored, sample_fingerprint):
    from basilisk.serve import create_app

    client = create_app().test_client()
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    store.record_claim(sample_fingerprint, "owner@basilisk.local", "oid-owner")

    r = client.put(
        f"/api/v1/me/keys/{sample_fingerprint}/label",
        json={"label": "Intruder label"},
        headers=_principal_header("stranger@example.com"),
    )
    assert r.status_code == 403


@pytest.mark.integration
def test_put_label_sets_and_returns_label(sample_armored, sample_fingerprint):
    from basilisk.serve import create_app

    client = create_app().test_client()
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    store.record_claim(sample_fingerprint, "test@basilisk.local", "oid-1")

    r = client.put(
        f"/api/v1/me/keys/{sample_fingerprint}/label",
        json={"label": "Work signing key"},
        headers=_principal_header("test@basilisk.local"),
    )
    assert r.status_code == 200
    assert r.get_json()["label"] == "Work signing key"

    record = store.get_by_fingerprint(sample_fingerprint)
    assert record.label == "Work signing key"


@pytest.mark.integration
def test_put_label_clears_with_empty_string(sample_armored, sample_fingerprint):
    from basilisk.serve import create_app

    client = create_app().test_client()
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    store.record_claim(sample_fingerprint, "test@basilisk.local", "oid-1")
    store.set_label(sample_fingerprint, "Old label")

    r = client.put(
        f"/api/v1/me/keys/{sample_fingerprint}/label",
        json={"label": ""},
        headers=_principal_header("test@basilisk.local"),
    )
    assert r.status_code == 200
    assert r.get_json()["label"] is None
    assert store.get_by_fingerprint(sample_fingerprint).label is None


@pytest.mark.integration
def test_put_label_truncates_at_200_chars(sample_armored, sample_fingerprint):
    from basilisk.serve import create_app

    client = create_app().test_client()
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    store.record_claim(sample_fingerprint, "test@basilisk.local", "oid-1")

    long_label = "A" * 300
    r = client.put(
        f"/api/v1/me/keys/{sample_fingerprint}/label",
        json={"label": long_label},
        headers=_principal_header("test@basilisk.local"),
    )
    assert r.status_code == 200
    assert len(r.get_json()["label"]) == 200
