"""RFC 9580 §5.2.3.25 no-modify preference + history endpoint helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from basilisk.db.blob_store import LocalBlobStore
from basilisk.db.sqlite_store import SqliteCertStore, sha256_hex
from basilisk.openpgp.certifications import merge_attested_certifications
from basilisk.openpgp.errors import IngestError
from basilisk.openpgp.ingest import parse_armored_keytext
from basilisk.openpgp.packets import (
    dearmor,
    has_keyserver_no_modify,
    list_self_notations,
)


@pytest.fixture
def sample_armored() -> str:
    return (Path(__file__).resolve().parents[1] / "fixtures" / "keys" / "sample.asc").read_text(
        encoding="utf-8"
    )


def _clear_no_modify_bit(binary: bytes) -> bytes:
    """Clear Key Server Preferences no-modify bit (0x80) if present."""
    data = bytearray(binary)
    needle = bytes([2, 23, 0x80])
    idx = bytes(data).find(needle)
    if idx >= 0:
        data[idx + 2] = 0
    return bytes(data)


@pytest.mark.unit
def test_sample_key_has_no_modify(sample_armored):
    """Fixture sample.asc advertises no-modify on its positive certification."""
    parsed = parse_armored_keytext(sample_armored, path="v1")
    assert has_keyserver_no_modify(dearmor(parsed.armored), parsed.fingerprint) is True


@pytest.mark.unit
def test_has_keyserver_no_modify_false_when_cleared(sample_armored):
    parsed = parse_armored_keytext(sample_armored, path="v1")
    cleared = _clear_no_modify_bit(dearmor(parsed.armored))
    assert has_keyserver_no_modify(cleared, parsed.fingerprint) is False


@pytest.mark.unit
def test_merge_rejects_no_modify(tmp_path, sample_armored):
    store = SqliteCertStore(str(tmp_path / "certs.db"))
    blobs = LocalBlobStore(str(tmp_path / "blobs"))
    parsed = parse_armored_keytext(sample_armored, path="v1")
    digest = sha256_hex(parsed.armored)
    uri = blobs.write_cert(parsed.fingerprint, digest, parsed.armored)
    store.upsert_pending(
        parsed.fingerprint, uri, digest, parsed.key_id, parsed.uids
    )
    store.approve(parsed.fingerprint, parsed.uids)

    with pytest.raises(IngestError) as exc:
        merge_attested_certifications(store, blobs, parsed.fingerprint, sample_armored)
    assert exc.value.status == 422
    assert "no-modify" in str(exc.value).lower()


@pytest.mark.unit
def test_history_appended_on_first_seen(tmp_path, sample_armored):
    store = SqliteCertStore(str(tmp_path / "certs.db"))
    blobs = LocalBlobStore(str(tmp_path / "blobs"))
    parsed = parse_armored_keytext(sample_armored, path="v1")
    digest = sha256_hex(parsed.armored)
    uri = blobs.write_cert(parsed.fingerprint, digest, parsed.armored)
    store.upsert_pending(
        parsed.fingerprint, uri, digest, parsed.key_id, parsed.uids
    )
    rec = store.get_by_fingerprint(parsed.fingerprint)
    assert rec is not None
    assert rec.created_at
    assert rec.updated_at
    history = store.list_history(parsed.fingerprint)
    assert history
    assert history[0]["event"] == "first_seen"
    assert history[0]["sha256"] == digest


@pytest.mark.unit
def test_list_self_notations_returns_list(sample_armored):
    parsed = parse_armored_keytext(sample_armored, path="v1")
    notations = list_self_notations(dearmor(parsed.armored), parsed.fingerprint)
    assert isinstance(notations, list)
