"""Attested certification merge / validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from basilisk.db.blob_store import LocalBlobStore
from basilisk.db.sqlite_store import SqliteCertStore, sha256_hex
from basilisk.openpgp.certifications import merge_attested_certifications
from basilisk.openpgp.errors import IngestError
from basilisk.openpgp.ingest import parse_armored_keytext
from basilisk.openpgp.packets import armor_public_key, dearmor, list_third_party_certifications


@pytest.fixture
def sample_armored() -> str:
    return (Path(__file__).resolve().parents[1] / "fixtures" / "keys" / "sample.asc").read_text(
        encoding="utf-8"
    )


@pytest.fixture
def store_and_blobs(tmp_path):
    store = SqliteCertStore(str(tmp_path / "certs.db"))
    blobs = LocalBlobStore(str(tmp_path / "blobs"))
    return store, blobs


def _clear_no_modify(binary: bytes) -> bytes:
    data = bytearray(binary)
    needle = bytes([2, 23, 0x80])
    idx = bytes(data).find(needle)
    if idx >= 0:
        data[idx + 2] = 0
    return bytes(data)


def _approve_sample(store, blobs, sample_armored: str, *, clear_no_modify: bool = True):
    """Approve sample key; clear no-modify by default so merge tests can exercise later checks."""
    parsed = parse_armored_keytext(sample_armored, path="v1")
    raw = parsed.armored
    if clear_no_modify:
        raw = armor_public_key(_clear_no_modify(dearmor(parsed.armored)))
    digest = sha256_hex(raw)
    uri = blobs.write_cert(parsed.fingerprint, digest, raw)
    store.upsert_pending(
        parsed.fingerprint,
        uri,
        digest,
        parsed.key_id,
        parsed.uids,
    )
    store.approve(parsed.fingerprint, parsed.uids)
    return parsed


@pytest.mark.unit
def test_merge_rejects_missing_target(store_and_blobs, sample_armored):
    store, blobs = store_and_blobs
    with pytest.raises(IngestError) as exc:
        merge_attested_certifications(
            store,
            blobs,
            "AABBCCDDEEFF00112233445566778899AABBCCDD",
            sample_armored,
        )
    assert exc.value.status == 404


@pytest.mark.unit
def test_merge_rejects_when_no_third_party_certs(store_and_blobs, sample_armored):
    store, blobs = store_and_blobs
    parsed = _approve_sample(store, blobs, sample_armored)
    with pytest.raises(IngestError) as exc:
        merge_attested_certifications(store, blobs, parsed.fingerprint, sample_armored)
    assert "No third-party" in str(exc.value)


@pytest.mark.unit
def test_merge_rejects_unapproved_issuer(store_and_blobs, sample_armored):
    store, blobs = store_and_blobs
    parsed = _approve_sample(store, blobs, sample_armored)
    binary = dearmor(parsed.armored)

    foreign_fpr = "00112233445566778899AABBCCDDEEFF00112233"
    fpr_bytes = bytes.fromhex(foreign_fpr)
    hashed = bytes([22, 33, 4]) + fpr_bytes
    body = bytes([4, 0x10, 1, 8])
    body += len(hashed).to_bytes(2, "big") + hashed
    body += (0).to_bytes(2, "big")
    body += b"\x00" * 34
    fake_sig = bytes([0xC2, len(body)]) + body
    uploaded = armor_public_key(_clear_no_modify(binary) + fake_sig).decode("utf-8")

    with pytest.raises(IngestError) as exc:
        merge_attested_certifications(store, blobs, parsed.fingerprint, uploaded)
    assert "not an approved key" in str(exc.value).lower()


@pytest.mark.unit
def test_list_third_party_empty_on_self_only(sample_armored):
    parsed = parse_armored_keytext(sample_armored, path="v1")
    certs = list_third_party_certifications(dearmor(parsed.armored), parsed.fingerprint)
    assert certs == []
