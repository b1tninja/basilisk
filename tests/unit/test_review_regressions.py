"""Regressions from the keyserver security review.

Each test pins one behavior that used to fail open: an unverified signature
treated as a self-signature, a later upload replacing a stored certificate,
a write-once blob that was not, or a lookup that published an unverified
address.
"""

from __future__ import annotations

import hashlib
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from pysequoia import Cert

from basilisk.db.blob_store import BlobConflict, LocalBlobStore, cert_blob_uri
from basilisk.hkp.handlers import get_blob_store, get_store, ingest_keytext
from basilisk.hkp.lookup import lookup_get
from basilisk.hkp_v2.submit import canonical_put, sendtoken_response
from basilisk.hkp_v2.tokens import issue_token
from basilisk.openpgp.approve import approve_cert
from basilisk.openpgp.errors import IngestError
from basilisk.openpgp.keyinfo import parse_cert_info
from basilisk.openpgp.packets import (
    armor_public_key,
    dearmor,
    has_keyserver_no_modify,
    iter_packets,
    strip_third_party_sigs,
)
from basilisk.openpgp.verify import frame_key, frame_uid, signature_verifies
from basilisk.security.rate_limit import RateLimiter


def _encode_packet(tag: int, body: bytes) -> bytes:
    length = len(body)
    if length < 192:
        header = bytes([0xC0 | tag, length])
    elif length < 8384:
        adjusted = length - 192
        header = bytes([0xC0 | tag, (adjusted >> 8) + 192, adjusted & 0xFF])
    else:
        header = bytes([0xC0 | tag, 255]) + length.to_bytes(4, "big")
    return header + body


def _mpi(data: bytes) -> bytes:
    value = int.from_bytes(data, "big")
    if value == 0:
        return b"\x00\x00"
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return value.bit_length().to_bytes(2, "big") + raw


def _v4_rsa_signer():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    created = int(time.time()).to_bytes(4, "big")
    body = bytes([4]) + created + bytes([1]) + _mpi(numbers.n.to_bytes(256, "big"))
    body += _mpi(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))
    fingerprint = hashlib.sha1(frame_key(body)).hexdigest().upper()
    return private, body, fingerprint


def _certify(primary_body: bytes, uid_body: bytes, private, signer_body: bytes) -> bytes:
    created = int(time.time()).to_bytes(4, "big")
    hashed = bytes([5, 2]) + created
    prefix = bytes([4, 0x10, 1, 8]) + len(hashed).to_bytes(2, "big") + hashed
    preimage = frame_key(primary_body) + frame_uid(uid_body) + prefix
    preimage += bytes([4, 0xFF]) + len(prefix).to_bytes(4, "big")
    signature = private.sign(preimage, PKCS1v15(), hashes.SHA256())
    sig_body = prefix + b"\x00\x00" + hashlib.sha256(preimage).digest()[:2] + _mpi(signature)
    assert signature_verifies(sig_body, frame_key(primary_body) + frame_uid(uid_body), signer_body)
    return _encode_packet(2, sig_body)


def _insert_before_subkey(binary: bytes, packet: bytes) -> bytes:
    out = bytearray()
    inserted = False
    for tag, _hdr, _body, start, end in iter_packets(binary):
        if tag == 14 and not inserted:
            out.extend(packet)
            inserted = True
        out.extend(binary[start:end])
    if not inserted:
        out.extend(packet)
    return bytes(out)


def _append_unhashed_no_modify(binary: bytes) -> bytes:
    """Append Key Server Preferences (no-modify) to the first signature's unhashed area."""
    out = bytearray()
    done = False
    extra = bytes([2, 23, 0x80])
    for tag, _hdr, body, start, end in iter_packets(binary):
        if tag == 2 and not done and body and body[0] == 4:
            hashed_len = int.from_bytes(body[4:6], "big")
            pos = 6 + hashed_len
            unhashed_len = int.from_bytes(body[pos : pos + 2], "big")
            unhashed_end = pos + 2 + unhashed_len
            new_len = (unhashed_len + len(extra)).to_bytes(2, "big")
            new_body = body[:pos] + new_len + body[pos + 2 : unhashed_end] + extra + body[unhashed_end:]
            out.extend(_encode_packet(2, new_body))
            done = True
            continue
        out.extend(binary[start:end])
    return bytes(out)


def _drop_uid(binary: bytes, email: bytes) -> bytes:
    out = bytearray()
    skipping = False
    for tag, _hdr, body, start, end in iter_packets(binary):
        if tag == 13 and email in body:
            skipping = True
            continue
        if skipping and tag == 2:
            continue
        skipping = False
        out.extend(binary[start:end])
    return bytes(out)


@pytest.mark.unit
def test_forged_self_claim_is_dropped(sample_armored, sample_fingerprint):
    binary = dearmor(sample_armored.encode())
    fpr = bytes.fromhex(sample_fingerprint)
    hashed = bytes([22, 33, 4]) + fpr
    body = bytes([4, 0x10, 1, 8]) + len(hashed).to_bytes(2, "big") + hashed
    body += b"\x00\x00" + b"\x00" * 34
    fake = _encode_packet(2, body)
    cleaned = strip_third_party_sigs(binary + fake, sample_fingerprint)
    assert fake not in cleaned


@pytest.mark.unit
def test_verified_third_party_certification_is_kept(sample_armored, sample_fingerprint):
    binary = dearmor(sample_armored.encode())
    packets = iter_packets(binary)
    primary = packets[0][2]
    uid = next(body for tag, _h, body, _s, _e in packets if tag == 13)
    private, signer_body, signer_fpr = _v4_rsa_signer()
    packet = _certify(primary, uid, private, signer_body)
    flooded = _insert_before_subkey(binary, packet)
    kept = strip_third_party_sigs(
        flooded,
        sample_fingerprint,
        allowlist={signer_fpr},
        signer_keys={signer_fpr: signer_body},
    )
    assert packet in kept
    dropped = strip_third_party_sigs(flooded, sample_fingerprint, allowlist={signer_fpr})
    assert packet not in dropped


@pytest.mark.unit
def test_unhashed_no_modify_is_ignored():
    cert = Cert.generate("Ada <ada@example.test>")
    binary = bytes(cert)
    assert has_keyserver_no_modify(binary, cert.fingerprint) is False
    tampered = _append_unhashed_no_modify(binary)
    assert has_keyserver_no_modify(tampered, cert.fingerprint) is False
    # The real signature still verifies, so the certificate is not gutted.
    assert sum(1 for tag, *_ in iter_packets(strip_third_party_sigs(tampered, cert.fingerprint)) if tag == 2) >= 1


@pytest.mark.unit
def test_unverified_revocation_does_not_mark_the_index(sample_armored, sample_fingerprint):
    binary = dearmor(sample_armored.encode())
    fpr = bytes.fromhex(sample_fingerprint)
    hashed = bytes([22, 33, 4]) + fpr
    body = bytes([4, 0x20, 1, 8]) + len(hashed).to_bytes(2, "big") + hashed
    body += b"\x00\x00" + b"\x11" * 32
    info = parse_cert_info(binary + _encode_packet(2, body))
    assert info is not None
    assert info.primary.is_revoked is False


@pytest.mark.unit
def test_reupload_cannot_drop_a_user_id():
    cert = Cert.generate(user_ids=["One <one@example.test>", "Two <two@example.test>"])
    full = armor_public_key(bytes(cert)).decode("utf-8")
    store = get_store()
    blobs = get_blob_store()
    ingest_keytext(store, blobs, full)
    reduced = armor_public_key(_drop_uid(bytes(cert), b"two@example.test")).decode("utf-8")
    ingest_keytext(store, blobs, reduced)
    stored = dearmor(blobs.read(store.get_by_fingerprint(cert.fingerprint).blob_uri))
    assert b"one@example.test" in stored
    assert b"two@example.test" in stored


@pytest.mark.unit
def test_rejected_key_cannot_be_submitted_again(sample_armored, sample_fingerprint):
    store = get_store()
    blobs = get_blob_store()
    ingest_keytext(store, blobs, sample_armored)
    store.reject(sample_fingerprint)
    with pytest.raises(IngestError) as exc:
        ingest_keytext(store, blobs, sample_armored)
    assert exc.value.status == 422


@pytest.mark.unit
def test_blob_write_is_once_and_paths_stay_inside(tmp_path):
    blobs = LocalBlobStore(str(tmp_path))
    fpr = "AB" * 20
    digest = "cd" * 32
    assert blobs.write_cert(fpr, digest, b"same") == cert_blob_uri(fpr, digest)
    assert blobs.write_cert(fpr, digest, b"same") == cert_blob_uri(fpr, digest)
    with pytest.raises(BlobConflict):
        blobs.write_cert(fpr, digest, b"different")
    assert blobs.read(cert_blob_uri(fpr, digest)) == b"same"
    with pytest.raises(ValueError):
        cert_blob_uri("../etc/passwd", digest)
    with pytest.raises(ValueError):
        blobs.read("certs/../../etc/passwd")
    with pytest.raises(ValueError):
        blobs.read(f"certs/{fpr}/not-a-digest.asc")


@pytest.mark.unit
def test_approved_lookup_omits_unapproved_addresses():
    cert = Cert.generate(user_ids=["One <one@example.test>", "Two <two@example.test>"])
    armored = armor_public_key(bytes(cert)).decode("utf-8")
    store = get_store()
    ingest_keytext(store, get_blob_store(), armored)
    approve_cert(store, cert.fingerprint, ["One <one@example.test>"])
    resp = lookup_get(f"0x{cert.fingerprint}")
    assert resp.status == 200
    body = resp.body if isinstance(resp.body, bytes) else str(resp.body).encode()
    published = dearmor(body)
    assert b"one@example.test" in published
    assert b"two@example.test" not in published
    assert lookup_get("two@example.test").status == 404
    assert lookup_get("one@example.test").status == 200


@pytest.mark.unit
def test_canonical_put_checks_the_uid_before_writing(sample_armored, sample_fingerprint):
    store = get_store()
    blobs = get_blob_store()
    ingest_keytext(store, blobs, sample_armored)
    before = store.get_by_fingerprint(sample_fingerprint).sha256
    token = issue_token("stranger@example.com")
    _body, status = canonical_put("stranger@example.com", token, sample_armored.encode())
    assert status == 422
    assert store.get_by_fingerprint(sample_fingerprint).sha256 == before
    assert store.get_by_fingerprint(sample_fingerprint).approval_state == "pending"


@pytest.mark.unit
def test_sendtoken_rejects_a_header_breaking_address():
    body, status = sendtoken_response("a@b.com\nBcc:victim@example.com")
    assert status == 422
    assert body == "Invalid email"
    body, status = sendtoken_response("not-an-email")
    assert status == 422


@pytest.mark.unit
def test_hkp_add_rejects_nm_query(sample_armored):
    from basilisk.serve import create_app

    client = create_app().test_client()
    response = client.post("/pks/add?options=nm", data={"keytext": sample_armored})
    assert response.status_code == 422


@pytest.mark.unit
def test_rate_limiter_forgets_the_oldest_buckets(monkeypatch):
    monkeypatch.setattr("basilisk.security.rate_limit._MAX_BUCKETS", 10)
    limiter = RateLimiter()
    for i in range(12):
        assert limiter.allow(f"k{i}", 60) is True
    assert len(limiter._last) <= 10
    assert "k11" in limiter._last
    assert "k0" not in limiter._last
