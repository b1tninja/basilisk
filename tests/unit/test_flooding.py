"""Certificate-flooding defenses: third-party signature strip + packet caps."""

from __future__ import annotations

import pytest

from basilisk.openpgp.errors import IngestError
from basilisk.openpgp.ingest import parse_armored_keytext
from basilisk.openpgp.packets import (
    count_packets,
    dearmor,
    iter_packets,
    strip_third_party_sigs,
)
from basilisk.openpgp.policy import PolicyConfig, validate_cert_policy


@pytest.fixture
def sample_armored() -> str:
    from pathlib import Path

    return (Path(__file__).resolve().parents[1] / "fixtures" / "keys" / "sample.asc").read_text(
        encoding="utf-8"
    )


@pytest.mark.unit
def test_sample_key_self_sigs_survive_strip(sample_armored):
    parsed = parse_armored_keytext(sample_armored, path="v1")
    binary = dearmor(parsed.armored)
    before = sum(1 for t, *_ in iter_packets(binary) if t == 2)
    cleaned = strip_third_party_sigs(binary, parsed.fingerprint)
    after = sum(1 for t, *_ in iter_packets(cleaned) if t == 2)
    # Sample cert has only self-signatures — none should be dropped.
    assert after == before
    assert after >= 1
    # Still parseable
    from pysequoia import Cert

    Cert.from_bytes(cleaned)


@pytest.mark.unit
def test_third_party_sig_packet_dropped(sample_armored):
    """Inject a fake signature packet with a foreign issuer key ID; it must be stripped."""
    parsed = parse_armored_keytext(sample_armored, path="v1")
    binary = dearmor(parsed.armored)

    # Minimal v4 signature packet body with Issuer Key ID subpacket (type 16)
    # pointing at a foreign key ID (all 0xFF).
    foreign_keyid = bytes.fromhex("ffffffffffffffff")
    # hashed area: one subpacket length=9, type=16, 8-byte keyid
    hashed = bytes([9, 16]) + foreign_keyid
    # unhashed empty
    body = bytes(
        [
            4,  # version
            0x10,  # generic certification
            1,  # RSA
            8,  # SHA256
        ]
    )
    body += len(hashed).to_bytes(2, "big") + hashed
    body += (0).to_bytes(2, "big")  # unhashed len
    body += b"\x00" * 2  # left 16 bits of hash
    body += b"\x00" * 32  # fake MPI / signature material (ignored by strip)

    # New-format packet tag 2, one-octet length
    assert len(body) < 192
    fake_sig = bytes([0xC2, len(body)]) + body
    flooded = binary + fake_sig

    before_sigs = sum(1 for t, *_ in iter_packets(flooded) if t == 2)
    cleaned = strip_third_party_sigs(flooded, parsed.fingerprint)
    after_sigs = sum(1 for t, *_ in iter_packets(cleaned) if t == 2)
    assert before_sigs == after_sigs + 1
    assert fake_sig not in cleaned


@pytest.mark.unit
def test_packet_cap_rejects_huge_cert(sample_armored, monkeypatch):
    parsed = parse_armored_keytext(sample_armored, path="v1")
    n = count_packets(dearmor(parsed.armored))
    cfg = PolicyConfig(
        max_armored_bytes=64 * 1024,
        max_uids=20,
        max_subkey_blocks=32,
        max_packets=max(1, n - 1),
        require_email_uid=True,
        reject_revoked=True,
        blocked_domains=frozenset(),
    )
    with pytest.raises(IngestError) as exc:
        validate_cert_policy(parsed, "v1", config=cfg)
    assert exc.value.status == 422
    assert "packets" in str(exc.value).lower()


@pytest.mark.unit
def test_uid_cap_still_enforced(sample_armored):
    parsed = parse_armored_keytext(sample_armored, path="v1")
    # Fabricate too many UIDs on the parsed object
    parsed.uids = [f"user{i}@example.com" for i in range(25)]
    cfg = PolicyConfig(
        max_armored_bytes=64 * 1024,
        max_uids=20,
        max_subkey_blocks=32,
        max_packets=1000,
        require_email_uid=True,
        reject_revoked=True,
        blocked_domains=frozenset(),
    )
    with pytest.raises(IngestError) as exc:
        validate_cert_policy(parsed, "v1", config=cfg)
    assert "user ID" in str(exc.value)
