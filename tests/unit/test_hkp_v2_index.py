"""Unit tests for the v2 index building blocks (draft-gallagher-openpgp-hkp-10)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from basilisk.db.store import CertRecord
from basilisk.hkp_v2.index import cert_object
from basilisk.hkp_v2.lookup import parse_vfingerprint, uid_matches_identity
from basilisk.openpgp.keyinfo import (
    ALGORITHM_NAMES,
    is_expired,
    key_fingerprint,
    parse_cert_info,
    rfc3339,
)
from basilisk.openpgp.packets import armor_public_key, dearmor


def _record(fingerprint: str, uids: list[str]) -> CertRecord:
    return CertRecord(
        fingerprint=fingerprint.upper(),
        approval_state="approved",
        blob_uri="blob",
        sha256="0" * 64,
        key_id=fingerprint[-16:],
        approved_uids=uids,
    )


# --------------------------------------------------------------------------
# §5.1.9 identity matching
# --------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("uid", "identity", "expected"),
    [
        ("Alice <alice@example.com>", "alice@example.com", True),
        ("Alice <alice@example.com>", "ALICE@EXAMPLE.COM", True),
        ("Alice (work) <alice@example.com>", "alice@example.com", True),
        ("alice@example.com", "alice@example.com", True),
        # Only the angle-bracket contents match, never the display name or domain.
        ("Alice <alice@example.com>", "Alice", False),
        ("Alice <alice@example.com>", "example.com", False),
        ("Alice <alice@example.com>", "alice", False),
        # A non-email User ID matches on its full text only.
        ("Some Project Team", "some project team", True),
        ("Some Project Team", "Some Project", False),
    ],
)
def test_uid_matches_identity(uid, identity, expected):
    """§5.1.9: v2 identity lookups "MUST only return results if the
    'identifier' path component exactly matches" the angle-bracket email or
    the full text of a non-email User ID."""
    assert uid_matches_identity(uid, identity) is expected


@pytest.mark.unit
@pytest.mark.parametrize("identity", ["a@b.com", "c@d.com"])
def test_ambiguous_uid_never_matches(identity):
    """§5.1.9: "if there is more than one substring of a User ID that could
    reasonably be interpreted as an email address, then a keyserver SHOULD NOT
    return an identity match on either substring.\""""
    assert uid_matches_identity("Evil <a@b.com> <c@d.com>", identity) is False


# --------------------------------------------------------------------------
# §5.1.2 versioned fingerprints
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_vfingerprint():
    """§5.1.2: "one octet of fingerprint version number and N octets of
    fingerprint", hex, "without a preceding 0x"."""
    v4 = "ab" * 20
    v6 = "cd" * 32
    assert parse_vfingerprint("04" + v4) == (4, v4.upper())
    assert parse_vfingerprint("06" + v6) == (6, v6.upper())
    assert parse_vfingerprint("05" + v6) == (5, v6.upper())
    # No version octet, wrong length, 0x prefix, odd nybble count, non-hex.
    assert parse_vfingerprint(v4) is None
    assert parse_vfingerprint("04" + v6) is None
    assert parse_vfingerprint("0x04" + v4) is None
    assert parse_vfingerprint("04" + v4 + "a") is None
    assert parse_vfingerprint("zz" + v4) is None


# --------------------------------------------------------------------------
# Packet-derived metadata
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_cert_info_matches_sequoia(sample_armored, sample_fingerprint):
    """The packet parser must agree with the reference implementation on the
    fingerprint it derives (RFC 9580 §5.5.4)."""
    info = parse_cert_info(dearmor(sample_armored.encode()))
    assert info is not None
    assert info.primary.version == 4
    assert info.primary.fingerprint == sample_fingerprint.lower()
    assert info.primary.algorithm == 1
    assert info.primary.bit_length == 2048
    assert [u.uid for u in info.user_ids] == ["test@basilisk.local"]


@pytest.mark.unit
def test_parse_cert_info_v6_fingerprint_matches_sequoia():
    """v6 fingerprints are SHA-256 over ``0x9B || 4-octet length || body``."""
    pysequoia = pytest.importorskip("pysequoia")
    cert = pysequoia.Cert.generate(
        user_ids=["V6 <v6@example.test>"], profile=pysequoia.Profile.RFC9580
    )
    info = parse_cert_info(dearmor(str(cert).encode()))
    assert info.primary.version == 6
    assert info.primary.fingerprint == cert.fingerprint.lower()
    # Subkey fingerprints are computed the same way.
    assert info.subkeys
    assert all(s.version == 6 and len(s.fingerprint) == 64 for s in info.subkeys)


@pytest.mark.unit
def test_key_fingerprint_rejects_unknown_versions():
    assert key_fingerprint(b"\x03rest") is None
    assert key_fingerprint(b"") is None


@pytest.mark.unit
def test_algorithm_names_follow_rfc9580_table_18():
    """RFC 9580 §9.1 Table 18 — the numbering changed late in the draft, so
    pin the post-9580 assignments."""
    assert ALGORITHM_NAMES[25] == "X25519"
    assert ALGORITHM_NAMES[26] == "X448"
    assert ALGORITHM_NAMES[27] == "Ed25519"
    assert ALGORITHM_NAMES[28] == "Ed448"
    assert 20 not in ALGORITHM_NAMES  # reserved, no name to report


@pytest.mark.unit
def test_rfc3339_is_utc_zulu():
    """§7.1.1: "Timestamps are given in UTC as per Section 5.6 of [RFC3339]"."""
    moment = datetime(2001, 1, 1, 1, 1, 1, tzinfo=timezone(timedelta(hours=5)))
    assert rfc3339(moment) == "2000-12-31T20:01:01Z"
    assert rfc3339(None) is None


@pytest.mark.unit
def test_is_expired():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert is_expired(None, now=now) is False
    assert is_expired(now - timedelta(seconds=1), now=now) is True
    assert is_expired(now + timedelta(seconds=1), now=now) is False


# --------------------------------------------------------------------------
# §7.1.1 index objects
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_cert_object_required_fields(sample_armored, sample_fingerprint):
    """§7.1.1: "The only required fields are the version and fingerprint of any
    key material, and the uidString of any User IDs.\""""
    binary = dearmor(sample_armored.encode())
    record = _record(sample_fingerprint, ["test@basilisk.local"])
    obj = cert_object(record, binary, identity="test@basilisk.local")

    assert obj["version"] == 4
    assert obj["fingerprint"] == sample_fingerprint.lower()
    assert obj["algorithm"] == {
        "code": 1,
        "name": "RSA (Encrypt or Sign)",
        "bitLength": 2048,
    }
    assert obj["userIDs"][0]["uidString"] == "test@basilisk.local"
    assert obj["userIDs"][0]["confidence"] == 120
    for subkey in obj.get("subkeys", []):
        assert isinstance(subkey["version"], int)
        assert isinstance(subkey["fingerprint"], str)


@pytest.mark.unit
def test_unapproved_uid_has_zero_confidence(sample_armored, sample_fingerprint):
    """§8: complete confidence requires a verified identity link; an unapproved
    User ID must not claim one."""
    binary = dearmor(sample_armored.encode())
    obj = cert_object(_record(sample_fingerprint, []), binary)
    assert obj["userIDs"][0]["confidence"] == 0


@pytest.mark.unit
def test_bitlength_only_for_rsa_dsa_elgamal():
    """§7.1.1 Table 9: bitLength is for "DSA/RSA/ElGamal keys only"."""
    pysequoia = pytest.importorskip("pysequoia")
    cert = pysequoia.Cert.generate(user_ids=["Ed <ed@example.test>"])
    info = parse_cert_info(dearmor(str(cert).encode()))
    assert info.primary.algorithm not in (1, 2, 3, 16, 17)
    assert info.primary.bit_length is None


@pytest.mark.unit
def test_cert_object_returns_none_for_non_certificate():
    assert cert_object(_record("AA" * 20, []), b"") is None
    assert cert_object(_record("AA" * 20, []), b"\xc2\x01\x04") is None  # signature packet


# --------------------------------------------------------------------------
# Armor handling
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_dearmor_skips_armor_headers(sample_armored):
    """RFC 9580 §6.2 armor headers precede the base64 data; GnuPG and Sequoia
    both emit ``Comment:``. Ignoring them corrupts the packet stream."""
    expected = dearmor(sample_armored.encode())
    body = sample_armored.split("-----\n", 1)[1]
    with_headers = (
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
        "Version: GnuPG v2\n"
        "Comment: https://example.test\n"
        "\n" + body
    )
    assert dearmor(with_headers.encode()) == expected


@pytest.mark.unit
def test_dearmor_concatenates_multiple_blocks(sample_armored):
    """§9: a bundle is "a sequence of one or more OpenPGP certificates,
    concatenated directly"."""
    single = dearmor(sample_armored.encode())
    doubled = dearmor((sample_armored + sample_armored).encode())
    assert doubled == single + single


@pytest.mark.unit
def test_dearmor_passes_binary_through(sample_armored):
    binary = dearmor(sample_armored.encode())
    assert dearmor(binary) == binary
    assert dearmor(armor_public_key(binary)) == binary
