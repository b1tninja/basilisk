"""Certificate metadata derived from the raw OpenPGP packet stream.

The HKP v2 index (draft-gallagher-openpgp-hkp-10 §7.1.1) needs per-key and
per-User-ID facts that ``pysequoia`` does not expose: primary/subkey packet
versions, subkey fingerprints, public-key algorithm IDs and bit lengths, and
the creation/expiration/revocation state of individual User IDs.

Everything here is read-only packet inspection over bytes that already passed
ingest policy. Anything that cannot be derived is left as ``None`` so the
caller can omit the field rather than invent a value (§7.1.1: "The only
required fields are the version and fingerprint of any key material, and the
uidString of any User IDs").
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from basilisk.openpgp.packets import (
    _iter_subpackets,
    _issuer_is_self,
    _signature_issuer,
    _signature_subpacket_areas,
    iter_packets,
)

# Packet tags (RFC 9580 §5)
_TAG_SIGNATURE = 2
_TAG_PUBLIC_KEY = 6
_TAG_USER_ID = 13
_TAG_PUBLIC_SUBKEY = 14
_TAG_USER_ATTRIBUTE = 17

# Signature types (RFC 9580 §5.2.1)
_CERTIFICATION_SIGS = frozenset({0x10, 0x11, 0x12, 0x13})
_SIG_SUBKEY_BINDING = 0x18
_SIG_DIRECT_KEY = 0x1F
_SIG_KEY_REVOCATION = 0x20
_SIG_SUBKEY_REVOCATION = 0x28
_SIG_CERT_REVOCATION = 0x30

# Signature subpacket types (RFC 9580 §5.2.3)
_SUB_SIG_CREATION = 2
_SUB_SIG_EXPIRATION = 3
_SUB_KEY_EXPIRATION = 9

# Public-key algorithm IDs, RFC 9580 §9.1 Table 18 ("OpenPGP Public Key
# Algorithms Registry"). Names are the registry's, verbatim.
ALGORITHM_NAMES: dict[int, str] = {
    1: "RSA (Encrypt or Sign)",
    2: "RSA Encrypt-Only",
    3: "RSA Sign-Only",
    16: "Elgamal (Encrypt-Only)",
    17: "DSA",
    18: "ECDH",
    19: "ECDSA",
    22: "EdDSALegacy",
    25: "X25519",
    26: "X448",
    27: "Ed25519",
    28: "Ed448",
}

# Algorithms whose key size is meaningfully expressed in bits (§7.1.1 Table 9:
# "key length in bits (DSA/RSA/ElGamal keys only)").
_BITLENGTH_ALGORITHMS = frozenset({1, 2, 3, 16, 17})


@dataclass
class UserIDInfo:
    uid: str
    creation: datetime | None = None
    expiration: datetime | None = None
    is_revoked: bool = False


@dataclass
class KeyInfo:
    """A primary key or subkey packet."""

    version: int
    fingerprint: str | None
    creation: datetime | None = None
    expiration: datetime | None = None
    algorithm: int | None = None
    bit_length: int | None = None
    is_revoked: bool = False

    @property
    def algorithm_name(self) -> str | None:
        return ALGORITHM_NAMES.get(self.algorithm) if self.algorithm is not None else None


@dataclass
class CertInfo:
    primary: KeyInfo
    user_ids: list[UserIDInfo] = field(default_factory=list)
    subkeys: list[KeyInfo] = field(default_factory=list)


def _ts(seconds: int) -> datetime | None:
    if seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def rfc3339(value: datetime | None) -> str | None:
    """Render a datetime as an RFC 3339 §5.6 UTC timestamp (``yyyy-mm-ddThh:mm:ssZ``)."""
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mpi_bits(material: bytes) -> int | None:
    """Bit length of the first MPI in a key-material blob (RFC 9580 §3.2)."""
    if len(material) < 2:
        return None
    bits = int.from_bytes(material[0:2], "big")
    return bits or None


def key_fingerprint(body: bytes) -> str | None:
    """Fingerprint of a public key packet body, lowercase hex (RFC 9580 §5.5.4).

    v4 is SHA-1 over ``0x99 || 2-octet length || body``; v6 is SHA-256 over
    ``0x9B || 4-octet length || body``; v5 (draft) uses ``0x9A``.
    """
    if not body:
        return None
    version = body[0]
    if version == 4:
        preimage = b"\x99" + len(body).to_bytes(2, "big") + body
        return hashlib.sha1(preimage).hexdigest()  # noqa: S324 - RFC 9580 mandates SHA-1 here
    if version in (5, 6):
        prefix = b"\x9a" if version == 5 else b"\x9b"
        preimage = prefix + len(body).to_bytes(4, "big") + body
        return hashlib.sha256(preimage).hexdigest()
    return None


def _parse_key_packet(body: bytes) -> KeyInfo | None:
    """Decode the common header of a v4/v5/v6 public key or subkey packet."""
    if len(body) < 6:
        return None
    version = body[0]
    if version not in (4, 5, 6):
        # v3 and unknown versions: report the version only (§7.1 clients must
        # silently ignore primary keys with unknown versions).
        return KeyInfo(version=version, fingerprint=None)
    creation = _ts(int.from_bytes(body[1:5], "big"))
    algorithm = body[5]
    material = body[6:]
    if version in (5, 6):
        if len(material) < 4:
            material = b""
        else:
            declared = int.from_bytes(material[0:4], "big")
            material = material[4 : 4 + declared]
    bit_length = _mpi_bits(material) if algorithm in _BITLENGTH_ALGORITHMS else None
    return KeyInfo(
        version=version,
        fingerprint=key_fingerprint(body),
        creation=creation,
        algorithm=algorithm,
        bit_length=bit_length,
    )


def _subpacket_values(body: bytes) -> dict[int, bytes]:
    """Flatten a signature's hashed+unhashed subpackets; hashed area wins."""
    areas = _signature_subpacket_areas(body)
    if not areas:
        return {}
    hashed, unhashed = areas
    out: dict[int, bytes] = {}
    for stype, sbody in _iter_subpackets(unhashed):
        out.setdefault(stype, sbody)
    for stype, sbody in _iter_subpackets(hashed):
        out[stype] = sbody
    return out


def _u32(value: bytes | None) -> int | None:
    if not value or len(value) < 4:
        return None
    return int.from_bytes(value[0:4], "big")


def parse_cert_info(binary: bytes) -> CertInfo | None:
    """Parse a single non-armored certificate into indexable metadata.

    Returns ``None`` if the packet stream does not start with a public key
    packet. Only the first certificate in a bundle is described.
    """
    try:
        packets = iter_packets(binary)
    except ValueError:
        return None
    if not packets or packets[0][0] != _TAG_PUBLIC_KEY:
        return None

    primary = _parse_key_packet(packets[0][2])
    if primary is None:
        return None
    info = CertInfo(primary=primary)
    primary_fpr = primary.fingerprint or ""

    # "current" is whatever component the following signature packets bind to.
    current_uid: UserIDInfo | None = None
    current_subkey: KeyInfo | None = None

    for tag, _hdr_len, body, _start, _end in packets[1:]:
        if tag == _TAG_PUBLIC_KEY:
            break  # start of the next certificate in the bundle
        if tag == _TAG_USER_ID:
            current_uid = UserIDInfo(uid=body.decode("utf-8", errors="replace"))
            current_subkey = None
            info.user_ids.append(current_uid)
            continue
        if tag == _TAG_USER_ATTRIBUTE:
            current_uid = None
            current_subkey = None
            continue
        if tag == _TAG_PUBLIC_SUBKEY:
            current_uid = None
            current_subkey = _parse_key_packet(body)
            if current_subkey is not None:
                info.subkeys.append(current_subkey)
            continue
        if tag != _TAG_SIGNATURE or len(body) < 2 or body[0] not in (4, 5, 6):
            continue

        sig_type = body[1]
        subs = _subpacket_values(body)
        sig_created = _ts(_u32(subs.get(_SUB_SIG_CREATION)) or 0)
        is_self = _issuer_is_self(_signature_issuer(body), primary_fpr) if primary_fpr else False

        if sig_type == _SIG_KEY_REVOCATION and is_self:
            primary.is_revoked = True
        elif sig_type == _SIG_SUBKEY_REVOCATION and current_subkey is not None and is_self:
            current_subkey.is_revoked = True
        elif sig_type == _SIG_CERT_REVOCATION and current_uid is not None and is_self:
            current_uid.is_revoked = True
        elif sig_type in _CERTIFICATION_SIGS and current_uid is not None:
            if is_self:
                if current_uid.creation is None or (
                    sig_created is not None and sig_created < current_uid.creation
                ):
                    # §7.1.1: creation of *the first* signature over the User ID.
                    current_uid.creation = sig_created or current_uid.creation
                sig_expiry = _u32(subs.get(_SUB_SIG_EXPIRATION))
                if sig_expiry and sig_created is not None:
                    current_uid.expiration = sig_created + timedelta(seconds=sig_expiry)
                _apply_key_expiration(primary, subs)
        elif sig_type == _SIG_DIRECT_KEY and is_self:
            _apply_key_expiration(primary, subs)
        elif sig_type == _SIG_SUBKEY_BINDING and current_subkey is not None and is_self:
            _apply_key_expiration(current_subkey, subs)

    return info


def _apply_key_expiration(key: KeyInfo, subs: dict[int, bytes]) -> None:
    """Key Expiration Time is a duration from the *key* creation time (§5.2.3.13)."""
    duration = _u32(subs.get(_SUB_KEY_EXPIRATION))
    if not duration or key.creation is None:
        return
    expires = key.creation + timedelta(seconds=duration)
    if key.expiration is None or expires > key.expiration:
        key.expiration = expires


def is_expired(expiration: datetime | None, *, now: datetime | None = None) -> bool:
    if expiration is None:
        return False
    return expiration <= (now or datetime.now(timezone.utc))
