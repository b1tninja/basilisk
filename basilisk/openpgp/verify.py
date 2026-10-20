"""Verify OpenPGP signatures before trusting them.

Issuer subpackets are not evidence. A signature packet can name any key in its
hashed area, and anything can be appended to the unhashed area without
invalidating a real signature. A certification is kept only when it verifies
under a key we already have: the certificate's own primary key, or a signer
whose public key was passed in explicitly.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from basilisk.openpgp.packets import (
    _iter_subpackets,
    _signature_subpacket_areas,
    iter_packets,
)

# RFC 9580 §9.1 / §9.5.
_RSA_ALGOS = frozenset({1, 3})
_ED25519_ALGOS = frozenset({22, 27})  # EdDSALegacy, Ed25519
_HASHES = {
    2: hashes.SHA1,
    8: hashes.SHA256,
    9: hashes.SHA384,
    10: hashes.SHA512,
    11: hashes.SHA224,
    12: hashes.SHA3_256,
    14: hashes.SHA3_512,
}
_CERTIFICATION = frozenset({0x10, 0x11, 0x12, 0x13, 0x30})
_PRIMARY_SIGNED = _CERTIFICATION | frozenset({0x1F, 0x20, 0x18, 0x28})
_KEY_SERVER_PREFS = 23
_KEY_SERVER_NO_MODIFY = 0x80
_NOTATION = 20


def _digest(alg: int, data: bytes) -> bytes:
    cls = _HASHES.get(alg)
    if cls is None:
        raise ValueError(f"unsupported hash algorithm {alg}")
    hasher = hashlib.new(_hashlib_name(alg))
    hasher.update(data)
    return hasher.digest()


def _hashlib_name(alg: int) -> str:
    return {
        2: "sha1",
        8: "sha256",
        9: "sha384",
        10: "sha512",
        11: "sha224",
        12: "sha3_256",
        14: "sha3_512",
    }[alg]


def _read_mpi(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated MPI")
    bits = int.from_bytes(data[offset : offset + 2], "big")
    nbytes = (bits + 7) // 8
    start = offset + 2
    end = start + nbytes
    if bits < 0 or end > len(data):
        raise ValueError("truncated MPI")
    return data[start:end], end


def _mpi_int(data: bytes, offset: int) -> tuple[int, int]:
    raw, end = _read_mpi(data, offset)
    return int.from_bytes(raw, "big"), end


def frame_key(body: bytes) -> bytes:
    """The key-packet octets that go into a signature hash (RFC 9580 §5.2.4)."""
    if not body:
        raise ValueError("empty key packet")
    version = body[0]
    if version in (4, 5):
        return b"\x99" + len(body).to_bytes(2, "big") + body
    if version == 6:
        return b"\x9b" + len(body).to_bytes(4, "big") + body
    raise ValueError(f"unsupported key version {version}")


def frame_uid(body: bytes) -> bytes:
    return b"\xb4" + len(body).to_bytes(4, "big") + body


def frame_uat(body: bytes) -> bytes:
    return b"\xd1" + len(body).to_bytes(4, "big") + body


def _hashed_region(sig_body: bytes) -> tuple[bytes, int]:
    """Return (bytes from version through hashed subpackets, offset after them)."""
    version = sig_body[0]
    if version == 4:
        if len(sig_body) < 6:
            raise ValueError("truncated v4 signature")
        hashed_len = int.from_bytes(sig_body[4:6], "big")
        end = 6 + hashed_len
    elif version == 6:
        if len(sig_body) < 8:
            raise ValueError("truncated v6 signature")
        hashed_len = int.from_bytes(sig_body[4:8], "big")
        end = 8 + hashed_len
    else:
        raise ValueError(f"unsupported signature version {version}")
    if end > len(sig_body):
        raise ValueError("truncated hashed subpackets")
    return sig_body[:end], end


def _salt_and_material(sig_body: bytes) -> tuple[bytes, bytes]:
    """Return (salt, raw signature material) after the unhashed area."""
    version = sig_body[0]
    _, pos = _hashed_region(sig_body)
    if version == 4:
        if pos + 2 > len(sig_body):
            raise ValueError("truncated v4 signature")
        unhashed_len = int.from_bytes(sig_body[pos : pos + 2], "big")
        pos += 2 + unhashed_len
        if pos + 2 > len(sig_body):
            raise ValueError("truncated v4 signature")
        pos += 2  # leftmost hash octets
        return b"", sig_body[pos:]
    if pos + 4 > len(sig_body):
        raise ValueError("truncated v6 signature")
    unhashed_len = int.from_bytes(sig_body[pos : pos + 4], "big")
    pos += 4 + unhashed_len
    if pos + 3 > len(sig_body):
        raise ValueError("truncated v6 signature")
    pos += 2
    salt_len = sig_body[pos]
    pos += 1
    if pos + salt_len > len(sig_body):
        raise ValueError("truncated v6 salt")
    salt = sig_body[pos : pos + salt_len]
    return salt, sig_body[pos + salt_len :]


def signature_preimage(sig_body: bytes, signed: bytes) -> bytes:
    """Hash preimage for ``signed`` data under this signature packet."""
    version = sig_body[0]
    hashed, _end = _hashed_region(sig_body)
    if version == 4:
        trailer = bytes([4, 0xFF]) + len(hashed).to_bytes(4, "big")
        return signed + hashed + trailer
    salt, _material = _salt_and_material(sig_body)
    trailer = bytes([6, 0xFF]) + len(hashed).to_bytes(4, "big")
    return salt + signed + hashed + trailer


def _ed25519_point(key_body: bytes) -> bytes:
    algo = key_body[5]
    if key_body[0] in (4, 5) and algo == 22:
        oid_len = key_body[6]
        rest = key_body[7 + oid_len :]
        mpi, _end = _read_mpi(rest, 0)
        if mpi.startswith(b"\x40"):
            mpi = mpi[1:]
        if len(mpi) != 32:
            raise ValueError("Ed25519 point is not 32 bytes")
        return mpi
    if key_body[0] == 6 and algo == 27:
        param_len = int.from_bytes(key_body[6:10], "big")
        point = key_body[10 : 10 + param_len]
        if len(point) != 32:
            raise ValueError("Ed25519 point is not 32 bytes")
        return point
    raise ValueError(f"not an Ed25519 key (version {key_body[0]} algo {algo})")


def _ed25519_signature(sig_body: bytes) -> bytes:
    _salt, material = _salt_and_material(sig_body)
    algo = sig_body[2]
    if algo == 27:
        if len(material) != 64:
            raise ValueError("Ed25519 signature is not 64 bytes")
        return material

    def _fit(raw: bytes) -> bytes:
        return raw.lstrip(b"\x00").rjust(32, b"\x00")

    r, offset = _read_mpi(material, 0)
    s, offset = _read_mpi(material, offset)
    if offset != len(material):
        raise ValueError("trailing data in EdDSA signature")
    signature = _fit(r) + _fit(s)
    if len(signature) != 64:
        raise ValueError("EdDSA signature is not 64 bytes")
    return signature


def _rsa_public(key_body: bytes) -> rsa.RSAPublicKey:
    if key_body[0] not in (4, 5) or key_body[5] not in _RSA_ALGOS:
        raise ValueError("not a v4/v5 RSA key")
    n, offset = _mpi_int(key_body, 6)
    e, _offset = _mpi_int(key_body, offset)
    if n.bit_length() < 512 or e <= 1:
        raise ValueError("implausible RSA key")
    return rsa.RSAPublicNumbers(e, n).public_key()


def _rsa_signature(sig_body: bytes, modulus_bits: int) -> bytes:
    _salt, material = _salt_and_material(sig_body)
    value, offset = _mpi_int(material, 0)
    if offset != len(material):
        raise ValueError("trailing data in RSA signature")
    width = (modulus_bits + 7) // 8
    if value.bit_length() > modulus_bits:
        raise ValueError("RSA signature larger than modulus")
    return value.to_bytes(width, "big")


def signature_verifies(sig_body: bytes, signed: bytes, signer_key_body: bytes) -> bool:
    """True when ``sig_body`` is a valid signature by ``signer_key_body`` over ``signed``."""
    try:
        if not sig_body or not signer_key_body or len(sig_body) < 6:
            return False
        if sig_body[0] not in (4, 6):
            return False
        preimage = signature_preimage(sig_body, signed)
        hash_alg = sig_body[3]
        digest = _digest(hash_alg, preimage)
        # Walk the packet once so a truncated signature fails closed here.
        _salt, _material = _salt_and_material(sig_body)
        # The two octets stored in the signature are the left 16 bits of that hash.
        left = _hash_prefix(sig_body)
        if left != digest[:2]:
            return False
        algo = sig_body[2]
        if algo in _RSA_ALGOS:
            if signer_key_body[5] not in _RSA_ALGOS:
                return False
            public = _rsa_public(signer_key_body)
            signature = _rsa_signature(sig_body, public.key_size)
            public.verify(signature, preimage, PKCS1v15(), _HASHES[hash_alg]())
            return True
        if algo in _ED25519_ALGOS:
            if signer_key_body[5] not in _ED25519_ALGOS:
                return False
            point = _ed25519_point(signer_key_body)
            signature = _ed25519_signature(sig_body)
            Ed25519PublicKey.from_public_bytes(point).verify(signature, digest)
            return True
        return False
    except (ValueError, InvalidSignature, KeyError):
        return False


def _hash_prefix(sig_body: bytes) -> bytes:
    _hashed, pos = _hashed_region(sig_body)
    version = sig_body[0]
    if version == 4:
        unhashed_len = int.from_bytes(sig_body[pos : pos + 2], "big")
        pos += 2 + unhashed_len
    else:
        unhashed_len = int.from_bytes(sig_body[pos : pos + 4], "big")
        pos += 4 + unhashed_len
    return sig_body[pos : pos + 2]


def signed_data(
    sig_body: bytes,
    primary_body: bytes,
    uid_body: bytes | None,
    subkey_body: bytes | None,
    uat_body: bytes | None,
) -> bytes | None:
    """The data this signature type covers, or None when the context is missing."""
    if len(sig_body) < 2:
        return None
    sig_type = sig_body[1]
    if sig_type in _CERTIFICATION:
        if uid_body is not None:
            return frame_key(primary_body) + frame_uid(uid_body)
        if uat_body is not None:
            return frame_key(primary_body) + frame_uat(uat_body)
        return None
    if sig_type in (0x1F, 0x20):
        return frame_key(primary_body)
    if sig_type in (0x18, 0x19, 0x28):
        if subkey_body is None:
            return None
        return frame_key(primary_body) + frame_key(subkey_body)
    return None


def is_verified_self_signature(
    sig_body: bytes,
    primary_body: bytes,
    uid_body: bytes | None = None,
    subkey_body: bytes | None = None,
    uat_body: bytes | None = None,
) -> bool:
    """True when this packet verifies under the primary key (or the subkey, for 0x19)."""
    signed = signed_data(sig_body, primary_body, uid_body, subkey_body, uat_body)
    if signed is None or len(sig_body) < 2:
        return False
    signer = subkey_body if sig_body[1] == 0x19 else primary_body
    if signer is None:
        return False
    return signature_verifies(sig_body, signed, signer)


def hashed_subpackets(sig_body: bytes) -> list[tuple[int, bytes]]:
    areas = _signature_subpacket_areas(sig_body)
    if not areas:
        return []
    hashed, _unhashed = areas
    return _iter_subpackets(hashed)


def drop_unverified_signatures(
    binary: bytes,
    primary_fingerprint: str,
    *,
    signer_keys: dict[str, bytes] | None = None,
) -> bytes:
    """Drop signature packets that do not verify under an allowed key.

    Self-signatures must verify under the primary key in this certificate.
    Any other signature is dropped unless ``signer_keys`` contains the signer's
    primary-key packet body and the signature verifies under that key.
    ``primary_fingerprint`` is accepted so callers keep a stable signature; the
    bytes of the primary key, not the fingerprint string, decide.
    """
    del primary_fingerprint  # verification uses the key packet, not the hex string
    packets = iter_packets(binary)
    if not packets or packets[0][0] != 6:
        raise ValueError("certificate does not start with a public-key packet")
    primary_body = packets[0][2]
    extras = {k.upper(): v for k, v in (signer_keys or {}).items()}
    uid_body: bytes | None = None
    uat_body: bytes | None = None
    subkey_body: bytes | None = None
    out = bytearray()
    for tag, _hdr, body, start, end in packets:
        raw = binary[start:end]
        if tag == 6:
            out.extend(raw)
            continue
        if tag == 13:
            uid_body, uat_body, subkey_body = body, None, None
            out.extend(raw)
            continue
        if tag == 17:
            uid_body, uat_body, subkey_body = None, body, None
            out.extend(raw)
            continue
        if tag == 14:
            uid_body, uat_body, subkey_body = None, None, body
            out.extend(raw)
            continue
        if tag != 2:
            out.extend(raw)
            continue
        signed = signed_data(body, primary_body, uid_body, subkey_body, uat_body)
        if signed is not None and is_verified_self_signature(
            body, primary_body, uid_body, subkey_body, uat_body
        ):
            out.extend(raw)
            continue
        if signed is not None and _verifies_with_any(body, signed, extras):
            out.extend(raw)
            continue
        # Not a self-signature and not an attested one: drop it.
    return bytes(out)


def _verifies_with_any(sig_body: bytes, signed: bytes, signer_keys: dict[str, bytes]) -> bool:
    if sig_body[1] not in _CERTIFICATION:
        return False
    for key_body in signer_keys.values():
        if signature_verifies(sig_body, signed, key_body):
            return True
    return False


def self_signature_has_no_modify(binary: bytes, primary_fingerprint: str) -> bool:
    """True when a *verified* self-signature carries no-modify in the hashed area.

    Key Server Preferences in the unhashed area are ignored: anyone can append
    them to a valid signature.
    """
    del primary_fingerprint
    packets = iter_packets(binary)
    if not packets or packets[0][0] != 6:
        return False
    primary_body = packets[0][2]
    uid_body: bytes | None = None
    uat_body: bytes | None = None
    subkey_body: bytes | None = None
    for tag, _hdr, body, _start, _end in packets:
        if tag == 13:
            uid_body, uat_body, subkey_body = body, None, None
            continue
        if tag == 17:
            uid_body, uat_body, subkey_body = None, body, None
            continue
        if tag == 14:
            uid_body, uat_body, subkey_body = None, None, body
            continue
        if tag != 2 or len(body) < 2 or body[1] not in (0x10, 0x11, 0x12, 0x13, 0x1F):
            continue
        if not is_verified_self_signature(body, primary_body, uid_body, subkey_body, uat_body):
            continue
        for stype, sbody in hashed_subpackets(body):
            if stype == _KEY_SERVER_PREFS and sbody and (sbody[0] & _KEY_SERVER_NO_MODIFY):
                return True
    return False


def verified_self_notations(binary: bytes, primary_fingerprint: str) -> list[dict[str, str | bool]]:
    """Notation Data from the hashed area of verified self-certifications."""
    from basilisk.openpgp.packets import parse_notation_subpacket

    del primary_fingerprint
    packets = iter_packets(binary)
    if not packets or packets[0][0] != 6:
        return []
    primary_body = packets[0][2]
    uid_body: bytes | None = None
    uat_body: bytes | None = None
    subkey_body: bytes | None = None
    out: list[dict[str, str | bool]] = []
    for tag, _hdr, body, _start, _end in packets:
        if tag == 13:
            uid_body, uat_body, subkey_body = body, None, None
            continue
        if tag == 17:
            uid_body, uat_body, subkey_body = None, body, None
            continue
        if tag == 14:
            uid_body, uat_body, subkey_body = None, None, body
            continue
        if tag != 2 or len(body) < 2 or body[1] not in (0x10, 0x11, 0x12, 0x13, 0x1F):
            continue
        if not is_verified_self_signature(body, primary_body, uid_body, subkey_body, uat_body):
            continue
        for stype, sbody in hashed_subpackets(body):
            if stype != _NOTATION:
                continue
            parsed = parse_notation_subpacket(sbody)
            if parsed:
                out.append(parsed)
    return out


def primary_key_body(data: bytes) -> bytes:
    """Primary key packet body from armored or binary certificate bytes."""
    from basilisk.openpgp.packets import dearmor

    binary = dearmor(data)
    packets = iter_packets(binary)
    if not packets or packets[0][0] != 6:
        raise ValueError("no public-key packet")
    return packets[0][2]
