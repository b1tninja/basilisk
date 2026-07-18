"""OpenPGP packet helpers (binary strip / armor)."""

from __future__ import annotations

import base64


def dearmor(data: bytes) -> bytes:
    """Return raw OpenPGP binary, accepting armored or binary input."""
    text = data.decode("utf-8", errors="replace")
    if "-----BEGIN PGP" not in text:
        return data
    lines: list[str] = []
    in_body = False
    for line in text.splitlines():
        if line.startswith("-----BEGIN PGP"):
            in_body = True
            continue
        if line.startswith("-----END PGP"):
            break
        if not in_body:
            continue
        if not line or line.startswith("="):
            continue
        lines.append(line.strip())
    return base64.b64decode("".join(lines), validate=False)


def armor_public_key(binary: bytes) -> bytes:
    b64 = base64.b64encode(binary).decode("ascii")
    wrapped = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return (
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
        f"{wrapped}\n"
        "-----END PGP PUBLIC KEY BLOCK-----\n"
    ).encode("utf-8")


def _read_packet(data: bytes, offset: int) -> tuple[int, int, bytes, int] | None:
    """Return (tag, header_len, body, next_offset) or None at EOF."""
    if offset >= len(data):
        return None
    first = data[offset]
    if first & 0x80 == 0:
        raise ValueError("Invalid OpenPGP packet header")
    if first & 0x40:  # new format
        tag = first & 0x3F
        hdr = offset + 1
        if hdr >= len(data):
            raise ValueError("Truncated packet length")
        length_byte = data[hdr]
        if length_byte < 192:
            length = length_byte
            hdr += 1
        elif length_byte < 224:
            if hdr + 1 >= len(data):
                raise ValueError("Truncated packet length")
            length = ((length_byte - 192) << 8) + data[hdr + 1] + 192
            hdr += 2
        elif length_byte == 255:
            if hdr + 4 >= len(data):
                raise ValueError("Truncated packet length")
            length = int.from_bytes(data[hdr + 1 : hdr + 5], "big")
            hdr += 5
        else:
            # Partial body lengths are uncommon for transferred certs; reject.
            raise ValueError("Unsupported partial body length")
        body = data[hdr : hdr + length]
        return tag, hdr - offset, body, hdr + length
    # old format
    tag = (first >> 2) & 0x0F
    length_type = first & 0x03
    hdr = offset + 1
    if length_type == 0:
        length = data[hdr]
        hdr += 1
    elif length_type == 1:
        length = int.from_bytes(data[hdr : hdr + 2], "big")
        hdr += 2
    elif length_type == 2:
        length = int.from_bytes(data[hdr : hdr + 4], "big")
        hdr += 4
    else:
        # Indeterminate: rest of stream
        body = data[hdr:]
        return tag, hdr - offset, body, len(data)
    body = data[hdr : hdr + length]
    return tag, hdr - offset, body, hdr + length


def iter_packets(binary: bytes) -> list[tuple[int, int, bytes, int, int]]:
    """Return list of (tag, header_len, body, start, end) for each packet."""
    out: list[tuple[int, int, bytes, int, int]] = []
    offset = 0
    while True:
        pkt = _read_packet(binary, offset)
        if pkt is None:
            break
        tag, hdr_len, body, nxt = pkt
        out.append((tag, hdr_len, body, offset, nxt))
        offset = nxt
    return out


def count_packets(binary: bytes) -> int:
    return len(iter_packets(binary))


def _iter_subpackets(data: bytes) -> list[tuple[int, bytes]]:
    """Parse OpenPGP signature subpacket area → [(type, body), ...]."""
    packets: list[tuple[int, bytes]] = []
    i = 0
    while i < len(data):
        if data[i] < 192:
            length = data[i]
            i += 1
        elif data[i] < 255:
            if i + 1 >= len(data):
                break
            length = ((data[i] - 192) << 8) + data[i + 1] + 192
            i += 2
        else:
            if i + 4 >= len(data):
                break
            length = int.from_bytes(data[i + 1 : i + 5], "big")
            i += 5
        if length < 1 or i + length > len(data):
            break
        chunk = data[i : i + length]
        i += length
        # Critical bit is high bit of type; mask it off.
        stype = chunk[0] & 0x7F
        packets.append((stype, chunk[1:]))
    return packets


def _signature_subpacket_areas(body: bytes) -> tuple[bytes, bytes] | None:
    """Return (hashed, unhashed) subpacket areas for a v4/v5/v6 signature body."""
    if not body:
        return None
    version = body[0]
    if version not in (4, 5, 6) or len(body) < 6:
        return None
    pos = 4
    if version == 6:
        if len(body) < 8:
            return None
        hashed_len = int.from_bytes(body[pos : pos + 4], "big")
        pos += 4
    else:
        hashed_len = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
    if pos + hashed_len > len(body):
        return None
    hashed = body[pos : pos + hashed_len]
    pos += hashed_len
    if version == 6:
        if pos + 4 > len(body):
            return None
        unhashed_len = int.from_bytes(body[pos : pos + 4], "big")
        pos += 4
    else:
        if pos + 2 > len(body):
            return None
        unhashed_len = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
    unhashed = body[pos : pos + unhashed_len] if pos + unhashed_len <= len(body) else b""
    return hashed, unhashed


def _signature_issuer(body: bytes) -> str | None:
    """Return issuer fingerprint or key ID (hex uppercase), or None."""
    if not body:
        return None
    version = body[0]
    if version == 3:
        # v3: version, type, created(4), keyid(8), ...
        if len(body) < 14:
            return None
        return body[6:14].hex().upper()
    areas = _signature_subpacket_areas(body)
    if not areas:
        return None
    hashed, unhashed = areas

    fingerprint: str | None = None
    key_id: str | None = None
    for stype, sbody in _iter_subpackets(hashed) + _iter_subpackets(unhashed):
        if stype == 33 and len(sbody) >= 21:
            # Issuer Fingerprint: 1 byte key version + fingerprint
            fingerprint = sbody[1:].hex().upper()
        elif stype == 16 and len(sbody) >= 8:
            key_id = sbody[:8].hex().upper()
    return fingerprint or key_id


# RFC 9580 §5.2.3.25 — Key Server Preferences, bit 7 = No-modify
_KEY_SERVER_PREFS = 23
_KEY_SERVER_NO_MODIFY = 0x80
# RFC 9580 §5.2.3.24 — Notation Data
_NOTATION_DATA = 20


def parse_notation_subpacket(body: bytes) -> dict[str, str | bool] | None:
    """Parse a Notation Data subpacket body → name/value dict."""
    if len(body) < 8:
        return None
    flags = int.from_bytes(body[0:4], "big")
    name_len = int.from_bytes(body[4:6], "big")
    value_len = int.from_bytes(body[6:8], "big")
    if 8 + name_len + value_len > len(body):
        return None
    name = body[8 : 8 + name_len].decode("utf-8", errors="replace")
    raw_value = body[8 + name_len : 8 + name_len + value_len]
    human = bool(flags & 0x80000000)
    value = (
        raw_value.decode("utf-8", errors="replace")
        if human
        else raw_value.hex()
    )
    return {
        "name": name,
        "value": value,
        "human_readable": human,
        "critical": False,
    }


def list_self_notations(binary: bytes, primary_fingerprint: str) -> list[dict[str, str | bool]]:
    """Collect Notation Data from self-certifications on the primary key."""
    out: list[dict[str, str | bool]] = []
    for tag, _hdr_len, body, _start, _end in iter_packets(binary):
        if tag != 2 or not body:
            continue
        version = body[0]
        if version not in (4, 5, 6) or len(body) < 2:
            continue
        sig_type = body[1]
        if sig_type not in (0x10, 0x11, 0x12, 0x13, 0x1F):
            continue
        issuer = _signature_issuer(body)
        if not _issuer_is_self(issuer, primary_fingerprint):
            continue
        areas = _signature_subpacket_areas(body)
        if not areas:
            continue
        hashed, unhashed = areas
        for stype, sbody in _iter_subpackets(hashed) + _iter_subpackets(unhashed):
            if stype != _NOTATION_DATA:
                continue
            parsed = parse_notation_subpacket(sbody)
            if parsed:
                out.append(parsed)
    return out


def has_keyserver_no_modify(binary: bytes, primary_fingerprint: str) -> bool:
    """True if a primary self-signature sets Key Server Preferences no-modify (§5.2.3.25)."""
    for tag, _hdr_len, body, _start, _end in iter_packets(binary):
        if tag != 2 or not body:
            continue
        version = body[0]
        if version not in (4, 5, 6) or len(body) < 2:
            continue
        sig_type = body[1]
        if sig_type not in (0x10, 0x11, 0x12, 0x13, 0x1F):
            continue
        issuer = _signature_issuer(body)
        if not _issuer_is_self(issuer, primary_fingerprint):
            continue
        areas = _signature_subpacket_areas(body)
        if not areas:
            continue
        hashed, unhashed = areas
        for stype, sbody in _iter_subpackets(hashed) + _iter_subpackets(unhashed):
            if stype == _KEY_SERVER_PREFS and sbody and (sbody[0] & _KEY_SERVER_NO_MODIFY):
                return True
    return False


def _issuer_is_self(issuer: str | None, primary_fingerprint: str) -> bool:
    if not issuer:
        return False
    fpr = primary_fingerprint.upper().replace(" ", "").removeprefix("0X")
    iss = issuer.upper().replace(" ", "")
    if iss == fpr:
        return True
    # Key ID is trailing 16 hex chars (8 bytes) of v4 fingerprint.
    if len(iss) == 16 and fpr.endswith(iss):
        return True
    if len(iss) == 8 and fpr.endswith(iss):
        return True
    return False


def _issuer_matches_allowlist(issuer: str | None, allowlist: set[str]) -> bool:
    """True if issuer fingerprint or key ID matches an allowlisted fingerprint/key ID."""
    if not issuer or not allowlist:
        return False
    iss = issuer.upper().replace(" ", "")
    if iss in allowlist:
        return True
    for item in allowlist:
        fpr = item.upper().replace(" ", "")
        if len(iss) == 16 and fpr.endswith(iss):
            return True
        if len(iss) == 8 and fpr.endswith(iss):
            return True
        if len(fpr) == 16 and iss.endswith(fpr):
            return True
    return False


def strip_third_party_sigs(
    binary: bytes,
    primary_fingerprint: str,
    *,
    allowlist: set[str] | frozenset[str] | None = None,
) -> bytes:
    """Keep self-signatures and optionally allowlisted third-party certifications.

    Drops third-party certifications used for certificate-flooding attacks unless
    the issuer is in ``allowlist`` (approved keys on this server). Signatures with
    no identifiable issuer are dropped (fail closed).
    """
    allowed = {a.upper().replace(" ", "") for a in (allowlist or set()) if a}
    out = bytearray()
    for tag, _hdr_len, body, start, end in iter_packets(binary):
        raw = binary[start:end]
        if tag == 2:
            issuer = _signature_issuer(body)
            if _issuer_is_self(issuer, primary_fingerprint):
                out.extend(raw)
                continue
            if _issuer_matches_allowlist(issuer, allowed):
                # Prefer issuer fingerprint subpackets for allowlisted retention.
                out.extend(raw)
                continue
            continue
        out.extend(raw)
    return bytes(out)


# Tags: 2=Signature, 6=Public-Key, 13=User ID, 14=Public-Subkey, 17=User Attribute
_SKIP_WITH_SIGS = {13, 17}
_STOP_SKIP = {6, 14, 13, 17}


def strip_uid_packets(binary: bytes) -> bytes:
    """Remove User ID / User Attribute packets and their certification signatures."""
    out = bytearray()
    offset = 0
    skipping_sigs = False
    while True:
        pkt = _read_packet(binary, offset)
        if pkt is None:
            break
        tag, _hdr_len, body, nxt = pkt
        raw = binary[offset:nxt]
        offset = nxt
        if tag in _SKIP_WITH_SIGS:
            skipping_sigs = True
            continue
        if skipping_sigs:
            if tag == 2:
                continue
            if tag in _STOP_SKIP or tag not in (2,):
                skipping_sigs = False
                if tag in _SKIP_WITH_SIGS:
                    skipping_sigs = True
                    continue
        out.extend(raw)
    return bytes(out)


def strip_uids_from_armored(armored: bytes) -> bytes:
    """Strip UIDs from an armored (or binary) public key and return armored bytes."""
    try:
        binary = dearmor(armored)
        stripped = strip_uid_packets(binary)
        if not stripped:
            return armored
        return armor_public_key(stripped)
    except Exception:
        return armored


def strip_third_party_from_armored(
    armored: bytes,
    primary_fingerprint: str,
    *,
    allowlist: set[str] | frozenset[str] | None = None,
) -> bytes:
    """Strip third-party signatures from armored public key; return armored bytes."""
    try:
        binary = dearmor(armored)
        cleaned = strip_third_party_sigs(
            binary, primary_fingerprint, allowlist=allowlist
        )
        if not cleaned:
            return armored
        return armor_public_key(cleaned)
    except Exception:
        return armored


def list_third_party_certifications(
    binary: bytes, primary_fingerprint: str
) -> list[dict[str, str | None]]:
    """Return third-party certification packets (issuer + optional UID context).

    Walks packets; associates signature packets with the most recent User ID.
    """
    out: list[dict[str, str | None]] = []
    current_uid: str | None = None
    for tag, _hdr_len, body, _start, _end in iter_packets(binary):
        if tag == 13:
            try:
                current_uid = body.decode("utf-8", errors="replace")
            except Exception:
                current_uid = None
            continue
        if tag == 14:
            current_uid = None
            continue
        if tag != 2 or not body:
            continue
        version = body[0]
        if version not in (3, 4, 5, 6):
            continue
        # Certification signature types: 0x10–0x13
        sig_type = body[1] if version >= 4 else (body[2] if len(body) > 2 else None)
        if version == 3:
            if len(body) < 3:
                continue
            sig_type = body[1]
        if sig_type not in (0x10, 0x11, 0x12, 0x13):
            continue
        issuer = _signature_issuer(body)
        if _issuer_is_self(issuer, primary_fingerprint):
            continue
        if not issuer:
            continue
        out.append(
            {
                "signer_fingerprint": issuer if len(issuer) >= 40 else None,
                "signer_key_id": issuer if len(issuer) < 40 else issuer[-16:],
                "uid": current_uid,
            }
        )
    return out
