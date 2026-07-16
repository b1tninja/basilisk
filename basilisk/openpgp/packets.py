"""OpenPGP packet helpers (binary strip / armor)."""

from __future__ import annotations

import base64
import re


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
