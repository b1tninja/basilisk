"""Web Key Directory (WKD) helpers — RFC 7929 / draft-koch-openpgp-webkey-service."""

from __future__ import annotations

import hashlib
import re

# Z-Base32 alphabet (RFC 6189 §5.1.6)
_ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769"


def zbase32_encode(data: bytes) -> str:
    """Encode bytes as z-base32 (used for WKD hashes)."""
    bits = 0
    value = 0
    out: list[str] = []
    for byte in data:
        value = (value << 8) | byte
        bits += 8
        while bits >= 5:
            out.append(_ZBASE32[(value >> (bits - 5)) & 31])
            bits -= 5
    if bits:
        out.append(_ZBASE32[(value << (5 - bits)) & 31])
    return "".join(out)


def wkd_local_hash(local_part: str) -> str:
    """SHA-1 of the lowercase local-part, z-base32 encoded (28 chars)."""
    digest = hashlib.sha1(local_part.lower().encode("utf-8")).digest()
    return zbase32_encode(digest)


def parse_email(email: str) -> tuple[str, str] | None:
    email = email.strip().lower()
    if "@" not in email or email.count("@") != 1:
        return None
    local, domain = email.split("@", 1)
    if not local or not domain or not re.fullmatch(r"[a-z0-9._+\-]+", local):
        return None
    return local, domain
