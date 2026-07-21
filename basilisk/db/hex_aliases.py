"""Indexed hex identity aliases for O(1) / partition-key lookups.

Avoids full-table ``LIKE '%…%'`` scans for short key IDs and half-fingerprint
queries. Stores index:

* ``fingerprint`` — full v4/v6 fingerprint (unique)
* ``keyid`` — 16-hex long key ID (unique in practice)
* ``short_keyid`` — last 8 hex (multi-valued; collisions expected)
* ``fpr32_prefix`` / ``fpr32_suffix`` — first/last 32 hex of the fingerprint
  (multi-valued; used for 32-hex "partial fingerprint" search)
"""

from __future__ import annotations

UNIQUE_ID_TYPES = frozenset({"fingerprint", "keyid"})
MULTI_ID_TYPES = frozenset({"short_keyid", "fpr32_prefix", "fpr32_suffix"})


def normalize_key_id(key_id: str) -> str:
    return (key_id or "").lower().removeprefix("0x")


def normalize_fingerprint(fpr: str) -> str:
    return (fpr or "").upper().removeprefix("0X")


def hex_aliases(fingerprint: str, key_id: str) -> list[tuple[str, str]]:
    """Return ``(identifier, id_type)`` rows to write for a cert.

    Unique types (``fingerprint``, ``keyid``) map 1:1. Multi types may map
    several fingerprints to the same identifier and must be stored with a
    composite key that includes the fingerprint.
    """
    fpr = normalize_fingerprint(fingerprint)
    if not fpr:
        return []
    kid = normalize_key_id(key_id) or fpr[-16:].lower()
    short = (kid[-8:] if len(kid) >= 8 else fpr[-8:]).lower()
    out: list[tuple[str, str]] = [
        (fpr, "fingerprint"),
        (kid, "keyid"),
        (short, "short_keyid"),
    ]
    if len(fpr) >= 32:
        out.append((fpr[:32].lower(), "fpr32_prefix"))
        out.append((fpr[-32:].lower(), "fpr32_suffix"))
    return out


def id_types_for_needle(hex_needle: str) -> tuple[str, ...]:
    """id_types to look up for an 8- or 32-hex search needle; empty if unsupported."""
    n = len(hex_needle or "")
    if n == 8:
        return ("short_keyid",)
    if n == 32:
        return ("fpr32_prefix", "fpr32_suffix")
    return ()


def normalize_hex_needle(hex_query: str) -> str:
    """Contiguous lowercase hex for alias lookup, or ``\"\"`` if not pure hex.

    Strips optional ``0x``, spaces, and colons. Rejects any other characters so
    callers never interpolate untrusted text into queries.
    """
    import re

    s = (hex_query or "").strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    s = re.sub(r"[\s:]+", "", s)
    if not s or not re.fullmatch(r"[0-9a-fA-F]+", s):
        return ""
    return s.lower()
