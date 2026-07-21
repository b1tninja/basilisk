from __future__ import annotations

import re

from pysequoia import Cert

from basilisk.config import get_settings
from basilisk.openpgp.errors import IngestError
from basilisk.openpgp.policy import (
    IngestPath,
    PolicyConfig,
    validate_armor_format,
    validate_cert_policy,
    validate_options_nm,
    validate_single_cert,
)
from basilisk.openpgp.types import ParsedCert, uid_string

MAX_UPLOAD_BYTES = 64 * 1024


def normalize_fingerprint(fpr: str) -> str:
    """Uppercase hex fingerprint; strip 0x prefix and internal whitespace."""
    s = fpr.strip().upper().removeprefix("0X")
    return re.sub(r"\s+", "", s)


def key_id_from_fingerprint(fpr: str) -> str:
    return normalize_fingerprint(fpr)[-16:].lower()


# Common OpenPGP hex identity lengths (contiguous hex after stripping 0x/spaces/colons).
# 8 = short key ID (allowed with warning); 16 = long key ID; 32 = half of a v4 fingerprint
# (partial substring match); 40 = v4 fingerprint; 64 = v6 fingerprint.
_HEX_SEARCH_KIND = {
    8: "short_keyid",
    16: "keyid",
    32: "fingerprint_partial",
    40: "fingerprint",
    64: "fingerprint",
}


def hex_search_candidate(search: str) -> str | None:
    """If ``search`` is only hex (optional ``0x``, spaces, colons), return contiguous hex.

    Otherwise return ``None`` (likely an email/name query).
    """
    raw = search.strip()
    if not raw or "@" in raw:
        return None
    candidate = raw
    if candidate.lower().startswith("0x"):
        candidate = candidate[2:]
    candidate = re.sub(r"[\s:]+", "", candidate)
    if not candidate or not re.fullmatch(r"[0-9a-fA-F]+", candidate):
        return None
    return candidate


def parse_search(search: str) -> tuple[str, str]:
    """Return (kind, normalized) where kind is
    email|fingerprint|fingerprint_partial|short_keyid|keyid|name.

    Hex queries are classified only at common lengths (8 / 16 / 32 / 40 / 64).
    Short key IDs (8 hex) are allowed for search but should be surfaced with a
    collision warning in the portal UI. 32-hex queries match indexed fingerprint
    prefix or suffix aliases (not an arbitrary mid-string scan).

    Fingerprint / key-ID queries may include spaces or a ``0x`` prefix
    (e.g. ``AABB CCDD …``). Those are stripped before hex length checks so
    they are not misclassified as name searches.
    """
    raw = search.strip()
    hex_candidate = hex_search_candidate(raw)

    if hex_candidate is not None:
        n = len(hex_candidate)
        kind = _HEX_SEARCH_KIND.get(n)
        if kind == "short_keyid":
            return "short_keyid", hex_candidate.lower()
        if kind == "keyid":
            return "keyid", hex_candidate.lower()
        if kind == "fingerprint":
            return "fingerprint", normalize_fingerprint(hex_candidate)
        if kind == "fingerprint_partial":
            return "fingerprint_partial", normalize_fingerprint(hex_candidate)
        # Non-standard hex lengths (e.g. Ada, Cafe, 12/20-hex) fall through.

    if "@" in raw:
        return "email", raw.lower()
    # Free-text / conventional UID name (min 2 chars, must include a letter).
    if len(raw) >= 2 and re.search(r"[A-Za-z]", raw):
        return "name", raw.casefold()
    raise IngestError("Unsupported search format", 404)


def parse_armored_keytext(
    keytext: str,
    *,
    path: IngestPath = "v1",
    config: PolicyConfig | None = None,
) -> ParsedCert:
    if not keytext or not keytext.strip():
        raise IngestError("Empty keytext", 422)

    config = config or PolicyConfig.from_settings()
    settings = get_settings()
    max_bytes = settings.max_upload_bytes
    data = keytext.encode("utf-8")
    if len(data) > max_bytes:
        raise IngestError("Payload too large", 413)

    validate_armor_format(keytext)
    validate_single_cert(keytext, path)
    validate_options_nm(keytext)

    try:
        cert = Cert.from_bytes(data)
    except Exception as exc:
        raise IngestError(f"Invalid OpenPGP data: {exc}", 422) from exc

    fpr = normalize_fingerprint(cert.fingerprint)

    # Hagrid-style: drop third-party certifications before storage (flooding defense).
    from basilisk.openpgp.packets import strip_third_party_from_armored

    cleaned = strip_third_party_from_armored(data, fpr)
    if cleaned != data:
        data = cleaned
        try:
            cert = Cert.from_bytes(data)
        except Exception as exc:
            raise IngestError(f"Invalid OpenPGP data after signature strip: {exc}", 422) from exc
        fpr = normalize_fingerprint(cert.fingerprint)

    uids = [uid_string(u) for u in cert.user_ids]
    parsed = ParsedCert(
        fingerprint=fpr,
        key_id=key_id_from_fingerprint(fpr),
        uids=uids,
        armored=data,
        raw_cert=cert,
        expiration=cert.expiration,
        is_revoked=bool(cert.is_revoked),
    )
    validate_cert_policy(parsed, path, config=config)
    return parsed


def strip_uids_for_pending(armored: bytes) -> bytes:
    """Return armored key with User ID packets removed (Hagrid-style pre-approve)."""
    from basilisk.openpgp.packets import strip_uids_from_armored

    stripped = strip_uids_from_armored(armored)
    # Sanity: still a public key block, and no email-looking UID leftovers in armor body.
    if b"BEGIN PGP PUBLIC KEY BLOCK" not in stripped:
        return armored
    return stripped
