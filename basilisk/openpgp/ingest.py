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
    return fpr.upper().removeprefix("0X")


def key_id_from_fingerprint(fpr: str) -> str:
    return normalize_fingerprint(fpr)[-16:].lower()


def parse_search(search: str) -> tuple[str, str]:
    """Return (kind, normalized) where kind is email|fingerprint|keyid."""
    s = search.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    if re.fullmatch(r"[0-9a-fA-F]{40}", s):
        return "fingerprint", normalize_fingerprint(s)
    if re.fullmatch(r"[0-9a-fA-F]{16}", s):
        return "keyid", s.lower()
    if re.fullmatch(r"[0-9a-fA-F]{8}", s):
        raise IngestError("Short key IDs are not supported", 400)
    if "@" in s:
        return "email", s.lower()
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
