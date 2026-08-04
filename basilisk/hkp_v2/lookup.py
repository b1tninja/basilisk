"""HKP v2 lookups (draft-gallagher-openpgp-hkp-10 §5.1).

The v2 API returns non-armored certificate bundles exclusively (§9), so every
response here dearmors the stored blob and sets
``Content-Type: application/pgp-keys;armor=no`` (§7.1).
"""

from __future__ import annotations

import re

from basilisk.config import Settings, get_settings
from basilisk.db.blob_store import LocalBlobStore
from basilisk.db.factory import get_blob_store as _factory_blob
from basilisk.db.factory import get_cert_store
from basilisk.db.store import CertRecord, CertStore
from basilisk.hkp.cors import cors_get_headers
from basilisk.hkp.response import HttpResponse
from basilisk.openpgp.canonical import parse_uid_parts
from basilisk.openpgp.ingest import normalize_fingerprint, strip_uids_for_pending
from basilisk.openpgp.keyinfo import parse_cert_info
from basilisk.openpgp.packets import dearmor

# §5 of I-D.gallagher-openpgp-media-types, required by §7.1.
V2_MEDIA_TYPE = "application/pgp-keys;armor=no"
JSON_MEDIA_TYPE = "application/json"

# Confidence (§8): 120+ means "complete". A UID reaches that here only after
# mailbox-proven approval; everything else is 0.
CONFIDENCE_APPROVED = 120
CONFIDENCE_UNVERIFIED = 0

# §5.1.1 / §5.1.5: "A keyserver SHOULD limit the returned bundle/index to a
# reasonable length."
MAX_BUNDLE_CERTS = 20

_ANGLE_SPAN = re.compile(r"<([^<>]*)>")
_LOOKS_LIKE_EMAIL = re.compile(r"^[^<>\s@]+@[^<>\s@]+$")


def v2_response(
    status: int,
    body: bytes | str,
    *,
    mimetype: str = "text/plain",
    extra: dict[str, str] | None = None,
) -> HttpResponse:
    """Build a v2 response. §7.1 makes ``Access-Control-Allow-Origin: *`` a MUST."""
    return HttpResponse(status, body, cors_get_headers(extra), mimetype)


def uid_matches_identity(uid: str, identity: str) -> bool:
    """§5.1.9 exact identity match against a single User ID string.

    A match requires either the text between angle brackets of an
    email-address style User ID, or the full text of a non-email User ID.
    Matching is case-insensitive ("Text lookups SHOULD NOT be case
    sensitive"). If more than one substring could reasonably be read as an
    email address the User ID is treated as ambiguous and never matches
    ("a keyserver SHOULD NOT return an identity match on either substring").
    """
    needle = (identity or "").strip().casefold()
    raw = (uid or "").strip()
    if not needle or not raw:
        return False

    candidates = [s.strip() for s in _ANGLE_SPAN.findall(raw)]
    emails = [c for c in candidates if _LOOKS_LIKE_EMAIL.match(c)]
    if len(emails) > 1:
        return False
    if emails:
        return emails[0].casefold() == needle
    bare = parse_uid_parts(raw)["email"]
    if bare:
        return bare.casefold() == needle
    return raw.casefold() == needle


def record_matches_identity(record: CertRecord, identity: str) -> bool:
    return any(uid_matches_identity(uid, identity) for uid in record.approved_uids or [])


def _confidence(record: CertRecord, identity: str) -> int:
    if record.approval_state != "approved":
        return CONFIDENCE_UNVERIFIED
    return CONFIDENCE_APPROVED if record_matches_identity(record, identity) else CONFIDENCE_UNVERIFIED


def records_for_identity(
    identity: str,
    store: CertStore | None = None,
    *,
    limit: int = MAX_BUNDLE_CERTS,
) -> list[CertRecord]:
    """Approved certs whose User IDs exactly match ``identity`` (§5.1.9).

    Sorted by decreasing confidence, then creation date most recent first
    (§5.1.1, §5.1.5).
    """
    store = store or get_cert_store()
    ident = (identity or "").strip()
    if not ident:
        return []

    candidates: list[CertRecord] = []
    seen: set[str] = set()
    source = store.list_by_email(ident.lower()) if "@" in ident else store.list_by_name(ident)
    for record in source:
        if record.fingerprint in seen:
            continue
        seen.add(record.fingerprint)
        # list_by_email also matches the portal claimer address, which is not a
        # User ID; §5.1.9 permits a match only on User ID contents.
        if record.approval_state == "approved" and record_matches_identity(record, ident):
            candidates.append(record)

    # Stable sorts applied least-significant first: creation date descending,
    # then confidence descending.
    candidates.sort(key=lambda r: r.created_at or "", reverse=True)
    candidates.sort(key=lambda r: _confidence(r, ident), reverse=True)
    return candidates[:limit]


def read_binary(record: CertRecord, blobs: LocalBlobStore) -> bytes:
    """Stored blobs are ASCII-armored; v2 serves the raw packet stream (§9)."""
    data = blobs.read(record.blob_uri)
    if record.approval_state != "approved":
        data = strip_uids_for_pending(data)
    return dearmor(data)


def _bundle(records: list[CertRecord], blobs: LocalBlobStore) -> bytes:
    """Concatenate certificates directly, as specified in §9."""
    out = bytearray()
    for record in records:
        try:
            out.extend(read_binary(record, blobs))
        except Exception:  # noqa: BLE001 - a bad blob must not fail the whole bundle
            continue
    return bytes(out)


def resolve_stores(
    store: CertStore | None, blobs: LocalBlobStore | None, settings: Settings | None
) -> tuple[CertStore, LocalBlobStore, Settings]:
    settings = settings or get_settings()
    return (
        store or get_cert_store(settings),
        blobs or _factory_blob(settings),
        settings,
    )


def certs_by_identity(
    identity: str,
    store: CertStore | None = None,
    blobs: LocalBlobStore | None = None,
    settings: Settings | None = None,
) -> HttpResponse:
    """§5.1.1 — bundle of certificates whose User IDs match ``identity``."""
    store, blobs, settings = resolve_stores(store, blobs, settings)
    records = records_for_identity(identity, store)
    if not records:
        return v2_response(404, "Not found")
    body = _bundle(records, blobs)
    if not body:
        return v2_response(404, "Not found")
    return v2_response(200, body, mimetype=V2_MEDIA_TYPE)


def canonical_bundle(
    identity: str,
    store: CertStore | None = None,
    blobs: LocalBlobStore | None = None,
    settings: Settings | None = None,
) -> HttpResponse:
    """§5.1.4 — the canonical bundle for ``identity``, or 404.

    A certificate becomes canonical for an identity here when its owner proves
    control of that mailbox and the matching User IDs are approved (§5.2.3).
    """
    return certs_by_identity(identity, store, blobs, settings)


def parse_vfingerprint(identifier: str) -> tuple[int, str] | None:
    """Split a versioned fingerprint into ``(version, fingerprint_hex)`` (§5.1.2).

    A versioned fingerprint is one octet of fingerprint version followed by N
    octets of fingerprint, hex-encoded without a leading ``0x``.
    """
    raw = (identifier or "").strip()
    if raw.lower().startswith("0x"):
        # §5.1.2 says "without a preceding 0x"; reject rather than guess.
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", raw) or len(raw) % 2:
        return None
    version = int(raw[0:2], 16)
    fingerprint = raw[2:]
    expected = {4: 40, 5: 64, 6: 64}.get(version)
    if expected is None or len(fingerprint) != expected:
        return None
    return version, fingerprint.upper()


def certs_by_vfingerprint(
    identifier: str,
    store: CertStore | None = None,
    blobs: LocalBlobStore | None = None,
    settings: Settings | None = None,
) -> HttpResponse:
    """§5.1.2 — certificate identified by versioned fingerprint."""
    store, blobs, settings = resolve_stores(store, blobs, settings)
    parsed = parse_vfingerprint(identifier)
    if parsed is None:
        return v2_response(404, "Not found")
    version, fingerprint = parsed
    record = store.get_by_fingerprint(normalize_fingerprint(fingerprint))
    if record is None or record.approval_state in ("expired", "rejected"):
        return v2_response(404, "Not found")
    body = read_binary(record, blobs)
    info = parse_cert_info(body)
    if info is None or info.primary.version != version:
        return v2_response(404, "Not found")
    return v2_response(200, body, mimetype=V2_MEDIA_TYPE)


def certs_by_keyid(
    identifier: str,
    store: CertStore | None = None,
    blobs: LocalBlobStore | None = None,
    settings: Settings | None = None,
) -> HttpResponse:
    """§5.1.3 — certificate identified by 64-bit Key ID.

    "certificates with versions greater than 4 MUST NOT be returned in
    response to a certs/by-keyid request."
    """
    store, blobs, settings = resolve_stores(store, blobs, settings)
    raw = (identifier or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{16}", raw):
        return v2_response(404, "Not found")
    record = store.get_by_identifier(raw.lower())
    if record is None or record.approval_state in ("expired", "rejected"):
        return v2_response(404, "Not found")
    body = read_binary(record, blobs)
    info = parse_cert_info(body)
    if info is None or info.primary.version > 4:
        return v2_response(404, "Not found")
    return v2_response(200, body, mimetype=V2_MEDIA_TYPE)
