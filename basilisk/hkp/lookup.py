from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timezone

from basilisk.cache.pubkey_lru import PubkeyLRU
from basilisk.config import Settings, get_settings
from basilisk.db.blob_store import LocalBlobStore
from basilisk.db.factory import get_blob_store as _factory_blob
from basilisk.db.factory import get_cert_store
from basilisk.db.sqlite_store import sha256_hex
from basilisk.db.store import CertRecord, CertStore
from basilisk.hkp.cors import cors_get_headers, http_cors
from basilisk.hkp.response import HttpResponse
from basilisk.openpgp.canonical import emails_from_uids, filter_armored_by_uids
from basilisk.openpgp.keyinfo import is_expired
from basilisk.openpgp.ingest import IngestError, parse_search, strip_uids_for_pending

_lru: PubkeyLRU | None = None


def _get_lru(settings: Settings) -> PubkeyLRU:
    global _lru
    if _lru is None:
        _lru = PubkeyLRU(settings.lru_cache_size)
    return _lru


def get_store(settings: Settings | None = None) -> CertStore:
    return get_cert_store(settings)


def get_blob_store(settings: Settings | None = None):
    return _factory_blob(settings)


def _read_blob(
    record,
    blobs: LocalBlobStore,
    settings: Settings,
    if_none_match: str | None = None,
) -> tuple[bytes, dict[str, str]]:
    cached = _get_lru(settings).get(record.sha256)
    if cached is None:
        data = blobs.read(record.blob_uri)
        if sha256_hex(data) != record.sha256:
            raise RuntimeError("Blob integrity check failed")
        _get_lru(settings).put(record.sha256, data)
    else:
        data = cached
    # `no-cache` means "store it, but revalidate before every use" -- not "do
    # not store it". The ETag below is the blob's digest, so revalidation is a
    # conditional GET that comes back 304 with no body when nothing changed.
    #
    # This URL used to be `max-age=31536000, immutable`, which was wrong in the
    # way that matters most for a keyserver. `immutable` tells a browser never
    # to revalidate, so the ETag right here could never fire -- and the URL is
    # keyed by *fingerprint* while its content is keyed by digest.
    # `refresh_approved` replaces the blob behind that fingerprint whenever a
    # key is re-uploaded: a new subkey, a new user id, **or a revocation**. So a
    # browser that fetched a key once kept serving the pre-revocation
    # certificate for up to a year, and `hkp.get refresh=true` -- the one
    # control a person has for exactly this -- could not dislodge it, because
    # the request never left the machine.
    #
    # `max-age` belongs on the digest-addressed blob (`certs/{fpr}/{sha}.asc`),
    # which really is immutable, not on the fingerprint-addressed lookup that
    # points at it. In `cache_mode = redirect` these same headers ride the 302,
    # so the stale mapping was being pinned there too.
    headers = cors_get_headers(
        {
            "ETag": f'"{record.sha256}"',
            "Cache-Control": "no-cache",
        }
    )
    if if_none_match and if_none_match.strip('"') == record.sha256:
        return b"", {**headers, "X-Not-Modified": "1"}
    return data, headers


def lookup_get(
    search: str,
    store: CertStore | None = None,
    blobs: LocalBlobStore | None = None,
    settings: Settings | None = None,
    if_none_match: str | None = None,
) -> HttpResponse:
    settings = settings or get_settings()
    store = store or get_cert_store(settings)
    blobs = blobs or get_blob_store(settings)
    try:
        kind, ident = parse_search(search)
    except IngestError as exc:
        return http_cors(exc.status, str(exc))

    if kind == "email":
        record = store.get_by_email(ident)
        if not record or record.approval_state != "approved":
            return http_cors(404, "Not found")
        data, headers = _read_blob(record, blobs, settings, if_none_match)
        if headers.get("X-Not-Modified"):
            return HttpResponse(304, "", headers, "application/pgp-keys")
        filtered = filter_armored_by_uids(data, emails_from_uids(record.approved_uids))
        return HttpResponse(200, filtered, headers, "application/pgp-keys")

    if kind == "name":
        return http_cors(404, "Not found")

    if kind == "fingerprint_partial" or kind == "short_keyid":
        matches = [
            r
            for r in store.list_by_fingerprint_substring(ident)
            if r.approval_state in ("approved", "pending")
        ]
        if len(matches) != 1:
            return http_cors(404, "Not found")
        record = matches[0]
    elif kind == "fingerprint":
        record = store.get_by_fingerprint(ident)
    else:
        record = store.get_by_identifier(ident)
    if not record:
        return http_cors(404, "Not found")

    # Expired keys are hidden from HKP (search already excludes them).
    # Pending keys remain fetchable with UIDs stripped for the claim flow.
    if record.approval_state == "expired":
        return http_cors(404, "Not found")
    if record.approval_state == "rejected":
        return http_cors(404, "Not found")

    data, headers = _read_blob(record, blobs, settings, if_none_match)
    if headers.get("X-Not-Modified"):
        return HttpResponse(304, "", headers, "application/pgp-keys")

    if record.approval_state != "approved":
        data = strip_uids_for_pending(data)

    if settings.cache_mode == "redirect" and settings.fd_base_url:
        url = f"{settings.fd_base_url.rstrip('/')}/{record.blob_uri}"
        # CORS on the redirect response; blob/CDN should also send ACAO for follow.
        return HttpResponse(
            302, "", {**headers, "Location": url}, "application/pgp-keys"
        )

    return HttpResponse(200, data, headers, "application/pgp-keys")


def _index_expiration(iso: str | None) -> datetime | None:
    """A stored ISO expiration as a datetime, or None when there is not one.

    A timestamp that will not parse is the same case as one that was never
    stored: the record does not tell us when this key expires. The index says
    so by leaving the field empty rather than by guessing, which is the rule
    `basilisk/openpgp/keyinfo.py` already states for the v2 index.
    """
    if not iso:
        return None
    try:
        parsed = datetime.fromisoformat(iso)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _index_flags(record: CertRecord, expiration: datetime | None) -> str:
    """The draft's flags column: `r` revoked, `e` expired, in that order.

    This is the whole reason the format below changed. Without a flags column a
    revoked record and a live one differ only in their fingerprint, so a client
    that reads the index -- which is all `gpg --search-keys` reads before it
    offers a key to import -- cannot tell that a key has been withdrawn. That is
    the most dangerous thing a keyserver can be quiet about.

    `e` is computed from the expiration rather than read off `approval_state`,
    because the two are not the same fact. `mark_expired` moves a record to the
    `expired` state and `lookup_index` 404s it well before reaching here; a key
    whose own expiration has passed but which the expiry sweep has not visited
    yet is still `approved`, and that window is exactly when a client needs
    telling.
    """
    flags = "r" if record.revoked else ""
    if is_expired(expiration):
        flags += "e"
    return flags


def lookup_index(search: str, store: CertStore | None = None) -> HttpResponse:
    """The machine-readable index, in the format an HKP client parses.

    `draft-shaw-openpgp-hkp-00` §5.2 spells the two record lines:

        pub:<keyid>:<algo>:<keylen>:<created>:<expires>:<flags>
        uid:<url-encoded uid>:<created>:<expires>:<flags>

    What this used to send was `pub:255:0::::::20:<fpr>` -- ten fields with the
    identifier *last*, two literals where the algorithm and key length belong,
    and the fingerprint's byte length in a tenth field of its own invention --
    over a uid line carrying a character count and then the raw user id, so a
    user id containing a colon shifted every field after it.

    It survived because nothing parsed it. Nothing in `web/src` requests
    `op=index` at all, and the one test over the surface asserted `"pub:" in
    r.text`, which every one of those forms satisfies. On its own that is an
    argument for leaving it alone: conformance with no consumer buys nothing.

    What changes the answer is the flags column. A revoked key has to be
    *distinguishable* from a live one here, and the only thing that can act on
    that is a real HKP client -- `gpg --search-keys`, which this repo already
    drives in `tests/e2e/test_hkp_index.py`. A flag in a column no parser can
    find is not a warning, so the field order is not separable from the warning
    that needs to ride in it: making the revocation legible *is* making the
    format conformant. They are one fix, and this is it.

    Algorithm, key length and creation date stay empty because `CertRecord`
    genuinely does not hold them -- there is no column for any of the three, and
    inventing `255:0` is precisely what the old form did. They are derivable, by
    parsing the stored certificate the way `basilisk/openpgp/keyinfo.py` does
    for the v2 index, but that turns a metadata read into a blob read on every
    request, and v2's JSON index is where a caller that wants those facts should
    be looking. Empty is legal and true; a guessed number is neither.
    """
    store = store or get_cert_store()
    try:
        kind, ident = parse_search(search)
    except IngestError as exc:
        return http_cors(exc.status, str(exc))

    if kind == "email":
        record = store.get_by_email(ident)
    elif kind == "fingerprint":
        record = store.get_by_fingerprint(ident)
    elif kind == "fingerprint_partial" or kind == "short_keyid":
        matches = [
            r
            for r in store.list_by_fingerprint_substring(ident)
            if r.approval_state == "approved"
        ]
        if len(matches) != 1:
            return http_cors(404, "Not found")
        record = matches[0]
    elif kind == "name":
        return http_cors(404, "Not found")
    else:
        record = store.get_by_identifier(ident)

    if not record or record.approval_state != "approved":
        return http_cors(404, "Not found")

    fpr = record.fingerprint
    uid = record.approved_uids[0] if record.approved_uids else "unknown"
    expiration = _index_expiration(record.key_expiration)
    # Lowercase hex, as before: a fingerprint is case-insensitive and no client
    # compares it as a string, so changing the case here would churn every
    # assertion over this route to say nothing.
    expires = str(int(expiration.timestamp())) if expiration else ""
    body = (
        "info:1:1\n"
        f"pub:{fpr.lower()}::::{expires}:{_index_flags(record, expiration)}\n"
        f"uid:{urllib.parse.quote(uid, safe='')}:::\n"
    )
    return http_cors(200, body, mimetype="text/plain")


def lookup_stats(store: CertStore | None = None) -> HttpResponse:
    from basilisk.observability.metrics import snapshot

    store = store or get_cert_store()
    stats = store.stats()
    stats.update(snapshot())
    body = json.dumps({"stats": stats})
    # Stats are public operational data; GET CORS is fine (no credentials).
    return http_cors(200, body, mimetype="application/json")
