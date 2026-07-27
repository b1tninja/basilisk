from __future__ import annotations

import json

from basilisk.cache.pubkey_lru import PubkeyLRU
from basilisk.config import Settings, get_settings
from basilisk.db.blob_store import LocalBlobStore
from basilisk.db.factory import get_blob_store as _factory_blob
from basilisk.db.factory import get_cert_store
from basilisk.db.sqlite_store import sha256_hex
from basilisk.db.store import CertStore
from basilisk.hkp.cors import cors_get_headers, http_cors
from basilisk.hkp.response import HttpResponse
from basilisk.openpgp.canonical import emails_from_uids, filter_armored_by_uids
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
    headers = cors_get_headers(
        {
            "ETag": f'"{record.sha256}"',
            "Cache-Control": "public, max-age=31536000, immutable",
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


def lookup_index(search: str, store: CertStore | None = None) -> HttpResponse:
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
    body = f"info:1:1\npub:255:0::::::{len(fpr)//2}:{fpr.lower()}\nuid:{len(uid)}:{uid}\n"
    return http_cors(200, body, mimetype="text/plain")


def lookup_stats(store: CertStore | None = None) -> HttpResponse:
    from basilisk.observability.metrics import snapshot

    store = store or get_cert_store()
    stats = store.stats()
    stats.update(snapshot())
    body = json.dumps({"stats": stats})
    # Stats are public operational data; GET CORS is fine (no credentials).
    return http_cors(200, body, mimetype="application/json")
