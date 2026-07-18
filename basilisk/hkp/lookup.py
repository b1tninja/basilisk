from __future__ import annotations

import json

from basilisk.cache.pubkey_lru import PubkeyLRU
from basilisk.config import Settings, get_settings
from basilisk.db.blob_store import LocalBlobStore
from basilisk.db.factory import get_blob_store as _factory_blob
from basilisk.db.factory import get_cert_store
from basilisk.db.sqlite_store import sha256_hex
from basilisk.db.store import CertStore
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
    headers = {
        "ETag": f'"{record.sha256}"',
        "Cache-Control": "public, max-age=31536000, immutable",
        "Access-Control-Allow-Origin": "*",
    }
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
        return HttpResponse(exc.status, str(exc), {}, "text/plain")

    if kind == "email":
        record = store.get_by_email(ident)
        if not record or record.approval_state != "approved":
            return HttpResponse(404, "Not found", {}, "text/plain")
        data, headers = _read_blob(record, blobs, settings, if_none_match)
        if headers.get("X-Not-Modified"):
            return HttpResponse(304, "", headers, "application/pgp-keys")
        filtered = filter_armored_by_uids(data, emails_from_uids(record.approved_uids))
        return HttpResponse(200, filtered, headers, "application/pgp-keys")

    if kind == "fingerprint":
        record = store.get_by_fingerprint(ident)
    else:
        record = store.get_by_identifier(ident)
    if not record:
        return HttpResponse(404, "Not found", {}, "text/plain")

    # Expired keys are hidden from HKP (search already excludes them).
    # Pending keys remain fetchable with UIDs stripped for the claim flow.
    if record.approval_state == "expired":
        return HttpResponse(404, "Not found", {}, "text/plain")
    if record.approval_state == "rejected":
        return HttpResponse(404, "Not found", {}, "text/plain")

    data, headers = _read_blob(record, blobs, settings, if_none_match)
    if headers.get("X-Not-Modified"):
        return HttpResponse(304, "", headers, "application/pgp-keys")

    if record.approval_state != "approved":
        data = strip_uids_for_pending(data)

    if settings.cache_mode == "redirect" and settings.fd_base_url:
        url = f"{settings.fd_base_url.rstrip('/')}/{record.blob_uri}"
        return HttpResponse(302, "", {**headers, "Location": url}, "application/pgp-keys")

    return HttpResponse(200, data, headers, "application/pgp-keys")


def lookup_index(search: str, store: CertStore | None = None) -> HttpResponse:
    store = store or get_cert_store()
    try:
        kind, ident = parse_search(search)
    except IngestError as exc:
        return HttpResponse(exc.status, str(exc), {}, "text/plain")

    if kind == "email":
        record = store.get_by_email(ident)
    elif kind == "fingerprint":
        record = store.get_by_fingerprint(ident)
    else:
        record = store.get_by_identifier(ident)

    if not record or record.approval_state != "approved":
        return HttpResponse(404, "Not found", {}, "text/plain")

    fpr = record.fingerprint
    uid = record.approved_uids[0] if record.approved_uids else "unknown"
    body = f"info:1:1\npub:255:0::::::{len(fpr)//2}:{fpr.lower()}\nuid:{len(uid)}:{uid}\n"
    headers = {"Access-Control-Allow-Origin": "*"}
    return HttpResponse(200, body, headers, "text/plain")


def lookup_stats(store: CertStore | None = None) -> HttpResponse:
    from basilisk.observability.metrics import snapshot

    store = store or get_cert_store()
    stats = store.stats()
    stats.update(snapshot())
    body = json.dumps({"stats": stats})
    return HttpResponse(200, body, {"Content-Type": "application/json"}, "application/json")
