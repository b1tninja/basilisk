from __future__ import annotations

import urllib.parse

from basilisk.config import Settings, get_settings
from basilisk.db.blob_store import LocalBlobStore
from basilisk.db.factory import get_blob_store as _factory_blob, get_cert_store
from basilisk.db.store import CertStore
from basilisk.messaging.bus import enqueue_key_pending
from basilisk.openpgp.errors import IngestError
from basilisk.openpgp.ingest import parse_armored_keytext
from basilisk.openpgp.policy import IngestPath
from basilisk.db.sqlite_store import sha256_hex


def get_store(settings: Settings | None = None) -> CertStore:
    return get_cert_store(settings)


def get_blob_store(settings: Settings | None = None) -> LocalBlobStore:
    return _factory_blob(settings)  # type: ignore[return-value]


def ingest_keytext(
    store: CertStore,
    blobs: LocalBlobStore,
    keytext: str,
    *,
    settings: Settings | None = None,
    path: IngestPath = "v1",
    enqueue_events: bool = True,
) -> tuple[str, str, bool]:
    """Parse, validate policy, optionally write blob. Returns (fpr, key_id, is_duplicate)."""
    settings = settings or get_settings()
    parsed = parse_armored_keytext(keytext, path=path)
    digest = sha256_hex(parsed.armored)

    existing = store.get_by_fingerprint(parsed.fingerprint)
    if existing and existing.sha256 == digest:
        return parsed.fingerprint, parsed.key_id, True

    blob_uri = blobs.write_cert(parsed.fingerprint, digest, parsed.armored)
    store.upsert_pending(
        parsed.fingerprint,
        blob_uri,
        digest,
        parsed.key_id,
        parsed.uids,
    )
    if enqueue_events:
        claim_url = f"{settings.base_url}/claim/{parsed.fingerprint}"
        enqueue_key_pending(parsed.fingerprint, parsed.uids, claim_url)
    return parsed.fingerprint, parsed.key_id, False


def parse_add_form(body: bytes, content_type: str | None) -> str:
    text = body.decode("utf-8", errors="replace")
    if content_type and "application/x-www-form-urlencoded" in content_type:
        parsed = urllib.parse.parse_qs(text, keep_blank_values=True)
        if "keytext" not in parsed:
            raise IngestError("Missing keytext", 422)
        return parsed["keytext"][0]
    if "keytext=" in text:
        parsed = urllib.parse.parse_qs(text, keep_blank_values=True)
        return parsed.get("keytext", [text])[0]
    return text
