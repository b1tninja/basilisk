from __future__ import annotations

from basilisk.config import Settings, get_settings
from basilisk.db.store import CertStore
from basilisk.openpgp.ingest import IngestError, parse_search
from basilisk.portal.serializers import key_summary


def search_keys(query: str, store: CertStore, settings: Settings | None = None) -> dict:
    settings = settings or get_settings()
    query = query.strip()
    if not query:
        return {"query": query, "results": []}

    try:
        kind, ident = parse_search(query)
    except IngestError:
        return {"query": query, "results": []}

    if kind == "email":
        record = store.get_by_email(ident)
        if not record:
            return {"query": query, "results": []}
        return {"query": query, "results": [key_summary(record, settings)]}

    record = (
        store.get_by_fingerprint(ident)
        if kind == "fingerprint"
        else store.get_by_identifier(ident)
    )
    if not record:
        return {"query": query, "results": []}

    if record.approval_state != "approved" and kind == "email":
        return {"query": query, "results": []}

    include_uids = record.approval_state == "approved"
    return {"query": query, "results": [key_summary(record, settings, include_uids=include_uids)]}
