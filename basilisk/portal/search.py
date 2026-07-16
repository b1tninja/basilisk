from __future__ import annotations

from basilisk.config import Settings, get_settings
from basilisk.db.store import CertStore
from basilisk.openpgp.ingest import IngestError, parse_search
from basilisk.portal.serializers import key_summary


def search_keys(query: str, store: CertStore, settings: Settings | None = None) -> dict:
    settings = settings or get_settings()
    query = query.strip()
    if not query:
        return {"query": query, "results": [], "reason": "empty"}

    try:
        kind, ident = parse_search(query)
    except IngestError as exc:
        reason = "invalid_query"
        if "Short key" in str(exc):
            reason = "short_keyid"
        return {"query": query, "results": [], "reason": reason, "error": str(exc)}

    if kind == "email":
        records = store.list_by_email(ident)
        approved = [r for r in records if r.approval_state == "approved"]
        if approved:
            return {
                "query": query,
                "results": [key_summary(r, settings, include_uids=True) for r in approved],
                "reason": "ok",
            }
        if records:
            return {"query": query, "results": [], "reason": "pending"}
        return {"query": query, "results": [], "reason": "not_found"}

    record = (
        store.get_by_fingerprint(ident)
        if kind == "fingerprint"
        else store.get_by_identifier(ident)
    )
    if not record:
        return {"query": query, "results": [], "reason": "not_found"}

    if record.approval_state != "approved":
        return {
            "query": query,
            "results": [],
            "reason": "pending",
            # Fingerprint hits can still deep-link to the key page.
            "fingerprint": record.fingerprint,
        }

    return {
        "query": query,
        "results": [key_summary(record, settings, include_uids=True)],
        "reason": "ok",
    }
