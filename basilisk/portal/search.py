from __future__ import annotations

from basilisk.config import Settings, get_settings
from basilisk.db.store import CertRecord, CertStore
from basilisk.openpgp.ingest import IngestError, parse_search
from basilisk.portal.serializers import key_summary

SHORT_KEYID_WARNING = (
    "Short (8-character) key IDs are collision-prone. "
    "Confirm the full fingerprint out of band before trusting a key."
)


def _fingerprint_needle_response(
    *,
    query: str,
    records: list[CertRecord],
    settings: Settings,
    reason_ok: str = "ok",
    warning: str | None = None,
) -> dict:
    approved = [r for r in records if r.approval_state == "approved"]
    pending = [r for r in records if r.approval_state == "pending"]
    extra = {"warning": warning} if warning else {}
    if approved:
        return {
            "query": query,
            "results": [key_summary(r, settings, include_uids=True) for r in approved],
            "reason": reason_ok,
            **extra,
        }
    if len(pending) == 1:
        return {
            "query": query,
            "results": [],
            "reason": "pending",
            "fingerprint": pending[0].fingerprint,
            **extra,
        }
    if pending:
        return {"query": query, "results": [], "reason": "pending", **extra}
    return {"query": query, "results": [], "reason": "not_found", **extra}


def search_keys(query: str, store: CertStore, settings: Settings | None = None) -> dict:
    settings = settings or get_settings()
    query = query.strip()
    if not query:
        return {"query": query, "results": [], "reason": "empty"}

    try:
        kind, ident = parse_search(query)
    except IngestError as exc:
        return {
            "query": query,
            "results": [],
            "reason": "invalid_query",
            "error": str(exc),
        }

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

    if kind == "name":
        records = store.list_by_name(ident)
        return {
            "query": query,
            "results": [key_summary(r, settings, include_uids=True) for r in records],
            "reason": "name" if records else "not_found",
        }

    if kind == "fingerprint_partial":
        return _fingerprint_needle_response(
            query=query,
            records=store.list_by_fingerprint_substring(ident),
            settings=settings,
        )

    if kind == "short_keyid":
        return _fingerprint_needle_response(
            query=query,
            records=store.list_by_fingerprint_substring(ident),
            settings=settings,
            reason_ok="short_keyid",
            warning=SHORT_KEYID_WARNING,
        )

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
