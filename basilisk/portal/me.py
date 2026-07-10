from __future__ import annotations

from basilisk.config import Settings, get_settings
from basilisk.db.store import CertStore
from basilisk.portal.serializers import key_summary


def my_keys(
    principal: dict[str, str],
    store: CertStore,
    settings: Settings | None = None,
) -> list[dict]:
    settings = settings or get_settings()
    email = principal.get("email", "").lower()
    oid = principal.get("oid", "")

    by_fp: dict[str, object] = {}
    for record in store.list_by_email(email):
        by_fp[record.fingerprint] = record
    for record in store.list_by_claimer_oid(oid):
        by_fp[record.fingerprint] = record

    results = [
        key_summary(record, settings, include_uids=True)
        for record in sorted(by_fp.values(), key=lambda r: r.fingerprint)
    ]
    for item in results:
        item["can_claim"] = (
            item["approval_state"] == "pending"
            and email
            and any(
                email in (uid.split("<")[-1].rstrip(">").strip() if "<" in uid else uid).lower()
                for uid in item.get("pending_uids") or item.get("uids") or []
            )
        )
    return results
