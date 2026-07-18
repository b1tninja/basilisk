from __future__ import annotations

from typing import Any

from basilisk.config import Settings
from basilisk.db.store import CertRecord
from basilisk.openpgp.canonical import structure_uids


def key_summary(record: CertRecord, settings: Settings, *, include_uids: bool = False) -> dict[str, Any]:
    uids: list[str] = []
    if include_uids or record.approval_state == "approved":
        uids = record.approved_uids if record.approval_state == "approved" else (record.pending_uids or [])
    elif record.approval_state == "pending" and include_uids:
        uids = record.pending_uids or []

    show_uids = include_uids or record.approval_state == "approved"
    return {
        "fingerprint": record.fingerprint,
        "key_id": record.key_id,
        "approval_state": record.approval_state,
        # Structured User IDs (conventional name/email/comment). Storage remains strings.
        "uids": structure_uids(uids) if show_uids else [],
        "pending_uids": structure_uids(record.pending_uids) if include_uids else [],
        "approved_uids": structure_uids(record.approved_uids)
        if record.approval_state == "approved"
        else [],
        "claimer_email": record.claimer_email,
        "label": record.label,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "sha256": record.sha256,
        "claim_url": f"{settings.base_url}/claim/{record.fingerprint}",
        "view_url": f"{settings.base_url}/key?fpr={record.fingerprint}",
    }
