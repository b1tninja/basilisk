from __future__ import annotations

from basilisk.config import Settings
from basilisk.db.blob_store import LocalBlobStore
from basilisk.db.store import CertRecord, CertStore
from basilisk.openpgp.canonical import parse_uid_parts
from basilisk.openpgp.ingest import strip_uids_for_pending


def can_view_key(record: CertRecord, viewer_email: str | None, viewer_oid: str | None) -> bool:
    if record.approval_state == "approved":
        return True
    if not viewer_email and not viewer_oid:
        return False
    if viewer_oid and record.claimer_oid == viewer_oid:
        return True
    if viewer_email and record.claimer_email and record.claimer_email.lower() == viewer_email.lower():
        return True
    pending = record.pending_uids or []
    viewer = (viewer_email or "").lower()
    for uid in pending:
        email = parse_uid_parts(uid)["email"]
        if viewer and email and email == viewer:
            return True
    return False


def read_key_armored(
    record: CertRecord,
    blobs: LocalBlobStore,
    settings: Settings,
    *,
    viewer_email: str | None = None,
    viewer_oid: str | None = None,
) -> bytes:
    if not can_view_key(record, viewer_email, viewer_oid):
        raise PermissionError("Key not available")
    data = blobs.read(record.blob_uri)
    if record.approval_state != "approved":
        return strip_uids_for_pending(data)
    return data
