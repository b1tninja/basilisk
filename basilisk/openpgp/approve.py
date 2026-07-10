from __future__ import annotations

from basilisk.db.store import CertStore


def approve_cert(store: CertStore, fingerprint: str, approved_uids: list[str] | None = None) -> None:
    record = store.get_by_fingerprint(fingerprint)
    if not record:
        raise ValueError(f"Unknown fingerprint: {fingerprint}")
    uids = approved_uids if approved_uids is not None else []
    if not uids:
        # default: approve all uids from pending upload metadata not stored separately;
        # caller should pass explicit list
        uids = record.approved_uids
    store.approve(fingerprint, uids)


def reject_cert(store: CertStore, fingerprint: str) -> None:
    store.reject(fingerprint)
