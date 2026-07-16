from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class CertRecord:
    fingerprint: str
    approval_state: str
    blob_uri: str
    sha256: str
    key_id: str
    approved_uids: list[str]
    pending_uids: list[str] | None = None
    claimer_email: str | None = None
    claimer_oid: str | None = None
    canonical_blob_uri: str | None = None
    revoked: bool = False
    key_expiration: str | None = None


class CertStore(Protocol):
    def upsert_pending(
        self,
        fingerprint: str,
        blob_uri: str,
        sha256: str,
        key_id: str,
        uids: list[str],
        *,
        expiration: str | None = None,
        revoked: bool = False,
    ) -> None: ...

    def get_by_fingerprint(self, fingerprint: str) -> CertRecord | None: ...

    def get_by_identifier(self, identifier: str) -> CertRecord | None: ...

    def get_by_email(self, email: str) -> CertRecord | None: ...

    def list_by_email(self, email: str) -> list[CertRecord]: ...

    def list_by_name(self, name_query: str, *, limit: int = 50) -> list[CertRecord]:
        """Return approved certs whose approved UID names contain ``name_query`` (casefold)."""
        ...

    def list_approved(self, *, limit: int = 10_000) -> list[CertRecord]:
        """Return approved (optionally including revoked) certs for attestation allowlists."""
        ...

    def list_by_claimer_oid(self, oid: str) -> list[CertRecord]: ...

    def record_claim(self, fingerprint: str, claimer_email: str, claimer_oid: str) -> None: ...

    def approve(self, fingerprint: str, approved_uids: list[str]) -> None: ...

    def reject(self, fingerprint: str) -> None: ...

    def refresh_approved(
        self,
        fingerprint: str,
        blob_uri: str,
        sha256: str,
        key_id: str,
        *,
        expiration: str | None = None,
        revoked: bool = False,
    ) -> None:
        """Update blob metadata for an already-approved cert without demoting approval."""
        ...

    def list_pending_older_than(self, cutoff_iso: str) -> list[CertRecord]:
        """Return pending certs with updated_at (or created_at) before cutoff."""
        ...

    def stats(self) -> dict[str, int]: ...
