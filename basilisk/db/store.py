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


class CertStore(Protocol):
    def upsert_pending(
        self,
        fingerprint: str,
        blob_uri: str,
        sha256: str,
        key_id: str,
        uids: list[str],
    ) -> None: ...

    def get_by_fingerprint(self, fingerprint: str) -> CertRecord | None: ...

    def get_by_identifier(self, identifier: str) -> CertRecord | None: ...

    def get_by_email(self, email: str) -> CertRecord | None: ...

    def list_by_email(self, email: str) -> list[CertRecord]: ...

    def list_by_claimer_oid(self, oid: str) -> list[CertRecord]: ...

    def record_claim(self, fingerprint: str, claimer_email: str, claimer_oid: str) -> None: ...

    def approve(self, fingerprint: str, approved_uids: list[str]) -> None: ...

    def reject(self, fingerprint: str) -> None: ...

    def stats(self) -> dict[str, int]: ...
