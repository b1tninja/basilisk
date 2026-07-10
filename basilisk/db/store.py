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

    def approve(self, fingerprint: str, approved_uids: list[str]) -> None: ...

    def reject(self, fingerprint: str) -> None: ...

    def stats(self) -> dict[str, int]: ...
