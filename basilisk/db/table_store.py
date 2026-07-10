from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from azure.core.exceptions import ResourceNotFoundError
from azure.data.tables import TableServiceClient

from basilisk.db.store import CertRecord, CertStore


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class AzureTableCertStore(CertStore):
    """Azure Table Storage index with approval gate."""

    def __init__(self, connection_string: str) -> None:
        self._client = TableServiceClient.from_connection_string(connection_string)
        for name in ("Certs", "Identifiers", "Emails"):
            try:
                self._client.create_table_if_not_exists(name)
            except Exception:
                pass
        self._certs = self._client.get_table_client("Certs")
        self._ids = self._client.get_table_client("Identifiers")
        self._emails = self._client.get_table_client("Emails")

    def _record(self, entity: dict) -> CertRecord:
        return CertRecord(
            fingerprint=entity["RowKey"],
            approval_state=entity.get("approval_state", "pending"),
            blob_uri=entity["blob_uri"],
            sha256=entity["sha256"],
            key_id=entity["key_id"],
            approved_uids=json.loads(entity.get("approved_uids", "[]")),
            canonical_blob_uri=entity.get("canonical_blob_uri"),
            revoked=bool(entity.get("revoked", False)),
        )

    def upsert_pending(
        self,
        fingerprint: str,
        blob_uri: str,
        sha256: str,
        key_id: str,
        uids: list[str],
    ) -> None:
        fpr = fingerprint.upper()
        now = _utcnow()
        self._certs.upsert_entity(
            {
                "PartitionKey": fpr,
                "RowKey": fpr,
                "approval_state": "pending",
                "blob_uri": blob_uri,
                "sha256": sha256,
                "key_id": key_id,
                "approved_uids": "[]",
                "created_at": now,
                "updated_at": now,
            }
        )
        kid = key_id.lower().removeprefix("0x")
        for ident, id_type in ((fpr, "fingerprint"), (kid, "keyid")):
            self._ids.upsert_entity(
                {"PartitionKey": ident, "RowKey": id_type, "fingerprint": fpr, "id_type": id_type}
            )

    def get_by_fingerprint(self, fingerprint: str) -> CertRecord | None:
        fpr = fingerprint.upper().removeprefix("0X")
        if len(fpr) == 16:
            try:
                row = self._ids.get_entity(partition_key=fpr.lower(), row_key="keyid")
                fpr = row["fingerprint"]
            except ResourceNotFoundError:
                return None
        try:
            entity = self._certs.get_entity(partition_key=fpr, row_key=fpr)
        except ResourceNotFoundError:
            return None
        return self._record(entity)

    def get_by_identifier(self, identifier: str) -> CertRecord | None:
        ident = identifier.lower().removeprefix("0x")
        try:
            row = self._ids.get_entity(partition_key=ident, row_key="keyid")
            if row.get("id_type") != "keyid":
                row = self._ids.get_entity(partition_key=ident, row_key="fingerprint")
        except ResourceNotFoundError:
            try:
                row = self._ids.get_entity(partition_key=ident, row_key="fingerprint")
            except ResourceNotFoundError:
                return None
        return self.get_by_fingerprint(row["fingerprint"])

    def get_by_email(self, email: str) -> CertRecord | None:
        try:
            row = self._emails.get_entity(partition_key=email.lower(), row_key="primary")
        except ResourceNotFoundError:
            return None
        return self.get_by_fingerprint(row["fingerprint"])

    def approve(self, fingerprint: str, approved_uids: list[str]) -> None:
        fpr = fingerprint.upper()
        entity = self._certs.get_entity(partition_key=fpr, row_key=fpr)
        entity["approval_state"] = "approved"
        entity["approved_uids"] = json.dumps(approved_uids)
        entity["updated_at"] = _utcnow()
        self._certs.update_entity(entity, mode="replace")
        for uid in approved_uids:
            email = uid.split("<")[-1].rstrip(">").strip() if "<" in uid else uid.strip()
            if "@" in email:
                self._emails.upsert_entity(
                    {"PartitionKey": email.lower(), "RowKey": "primary", "fingerprint": fpr}
                )

    def reject(self, fingerprint: str) -> None:
        fpr = fingerprint.upper()
        entity = self._certs.get_entity(partition_key=fpr, row_key=fpr)
        entity["approval_state"] = "rejected"
        entity["updated_at"] = _utcnow()
        self._certs.update_entity(entity, mode="replace")

    def stats(self) -> dict[str, int]:
        out = {"total": 0, "pending": 0, "approved": 0, "rejected": 0}
        for entity in self._certs.list_entities():
            state = entity.get("approval_state", "pending")
            out[state] = out.get(state, 0) + 1
            out["total"] += 1
        return out
