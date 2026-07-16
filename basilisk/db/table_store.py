from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone

from azure.core.exceptions import ResourceNotFoundError
from azure.data.tables import TableServiceClient

from basilisk.db.store import CertRecord, CertStore
from basilisk.openpgp.canonical import parse_uid_parts

logger = logging.getLogger(__name__)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _escape_odata(value: str) -> str:
    return value.replace("'", "''")


class AzureTableCertStore(CertStore):
    """Azure Table Storage index with approval gate."""

    def __init__(self, connection_string: str) -> None:
        self._client = TableServiceClient.from_connection_string(connection_string)
        for name in ("Certs", "Identifiers", "Emails"):
            try:
                self._client.create_table_if_not_exists(name)
            except Exception:
                logger.warning("Could not ensure table %s exists", name, exc_info=True)
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
            pending_uids=json.loads(entity.get("pending_uids", "[]")),
            claimer_email=entity.get("claimer_email"),
            claimer_oid=entity.get("claimer_oid"),
            canonical_blob_uri=entity.get("canonical_blob_uri"),
            revoked=bool(entity.get("revoked", False)),
            key_expiration=entity.get("key_expiration"),
            label=entity.get("label") or None,
        )

    def _index_emails(self, fingerprint: str, uids: list[str]) -> None:
        fpr = fingerprint.upper()
        for uid in uids:
            email = parse_uid_parts(uid)["email"]
            if not email:
                continue
            self._emails.upsert_entity(
                {"PartitionKey": email, "RowKey": fpr, "fingerprint": fpr}
            )

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
                "pending_uids": json.dumps(uids),
                "revoked": revoked,
                "key_expiration": expiration,
                "created_at": now,
                "updated_at": now,
            }
        )
        kid = key_id.lower().removeprefix("0x")
        for ident, id_type in ((fpr, "fingerprint"), (kid, "keyid")):
            self._ids.upsert_entity(
                {"PartitionKey": ident, "RowKey": id_type, "fingerprint": fpr, "id_type": id_type}
            )
        self._index_emails(fpr, uids)

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
        for entity in self._emails.query_entities(
            query_filter=f"PartitionKey eq '{_escape_odata(email.lower())}'"
        ):
            record = self.get_by_fingerprint(entity["fingerprint"])
            if record and record.approval_state == "approved":
                return record
        return None

    def list_by_email(self, email: str) -> list[CertRecord]:
        target = email.lower()
        seen: set[str] = set()
        out: list[CertRecord] = []
        for entity in self._emails.query_entities(
            query_filter=f"PartitionKey eq '{_escape_odata(target)}'"
        ):
            record = self.get_by_fingerprint(entity["fingerprint"])
            if record and record.fingerprint not in seen:
                seen.add(record.fingerprint)
                out.append(record)
        for entity in self._certs.query_entities(
            query_filter=f"claimer_email eq '{_escape_odata(target)}'"
        ):
            record = self._record(entity)
            if record.fingerprint not in seen:
                seen.add(record.fingerprint)
                out.append(record)
        return out

    def list_by_name(self, name_query: str, *, limit: int = 50) -> list[CertRecord]:
        needle = (name_query or "").casefold().strip()
        if len(needle) < 2:
            return []
        out: list[CertRecord] = []
        for entity in self._certs.list_entities():
            if entity.get("approval_state") != "approved":
                continue
            record = self._record(entity)
            for uid in record.approved_uids or []:
                parts = parse_uid_parts(uid)
                name = (parts.get("name") or "").casefold()
                raw = (parts.get("raw") or "").casefold()
                if needle in name or (not name and needle in raw):
                    out.append(record)
                    break
            if len(out) >= limit:
                break
        return out

    def list_approved(self, *, limit: int = 10_000) -> list[CertRecord]:
        out: list[CertRecord] = []
        for entity in self._certs.list_entities():
            if entity.get("approval_state") != "approved":
                continue
            out.append(self._record(entity))
            if len(out) >= limit:
                break
        return out

    def list_by_claimer_oid(self, oid: str) -> list[CertRecord]:
        if not oid:
            return []
        return [
            self._record(entity)
            for entity in self._certs.query_entities(
                query_filter=f"claimer_oid eq '{_escape_odata(oid)}'"
            )
        ]

    def record_claim(self, fingerprint: str, claimer_email: str, claimer_oid: str) -> None:
        fpr = fingerprint.upper()
        entity = self._certs.get_entity(partition_key=fpr, row_key=fpr)
        entity["claimer_email"] = claimer_email.lower()
        entity["claimer_oid"] = claimer_oid
        entity["updated_at"] = _utcnow()
        self._certs.update_entity(entity, mode="replace")

    def approve(self, fingerprint: str, approved_uids: list[str]) -> None:
        fpr = fingerprint.upper()
        entity = self._certs.get_entity(partition_key=fpr, row_key=fpr)
        entity["approval_state"] = "approved"
        entity["approved_uids"] = json.dumps(approved_uids)
        entity["updated_at"] = _utcnow()
        self._certs.update_entity(entity, mode="replace")
        self._index_emails(fpr, approved_uids)

    def reject(self, fingerprint: str) -> None:
        fpr = fingerprint.upper()
        entity = self._certs.get_entity(partition_key=fpr, row_key=fpr)
        entity["approval_state"] = "rejected"
        entity["updated_at"] = _utcnow()
        self._certs.update_entity(entity, mode="replace")

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
        fpr = fingerprint.upper()
        entity = self._certs.get_entity(partition_key=fpr, row_key=fpr)
        if entity.get("approval_state") != "approved":
            return
        entity["blob_uri"] = blob_uri
        entity["sha256"] = sha256
        entity["key_id"] = key_id
        entity["revoked"] = revoked
        entity["key_expiration"] = expiration
        entity["updated_at"] = _utcnow()
        self._certs.update_entity(entity, mode="replace")
        kid = key_id.lower().removeprefix("0x")
        for ident, id_type in ((fpr, "fingerprint"), (kid, "keyid")):
            self._ids.upsert_entity(
                {"PartitionKey": ident, "RowKey": id_type, "fingerprint": fpr, "id_type": id_type}
            )

    def list_pending_older_than(self, cutoff_iso: str) -> list[CertRecord]:
        out: list[CertRecord] = []
        for entity in self._certs.query_entities(
            query_filter="approval_state eq 'pending'"
        ):
            updated = str(entity.get("updated_at") or entity.get("created_at") or "")
            if updated and updated < cutoff_iso:
                out.append(self._record(entity))
        return out

    def set_label(self, fingerprint: str, label: str | None) -> None:
        fpr = fingerprint.upper()
        entity = self._certs.get_entity(partition_key=fpr, row_key=fpr)
        entity["label"] = label
        entity["updated_at"] = _utcnow()
        self._certs.update_entity(entity, mode="replace")

    def stats(self) -> dict[str, int]:
        out = {"total": 0, "pending": 0, "approved": 0, "rejected": 0}
        for entity in self._certs.list_entities():
            state = entity.get("approval_state", "pending")
            out[state] = out.get(state, 0) + 1
            out["total"] += 1
        return out
