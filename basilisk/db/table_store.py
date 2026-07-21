from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone

from azure.core.exceptions import ResourceNotFoundError
from azure.data.tables import TableServiceClient

from basilisk.db.hex_aliases import (
    UNIQUE_ID_TYPES,
    hex_aliases,
    id_types_for_needle,
    normalize_hex_needle,
)
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
        for name in ("Certs", "Identifiers", "Emails", "CertHistory"):
            try:
                self._client.create_table_if_not_exists(name)
            except Exception:
                logger.warning("Could not ensure table %s exists", name, exc_info=True)
        self._certs = self._client.get_table_client("Certs")
        self._ids = self._client.get_table_client("Identifiers")
        self._emails = self._client.get_table_client("Emails")
        self._history = self._client.get_table_client("CertHistory")
        self._ensure_hex_alias_index()

    def _ensure_hex_alias_index(self) -> None:
        """One-time backfill of short/fpr32 aliases (marker in Identifiers)."""
        try:
            self._ids.get_entity(partition_key="_meta", row_key="hex_alias_v1")
            return
        except ResourceNotFoundError:
            pass
        except Exception:
            logger.warning("Could not read hex-alias marker", exc_info=True)
            return
        try:
            self.backfill_hex_identifier_index()
            self._ids.upsert_entity(
                {
                    "PartitionKey": "_meta",
                    "RowKey": "hex_alias_v1",
                    "id_type": "meta",
                    "fingerprint": "",
                }
            )
        except Exception:
            logger.warning("Hex-alias backfill failed", exc_info=True)

    def backfill_hex_identifier_index(self) -> int:
        """Re-index hex aliases for every cert. Returns number of certs processed."""
        n = 0
        for entity in self._certs.list_entities():
            fpr = str(entity.get("RowKey") or entity.get("fingerprint") or "")
            kid = str(entity.get("key_id") or "")
            if not fpr:
                continue
            self._replace_hex_aliases(fpr, kid)
            n += 1
        return n

    def _identifier_row_key(self, id_type: str, fingerprint: str) -> str:
        if id_type in UNIQUE_ID_TYPES:
            return id_type
        return fingerprint.upper()

    def _clear_hex_aliases(self, fingerprint: str, key_id: str) -> None:
        fpr = fingerprint.upper()
        for ident, id_type in hex_aliases(fpr, key_id):
            try:
                self._ids.delete_entity(
                    partition_key=ident,
                    row_key=self._identifier_row_key(id_type, fpr),
                )
            except ResourceNotFoundError:
                pass
            except Exception:
                pass

    def _replace_hex_aliases(self, fingerprint: str, key_id: str) -> None:
        fpr = fingerprint.upper()
        # Drop any prior alias set for this fingerprint (uses current key_id material).
        self._clear_hex_aliases(fpr, key_id)
        for ident, id_type in hex_aliases(fpr, key_id):
            self._ids.upsert_entity(
                {
                    "PartitionKey": ident,
                    "RowKey": self._identifier_row_key(id_type, fpr),
                    "fingerprint": fpr,
                    "id_type": id_type,
                }
            )

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
            created_at=entity.get("created_at"),
            updated_at=entity.get("updated_at"),
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
        prior = self.get_by_fingerprint(fpr)
        created_at = (prior.created_at if prior and prior.created_at else now)
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
                "created_at": created_at,
                "updated_at": now,
            }
        )
        if prior is None:
            self.append_history(fpr, sha256, "first_seen", recorded_at=now)
        elif prior.sha256 != sha256:
            self.append_history(fpr, sha256, "blob_changed", recorded_at=now)
        if prior is not None and prior.key_id and prior.key_id != key_id:
            self._clear_hex_aliases(fpr, prior.key_id)
        self._replace_hex_aliases(fpr, key_id)
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

    def list_by_fingerprint_substring(
        self, hex_query: str, *, limit: int = 50
    ) -> list[CertRecord]:
        needle = normalize_hex_needle(hex_query)
        types = set(id_types_for_needle(needle))
        if not types:
            return []
        # Partition-key point query on Identifiers (no Certs table scan).
        out: list[CertRecord] = []
        seen: set[str] = set()
        for entity in self._ids.query_entities(
            query_filter=f"PartitionKey eq '{_escape_odata(needle)}'"
        ):
            id_type = str(entity.get("id_type") or "")
            if id_type not in types:
                continue
            fpr = str(entity.get("fingerprint") or entity.get("RowKey") or "")
            if not fpr or fpr in seen:
                continue
            record = self.get_by_fingerprint(fpr)
            if not record or record.approval_state not in ("approved", "pending"):
                continue
            seen.add(record.fingerprint)
            out.append(record)
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
        prior_sha = entity.get("sha256")
        prior_kid = str(entity.get("key_id") or "")
        now = _utcnow()
        entity["blob_uri"] = blob_uri
        entity["sha256"] = sha256
        entity["key_id"] = key_id
        entity["revoked"] = revoked
        entity["key_expiration"] = expiration
        entity["updated_at"] = now
        self._certs.update_entity(entity, mode="replace")
        if prior_kid and prior_kid != key_id:
            self._clear_hex_aliases(fpr, prior_kid)
        self._replace_hex_aliases(fpr, key_id)
        if prior_sha != sha256:
            self.append_history(fpr, sha256, "blob_changed", recorded_at=now)

    def append_history(
        self,
        fingerprint: str,
        sha256: str,
        event: str,
        *,
        recorded_at: str | None = None,
    ) -> None:
        fpr = fingerprint.upper()
        when = recorded_at or _utcnow()
        # RowKey = timestamp + sha prefix for uniqueness / chronological order
        row_key = f"{when}_{sha256[:16]}_{event}"
        self._history.upsert_entity(
            {
                "PartitionKey": fpr,
                "RowKey": row_key,
                "fingerprint": fpr,
                "sha256": sha256,
                "event": event,
                "recorded_at": when,
            }
        )

    def list_history(self, fingerprint: str) -> list[dict[str, str]]:
        fpr = fingerprint.upper()
        rows = []
        for entity in self._history.query_entities(
            query_filter=f"PartitionKey eq '{_escape_odata(fpr)}'"
        ):
            rows.append(
                {
                    "fingerprint": entity.get("fingerprint") or fpr,
                    "sha256": str(entity.get("sha256") or ""),
                    "event": str(entity.get("event") or ""),
                    "recorded_at": str(entity.get("recorded_at") or ""),
                }
            )
        rows.sort(key=lambda r: r.get("recorded_at") or "")
        return rows

    def list_pending_older_than(self, cutoff_iso: str) -> list[CertRecord]:
        out: list[CertRecord] = []
        for entity in self._certs.query_entities(
            query_filter="approval_state eq 'pending'"
        ):
            updated = str(entity.get("updated_at") or entity.get("created_at") or "")
            if updated and updated < cutoff_iso:
                out.append(self._record(entity))
        return out

    def list_approved_past_expiration(self, now_iso: str) -> list[CertRecord]:
        out: list[CertRecord] = []
        for entity in self._certs.query_entities(
            query_filter="approval_state eq 'approved'"
        ):
            exp = str(entity.get("key_expiration") or "")
            if exp and exp < now_iso:
                out.append(self._record(entity))
        return out

    def mark_expired(self, fingerprint: str) -> None:
        fpr = fingerprint.upper()
        entity = self._certs.get_entity(partition_key=fpr, row_key=fpr)
        if entity.get("approval_state") != "approved":
            return
        entity["approval_state"] = "expired"
        entity["updated_at"] = _utcnow()
        self._certs.update_entity(entity, mode="replace")

    def list_expired_past_grace(self, cutoff_iso: str) -> list[CertRecord]:
        out: list[CertRecord] = []
        for entity in self._certs.query_entities(
            query_filter="approval_state eq 'expired'"
        ):
            exp = str(entity.get("key_expiration") or "")
            if exp and exp < cutoff_iso:
                out.append(self._record(entity))
        return out

    def delete_cert(self, fingerprint: str) -> CertRecord | None:
        fpr = fingerprint.upper()
        try:
            entity = self._certs.get_entity(partition_key=fpr, row_key=fpr)
        except Exception:
            return None
        record = self._record(entity)
        # Best-effort cleanup of secondary indexes.
        for uid in record.approved_uids or []:
            email = ""
            try:
                from basilisk.openpgp.canonical import parse_uid_parts

                email = parse_uid_parts(uid).get("email") or ""
            except Exception:
                email = ""
            if email:
                try:
                    self._emails.delete_entity(partition_key=email.lower(), row_key=fpr)
                except Exception:
                    pass
        for ident, id_type in hex_aliases(fpr, record.key_id or fpr[-16:]):
            try:
                self._ids.delete_entity(
                    partition_key=ident,
                    row_key=self._identifier_row_key(id_type, fpr),
                )
            except Exception:
                pass
        try:
            self._certs.delete_entity(partition_key=fpr, row_key=fpr)
        except Exception:
            return None
        return record

    def set_label(self, fingerprint: str, label: str | None) -> None:
        fpr = fingerprint.upper()
        entity = self._certs.get_entity(partition_key=fpr, row_key=fpr)
        entity["label"] = label
        entity["updated_at"] = _utcnow()
        self._certs.update_entity(entity, mode="replace")

    def stats(self) -> dict[str, int]:
        out = {"total": 0, "pending": 0, "approved": 0, "rejected": 0, "expired": 0}
        for entity in self._certs.list_entities():
            state = entity.get("approval_state", "pending")
            out[state] = out.get(state, 0) + 1
            out["total"] += 1
        return out
