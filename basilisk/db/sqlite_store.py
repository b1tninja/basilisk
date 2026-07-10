from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from basilisk.db.store import CertRecord, CertStore


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class SqliteCertStore(CertStore):
    def __init__(self, db_path: str) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        self._conn.executescript(schema)
        self._conn.commit()
        self._migrate_portal()
        self._ensure_portal_indexes()

    def _ensure_portal_indexes(self) -> None:
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_certs_claimer_email ON certs(claimer_email)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_certs_claimer_oid ON certs(claimer_oid)"
        )
        self._conn.commit()

    def _migrate_portal(self) -> None:
        cols = {row[1] for row in self._conn.execute("PRAGMA table_info(certs)")}
        if "pending_uids" in cols:
            return
        migration = (
            Path(__file__).resolve().parent / "migrations" / "002_portal.sql"
        ).read_text(encoding="utf-8")
        self._conn.executescript(migration)
        self._conn.commit()

    def _row_to_record(self, row: sqlite3.Row) -> CertRecord:
        pending_raw = row["pending_uids"] if "pending_uids" in row.keys() else "[]"
        return CertRecord(
            fingerprint=row["fingerprint"],
            approval_state=row["approval_state"],
            blob_uri=row["blob_uri"],
            sha256=row["sha256"],
            key_id=row["key_id"],
            approved_uids=json.loads(row["approved_uids"]),
            pending_uids=json.loads(pending_raw or "[]"),
            claimer_email=row["claimer_email"] if "claimer_email" in row.keys() else None,
            claimer_oid=row["claimer_oid"] if "claimer_oid" in row.keys() else None,
            canonical_blob_uri=row["canonical_blob_uri"],
            revoked=bool(row["revoked"]),
        )

    def _index_emails(self, fingerprint: str, uids: list[str]) -> None:
        fpr = fingerprint.upper()
        self._conn.execute("DELETE FROM emails WHERE fingerprint=?", (fpr,))
        for uid in uids:
            addr = uid.split("<")[-1].rstrip(">").strip() if "<" in uid else uid.strip()
            if "@" in addr:
                self._conn.execute(
                    "INSERT OR REPLACE INTO emails (email, fingerprint) VALUES (?, ?)",
                    (addr.lower(), fpr),
                )

    def upsert_pending(
        self,
        fingerprint: str,
        blob_uri: str,
        sha256: str,
        key_id: str,
        uids: list[str],
    ) -> None:
        now = _utcnow()
        fpr = fingerprint.upper()
        self._conn.execute(
            """
            INSERT INTO certs (fingerprint, approval_state, blob_uri, sha256, key_id,
                               approved_uids, pending_uids, created_at, updated_at)
            VALUES (?, 'pending', ?, ?, ?, '[]', ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                approval_state='pending',
                blob_uri=excluded.blob_uri,
                sha256=excluded.sha256,
                key_id=excluded.key_id,
                approved_uids='[]',
                pending_uids=excluded.pending_uids,
                updated_at=excluded.updated_at
            """,
            (fpr, blob_uri, sha256, key_id, json.dumps(uids), now, now),
        )
        kid = key_id.lower().removeprefix("0x")
        self._conn.execute("DELETE FROM identifiers WHERE fingerprint=?", (fpr,))
        self._conn.execute(
            "INSERT OR REPLACE INTO identifiers (identifier, fingerprint, id_type) VALUES (?, ?, 'fingerprint')",
            (fpr, fpr),
        )
        self._conn.execute(
            "INSERT OR REPLACE INTO identifiers (identifier, fingerprint, id_type) VALUES (?, ?, 'keyid')",
            (kid, fpr),
        )
        self._index_emails(fpr, uids)
        self._conn.commit()

    def get_by_fingerprint(self, fingerprint: str) -> CertRecord | None:
        fpr = fingerprint.upper().removeprefix("0X")
        if len(fpr) == 16:
            row = self._conn.execute(
                "SELECT c.* FROM certs c JOIN identifiers i ON c.fingerprint=i.fingerprint "
                "WHERE i.identifier=? AND i.id_type='keyid'",
                (fpr.lower(),),
            ).fetchone()
        elif len(fpr) == 40:
            row = self._conn.execute(
                "SELECT * FROM certs WHERE fingerprint=?",
                (fpr,),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT * FROM certs WHERE fingerprint=?",
                (fpr,),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def get_by_identifier(self, identifier: str) -> CertRecord | None:
        ident = identifier.lower().removeprefix("0x")
        row = self._conn.execute(
            "SELECT c.* FROM certs c JOIN identifiers i ON c.fingerprint=i.fingerprint WHERE i.identifier=?",
            (ident,),
        ).fetchone()
        return self._row_to_record(row) if row else None

    def get_by_email(self, email: str) -> CertRecord | None:
        row = self._conn.execute(
            "SELECT c.* FROM certs c JOIN emails e ON c.fingerprint=e.fingerprint "
            "WHERE e.email=? AND c.approval_state='approved' LIMIT 1",
            (email.lower(),),
        ).fetchone()
        return self._row_to_record(row) if row else None

    def list_by_email(self, email: str) -> list[CertRecord]:
        target = email.lower()
        seen: set[str] = set()
        out: list[CertRecord] = []
        rows = self._conn.execute(
            "SELECT c.* FROM certs c JOIN emails e ON c.fingerprint=e.fingerprint WHERE e.email=?",
            (target,),
        ).fetchall()
        for row in rows:
            rec = self._row_to_record(row)
            if rec.fingerprint not in seen:
                seen.add(rec.fingerprint)
                out.append(rec)
        for row in self._conn.execute(
            "SELECT * FROM certs WHERE lower(claimer_email)=?",
            (target,),
        ).fetchall():
            rec = self._row_to_record(row)
            if rec.fingerprint not in seen:
                seen.add(rec.fingerprint)
                out.append(rec)
        return out

    def list_by_claimer_oid(self, oid: str) -> list[CertRecord]:
        if not oid:
            return []
        rows = self._conn.execute(
            "SELECT * FROM certs WHERE claimer_oid=?",
            (oid,),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def record_claim(self, fingerprint: str, claimer_email: str, claimer_oid: str) -> None:
        fpr = fingerprint.upper()
        self._conn.execute(
            "UPDATE certs SET claimer_email=?, claimer_oid=?, updated_at=? WHERE fingerprint=?",
            (claimer_email.lower(), claimer_oid, _utcnow(), fpr),
        )
        self._conn.commit()

    def approve(self, fingerprint: str, approved_uids: list[str]) -> None:
        fpr = fingerprint.upper()
        now = _utcnow()
        self._conn.execute(
            "UPDATE certs SET approval_state='approved', approved_uids=?, updated_at=? WHERE fingerprint=?",
            (json.dumps(approved_uids), now, fpr),
        )
        self._index_emails(fpr, approved_uids)
        self._conn.commit()

    def reject(self, fingerprint: str) -> None:
        fpr = fingerprint.upper()
        self._conn.execute(
            "UPDATE certs SET approval_state='rejected', updated_at=? WHERE fingerprint=?",
            (_utcnow(), fpr),
        )
        self._conn.commit()

    def stats(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT approval_state, COUNT(*) as n FROM certs GROUP BY approval_state"
        ).fetchall()
        out = {"total": 0, "pending": 0, "approved": 0, "rejected": 0}
        for row in rows:
            out[row["approval_state"]] = row["n"]
            out["total"] += row["n"]
        return out


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
