from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from basilisk.db.store import CertRecord, CertStore
from basilisk.openpgp.canonical import parse_uid_parts


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
        self._run_migrations()
        self._ensure_portal_indexes()

    def _ensure_portal_indexes(self) -> None:
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_certs_claimer_email ON certs(claimer_email)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_certs_claimer_oid ON certs(claimer_oid)"
        )
        self._conn.commit()

    def _run_migrations(self) -> None:
        cols = {row[1] for row in self._conn.execute("PRAGMA table_info(certs)")}
        migrations_dir = Path(__file__).resolve().parent / "migrations"
        if "pending_uids" not in cols:
            migration = (migrations_dir / "002_portal.sql").read_text(encoding="utf-8")
            self._conn.executescript(migration)
            self._conn.commit()
            cols = {row[1] for row in self._conn.execute("PRAGMA table_info(certs)")}
        if "key_expiration" not in cols:
            migration = (migrations_dir / "003_key_metadata.sql").read_text(encoding="utf-8")
            self._conn.executescript(migration)
            self._conn.commit()
            cols = {row[1] for row in self._conn.execute("PRAGMA table_info(certs)")}
        if "label" not in cols:
            migration = (migrations_dir / "004_key_label.sql").read_text(encoding="utf-8")
            self._conn.executescript(migration)
            self._conn.commit()
        tables = {
            row[0]
            for row in self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if "cert_history" not in tables:
            migration = (migrations_dir / "005_cert_history.sql").read_text(encoding="utf-8")
            self._conn.executescript(migration)
            self._conn.commit()

    def _row_to_record(self, row: sqlite3.Row) -> CertRecord:
        keys = row.keys()
        pending_raw = row["pending_uids"] if "pending_uids" in keys else "[]"
        return CertRecord(
            fingerprint=row["fingerprint"],
            approval_state=row["approval_state"],
            blob_uri=row["blob_uri"],
            sha256=row["sha256"],
            key_id=row["key_id"],
            approved_uids=json.loads(row["approved_uids"]),
            pending_uids=json.loads(pending_raw or "[]"),
            claimer_email=row["claimer_email"] if "claimer_email" in keys else None,
            claimer_oid=row["claimer_oid"] if "claimer_oid" in keys else None,
            canonical_blob_uri=row["canonical_blob_uri"],
            revoked=bool(row["revoked"]),
            key_expiration=row["key_expiration"] if "key_expiration" in keys else None,
            label=row["label"] if "label" in keys else None,
            created_at=row["created_at"] if "created_at" in keys else None,
            updated_at=row["updated_at"] if "updated_at" in keys else None,
        )

    def _index_emails(self, fingerprint: str, uids: list[str]) -> None:
        fpr = fingerprint.upper()
        self._conn.execute("DELETE FROM emails WHERE fingerprint=?", (fpr,))
        for uid in uids:
            email = parse_uid_parts(uid)["email"]
            if email:
                self._conn.execute(
                    "INSERT OR REPLACE INTO emails (email, fingerprint) VALUES (?, ?)",
                    (email, fpr),
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
        now = _utcnow()
        fpr = fingerprint.upper()
        prior = self.get_by_fingerprint(fpr)
        self._conn.execute(
            """
            INSERT INTO certs (fingerprint, approval_state, blob_uri, sha256, key_id,
                               approved_uids, pending_uids, revoked, key_expiration,
                               created_at, updated_at)
            VALUES (?, 'pending', ?, ?, ?, '[]', ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                approval_state='pending',
                blob_uri=excluded.blob_uri,
                sha256=excluded.sha256,
                key_id=excluded.key_id,
                approved_uids='[]',
                pending_uids=excluded.pending_uids,
                revoked=excluded.revoked,
                key_expiration=excluded.key_expiration,
                updated_at=excluded.updated_at
            """,
            (
                fpr,
                blob_uri,
                sha256,
                key_id,
                json.dumps(uids),
                1 if revoked else 0,
                expiration,
                now,
                now,
            ),
        )
        if prior is None:
            self.append_history(fpr, sha256, "first_seen", recorded_at=now)
        elif prior.sha256 != sha256:
            self.append_history(fpr, sha256, "blob_changed", recorded_at=now)
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

    def list_by_name(self, name_query: str, *, limit: int = 50) -> list[CertRecord]:
        needle = (name_query or "").casefold().strip()
        if len(needle) < 2:
            return []
        out: list[CertRecord] = []
        rows = self._conn.execute(
            "SELECT * FROM certs WHERE approval_state='approved'"
        ).fetchall()
        for row in rows:
            rec = self._row_to_record(row)
            for uid in rec.approved_uids or []:
                parts = parse_uid_parts(uid)
                name = (parts.get("name") or "").casefold()
                raw = (parts.get("raw") or "").casefold()
                if needle in name or (not name and needle in raw):
                    out.append(rec)
                    break
            if len(out) >= limit:
                break
        return out

    def list_approved(self, *, limit: int = 10_000) -> list[CertRecord]:
        rows = self._conn.execute(
            "SELECT * FROM certs WHERE approval_state='approved' LIMIT ?",
            (limit,),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

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
        now = _utcnow()
        prior = self.get_by_fingerprint(fpr)
        self._conn.execute(
            """
            UPDATE certs SET blob_uri=?, sha256=?, key_id=?, revoked=?, key_expiration=?,
                             updated_at=?
            WHERE fingerprint=? AND approval_state='approved'
            """,
            (blob_uri, sha256, key_id, 1 if revoked else 0, expiration, now, fpr),
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
        if prior is None:
            self.append_history(fpr, sha256, "first_seen", recorded_at=now)
        elif prior.sha256 != sha256:
            self.append_history(fpr, sha256, "blob_changed", recorded_at=now)
        self._conn.commit()

    def append_history(
        self,
        fingerprint: str,
        sha256: str,
        event: str,
        *,
        recorded_at: str | None = None,
    ) -> None:
        fpr = fingerprint.upper()
        self._conn.execute(
            """
            INSERT INTO cert_history (fingerprint, sha256, event, recorded_at)
            VALUES (?, ?, ?, ?)
            """,
            (fpr, sha256, event, recorded_at or _utcnow()),
        )

    def list_history(self, fingerprint: str) -> list[dict[str, str]]:
        fpr = fingerprint.upper()
        rows = self._conn.execute(
            """
            SELECT fingerprint, sha256, event, recorded_at
            FROM cert_history
            WHERE fingerprint=?
            ORDER BY id ASC
            """,
            (fpr,),
        ).fetchall()
        return [
            {
                "fingerprint": row["fingerprint"],
                "sha256": row["sha256"],
                "event": row["event"],
                "recorded_at": row["recorded_at"],
            }
            for row in rows
        ]

    def list_pending_older_than(self, cutoff_iso: str) -> list[CertRecord]:
        rows = self._conn.execute(
            "SELECT * FROM certs WHERE approval_state='pending' AND updated_at < ?",
            (cutoff_iso,),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def list_approved_past_expiration(self, now_iso: str) -> list[CertRecord]:
        rows = self._conn.execute(
            """
            SELECT * FROM certs
            WHERE approval_state='approved'
              AND key_expiration IS NOT NULL
              AND key_expiration != ''
              AND key_expiration < ?
            """,
            (now_iso,),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def mark_expired(self, fingerprint: str) -> None:
        fpr = fingerprint.upper()
        self._conn.execute(
            "UPDATE certs SET approval_state='expired', updated_at=? WHERE fingerprint=? AND approval_state='approved'",
            (_utcnow(), fpr),
        )
        self._conn.commit()

    def list_expired_past_grace(self, cutoff_iso: str) -> list[CertRecord]:
        rows = self._conn.execute(
            """
            SELECT * FROM certs
            WHERE approval_state='expired'
              AND key_expiration IS NOT NULL
              AND key_expiration != ''
              AND key_expiration < ?
            """,
            (cutoff_iso,),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def delete_cert(self, fingerprint: str) -> CertRecord | None:
        fpr = fingerprint.upper()
        row = self._conn.execute(
            "SELECT * FROM certs WHERE fingerprint=?", (fpr,)
        ).fetchone()
        if not row:
            return None
        record = self._row_to_record(row)
        self._conn.execute("DELETE FROM emails WHERE fingerprint=?", (fpr,))
        self._conn.execute("DELETE FROM identifiers WHERE fingerprint=?", (fpr,))
        self._conn.execute("DELETE FROM certs WHERE fingerprint=?", (fpr,))
        self._conn.commit()
        return record

    def stats(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT approval_state, COUNT(*) as n FROM certs GROUP BY approval_state"
        ).fetchall()
        out = {"total": 0, "pending": 0, "approved": 0, "rejected": 0, "expired": 0}
        for row in rows:
            out[row["approval_state"]] = row["n"]
            out["total"] += row["n"]
        return out

    def set_label(self, fingerprint: str, label: str | None) -> None:
        fpr = fingerprint.upper()
        self._conn.execute(
            "UPDATE certs SET label=?, updated_at=? WHERE fingerprint=?",
            (label, _utcnow(), fpr),
        )
        self._conn.commit()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
