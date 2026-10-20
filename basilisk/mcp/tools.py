"""Read-only lookups against the certificate store this process already has.

Nothing here uploads a key, sends mail, or fetches a URL. A redirect from the
HKP layer is reported and not followed: following it would be a request, and
a request from this process is the thing these tools do not do.
"""

from __future__ import annotations

import json
from typing import Any

from basilisk.db.sqlite_store import sha256_hex
from basilisk.hkp.handlers import get_blob_store, get_store
from basilisk.hkp.lookup import lookup_get, lookup_index
from basilisk.hkp.response import HttpResponse


def _ok(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, default=str)


def _text(resp: HttpResponse) -> str:
    if isinstance(resp.body, bytes):
        return resp.body.decode("utf-8", errors="replace")
    return str(resp.body)


def lookup_key(query: str) -> str:
    """HKP get for one query. Pending keys come back with user IDs stripped."""
    resp = lookup_get(query)
    if resp.status == 302:
        return _ok(
            {
                "status": 302,
                "code": "redirect_not_followed",
                "error": "Lookup would redirect. This tool does not fetch the target.",
            }
        )
    if resp.status != 200:
        return _ok({"status": resp.status, "error": _text(resp)})
    return _ok({"status": 200, "armored": _text(resp)})


def search(query: str) -> str:
    """HKP index for one query. The body is the machine-readable index text."""
    resp = lookup_index(query)
    if resp.status != 200:
        return _ok({"status": resp.status, "error": _text(resp)})
    return _ok({"status": 200, "index": _text(resp)})


def key_status(fingerprint: str) -> str:
    """Approval state and blob integrity for one fingerprint.

    Pending and rejected user IDs are not included. An approved key reports
    only the user IDs that lookup would publish.
    """
    store = get_store()
    record = store.get_by_fingerprint(fingerprint)
    if record is None:
        return _ok({"status": 404, "error": "Not found"})
    integrity = "unreadable"
    try:
        data = get_blob_store().read(record.blob_uri)
    except (OSError, ValueError):
        data = None
    if data is not None:
        integrity = "ok" if sha256_hex(data) == record.sha256 else "mismatch"
    published = list(record.approved_uids or []) if record.approval_state == "approved" else []
    return _ok(
        {
            "status": 200,
            "fingerprint": record.fingerprint,
            "key_id": record.key_id,
            "approval_state": record.approval_state,
            "revoked": bool(record.revoked),
            "expiration": record.key_expiration,
            "published_uids": published,
            "integrity": integrity,
        }
    )
