from __future__ import annotations

from datetime import datetime, timedelta, timezone

from basilisk.config import get_settings
from basilisk.hkp.add import ingest_keytext
from basilisk.hkp.handlers import get_blob_store, get_store
from basilisk.hkp_v2.tokens import issue_token, verify_token
from basilisk.messaging.bus import enqueue_sendtoken
from basilisk.openpgp.approve import approve_cert
from basilisk.openpgp.canonical import emails_from_uids
from basilisk.openpgp.errors import IngestError
from basilisk.openpgp.ingest import parse_armored_keytext


def sendtoken_response(email: str) -> tuple[dict, int]:
    """Issue a bearer token and deliver it out-of-band only (never in the HTTP body)."""
    if not email or "@" not in email:
        return {"error": "Invalid email"}, 422
    settings = get_settings()
    token = issue_token(email)
    url = f"{settings.base_url}/pks/v2/canonical/{email}"
    expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
    json_ld = {
        "@context": "http://hockeypuck.io/contexts/hkp-sendtoken.jsonld",
        "url": url,
        "token": token,
        "expires": expires,
    }
    enqueue_sendtoken(email, token, url, expires, json_ld)
    # Do not echo the token — mailbox proof is required to obtain it.
    return {"status": "sent", "email": email.lower(), "expires": expires}, 200


def canonical_put(identity: str, token: str, keytext: str) -> tuple[dict | str, int]:
    if not verify_token(token, identity):
        return "Unauthorized", 401
    store = get_store()
    blobs = get_blob_store()
    try:
        fpr, _, _dup = ingest_keytext(store, blobs, keytext, path="v2", enqueue_events=False)
        parsed = parse_armored_keytext(keytext, path="v2")
        identity_l = identity.lower()
        matched = [u for u in parsed.uids if identity_l in emails_from_uids([u])]
        if not matched:
            return {
                "error": f"No UID on the key matches the token identity ({identity_l})"
            }, 422
        approve_cert(store, fpr, matched)
        return {"status": "published", "fingerprint": fpr}, 200
    except IngestError as exc:
        return str(exc), exc.status


def certs_post(keytext: str) -> tuple[dict | str, int]:
    store = get_store()
    blobs = get_blob_store()
    try:
        fpr, _, dup = ingest_keytext(store, blobs, keytext, path="v2")
        state = "pending" if not dup else "unchanged"
        return {"fingerprint": fpr, "state": state}, 200
    except IngestError as exc:
        return str(exc), exc.status
