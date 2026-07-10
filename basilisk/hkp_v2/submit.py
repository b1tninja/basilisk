from __future__ import annotations

from datetime import datetime, timedelta, timezone

from basilisk.config import get_settings
from basilisk.hkp.add import ingest_keytext
from basilisk.hkp.handlers import get_blob_store, get_store
from basilisk.hkp_v2.tokens import issue_token, verify_token
from basilisk.messaging.bus import enqueue_sendtoken
from basilisk.openpgp.approve import approve_cert
from basilisk.openpgp.errors import IngestError
from basilisk.openpgp.ingest import parse_armored_keytext


def sendtoken_response(email: str) -> tuple[dict, int]:
    if not email or "@" not in email:
        return {"error": "Invalid email"}, 422
    settings = get_settings()
    token = issue_token(email)
    url = f"{settings.base_url}/pks/v2/canonical/{email}"
    body = {
        "@context": "http://hockeypuck.io/contexts/hkp-sendtoken.jsonld",
        "url": url,
        "token": token,
        "expires": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
    }
    enqueue_sendtoken(email, token, url, body["expires"], body)
    return body, 200


def canonical_put(identity: str, token: str, keytext: str) -> tuple[dict | str, int]:
    if not verify_token(token, identity):
        return "Unauthorized", 401
    store = get_store()
    blobs = get_blob_store()
    try:
        fpr, _, _dup = ingest_keytext(store, blobs, keytext, path="v2", enqueue_events=False)
        parsed = parse_armored_keytext(keytext, path="v2")
        identity_l = identity.lower()
        matched = [u for u in parsed.uids if identity_l in u.lower()]
        approve_cert(store, fpr, matched or parsed.uids)
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
