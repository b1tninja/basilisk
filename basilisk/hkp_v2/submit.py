"""HKP v2 submissions (draft-gallagher-openpgp-hkp-10 §5.2, §7.2).

v2 submission bodies are non-armored certificate bundles (§5.2.4) or a
``multipart/form-data`` part named ``keytext`` (§5.2.5). The store keeps
certificates ASCII-armored, so binary input is armored on the way in; the
existing ingest policy pipeline is otherwise unchanged.

Responses use the §7.2 submission response object.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from basilisk.config import get_settings
from basilisk.db.store import CertStore
from basilisk.hkp.add import ingest_keytext
from basilisk.hkp.handlers import get_blob_store, get_store
from basilisk.hkp_v2.tokens import issue_token, verify_token
from basilisk.messaging.bus import enqueue_sendtoken
from basilisk.openpgp.approve import approve_cert
from basilisk.openpgp.errors import IngestError
from basilisk.openpgp.ingest import parse_armored_keytext
from basilisk.openpgp.keyinfo import parse_cert_info
from basilisk.openpgp.packets import armor_public_key, dearmor

# §7.2 Table 12. Every array is always present so clients need no key probing.
SUBMISSION_FIELDS = ("inserted", "updated", "deleted", "ignored", "invalid")

# Media types advertised by OPTIONS (§5.2.6) and accepted on submission.
ACCEPT_BASIC = "application/pgp-keys"
ACCEPT_TOKEN_PROOF = "application/pgp-keys;proof=tokens"


def empty_submission_response() -> dict[str, list[dict[str, object]]]:
    return {name: [] for name in SUBMISSION_FIELDS}


def normalize_submission(body: bytes) -> str:
    """Return armored keytext for a v2 submission body.

    §5.2.4 requires a non-armored bundle, but ``dearmor()`` passes binary
    through unchanged and decodes armor, so a non-conformant armored
    submission is normalized rather than rejected.
    """
    if not body or not body.strip():
        raise IngestError("Empty submission body", 422)
    try:
        binary = dearmor(body)
    except Exception as exc:  # noqa: BLE001 - malformed base64 in a claimed armor block
        raise IngestError(f"Malformed certificate bundle: {exc}", 422) from exc
    if not binary:
        raise IngestError("Empty certificate bundle", 422)
    return armor_public_key(binary).decode("utf-8")


def cert_ref(binary: bytes, fingerprint: str, comment: str | None = None) -> dict[str, object]:
    """A §7.2 certificate object: ``version`` and ``fingerprint`` are REQUIRED."""
    info = parse_cert_info(binary)
    version = info.primary.version if info else 4
    out: dict[str, object] = {
        "version": version,
        "fingerprint": fingerprint.lower(),
    }
    if comment:
        out["comment"] = comment
    return out


def _identify(body: bytes) -> tuple[bytes, str] | None:
    """Best-effort ``(binary, fingerprint)`` for a body that failed ingest."""
    try:
        binary = dearmor(body)
        info = parse_cert_info(binary)
    except Exception:  # noqa: BLE001 - identification is opportunistic
        return None
    if info is None or not info.primary.fingerprint:
        return None
    return binary, info.primary.fingerprint


def _invalid_response(body: bytes, exc: IngestError) -> tuple[dict | str, int]:
    """§7.2 ``invalid`` entry, or a plain error when the cert cannot be named.

    A conformant certificate object MUST carry version and fingerprint; if the
    bundle is too broken to yield either, there is nothing valid to put in the
    array, so the reason is returned as the response body instead.
    """
    identified = _identify(body)
    if identified is None:
        return str(exc), exc.status
    binary, fingerprint = identified
    response = empty_submission_response()
    response["invalid"].append(cert_ref(binary, fingerprint, str(exc)))
    return response, exc.status


def sendtoken_response(email: str) -> tuple[str, int]:
    """§5.2.2 — mail a time-limited Bearer token; respond with an empty document.

    The token is never echoed in the HTTP response: possession of the mailbox
    is the whole proof.
    """
    if not email or "@" not in email:
        return "Invalid email", 422
    settings = get_settings()
    token = issue_token(email)
    url = f"{settings.base_url}/pks/v2/canonical/{email}"
    # §5.2.2: "The expiry time MUST be given in UTC, in the format
    # yyyy-mm-ddThh:mm:ssZ."
    expires = (datetime.now(timezone.utc) + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    json_ld = {
        "@context": "http://hockeypuck.io/contexts/hkp-sendtoken.jsonld",
        "url": url,
        "token": token,
        "expires": expires,
    }
    enqueue_sendtoken(email, token, url, expires, json_ld)
    return "", 200


def _submit(
    body: bytes,
    store: CertStore,
    blobs,
    *,
    enqueue_events: bool,
) -> tuple[dict, str, bytes]:
    """Ingest one v2 submission; returns (§7.2 response, fingerprint, binary)."""
    keytext = normalize_submission(body)
    binary = dearmor(keytext.encode("utf-8"))
    info = parse_cert_info(binary)
    fingerprint = info.primary.fingerprint if info and info.primary.fingerprint else ""
    existed = store.get_by_fingerprint(fingerprint) is not None if fingerprint else False

    fpr, _key_id, duplicate = ingest_keytext(
        store, blobs, keytext, path="v2", enqueue_events=enqueue_events
    )
    response = empty_submission_response()
    bucket = "ignored" if duplicate else ("updated" if existed else "inserted")
    comment = "Certificate already present with no new information" if duplicate else None
    response[bucket].append(cert_ref(binary, fpr, comment))
    return response, fpr, binary


def certs_post(body: bytes) -> tuple[dict | str, int]:
    """§5.2.1 — ``POST /pks/v2/certs``."""
    store = get_store()
    blobs = get_blob_store()
    try:
        response, _fpr, _binary = _submit(body, store, blobs, enqueue_events=True)
        return response, 200
    except IngestError as exc:
        return _invalid_response(body, exc)


def canonical_put(identity: str, token: str, body: bytes) -> tuple[dict | str, int]:
    """§5.2.3 — ``PUT /pks/v2/canonical/<identity>``.

    "A keyserver MUST verify the request and reject any submissions that
    cannot be verified." The Bearer token proves control of ``identity``, and
    that identity must appear in a User ID of the submitted bundle (§5.2.4.1).
    """
    if not verify_token(token, identity):
        return "Unauthorized", 401
    store = get_store()
    blobs = get_blob_store()
    try:
        response, fpr, binary = _submit(body, store, blobs, enqueue_events=False)
        keytext = armor_public_key(binary).decode("utf-8")
        parsed = parse_armored_keytext(keytext, path="v2")
        from basilisk.hkp_v2.lookup import uid_matches_identity

        matched = [u for u in parsed.uids if uid_matches_identity(u, identity)]
        if not matched:
            invalid = empty_submission_response()
            invalid["invalid"].append(
                cert_ref(
                    binary,
                    fpr,
                    f"No User ID matches the token identity ({identity.lower()})",
                )
            )
            return invalid, 422
        approve_cert(store, fpr, matched)
        return response, 200
    except IngestError as exc:
        return _invalid_response(body, exc)
