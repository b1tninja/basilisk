"""The v2 "index" lookup category (draft-gallagher-openpgp-hkp-10 §5.1.5, §7.1.1).

Returns ``application/json``: a list of certificate objects. Only ``version``
and ``fingerprint`` (and ``uidString`` on User IDs) are required; every other
field is emitted only when it can actually be derived from the stored
certificate, per §7.1.1 ("Implementations MAY omit algorithms, subkeys and
User IDs from indexes; however if they are present they MUST contain the
required fields").
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from basilisk.config import Settings
from basilisk.db.blob_store import LocalBlobStore
from basilisk.db.store import CertRecord, CertStore
from basilisk.hkp.response import HttpResponse
from basilisk.hkp_v2.lookup import (
    CONFIDENCE_APPROVED,
    CONFIDENCE_UNVERIFIED,
    JSON_MEDIA_TYPE,
    resolve_stores,
    records_for_identity,
    uid_matches_identity,
    v2_response,
)
from basilisk.openpgp.keyinfo import CertInfo, KeyInfo, is_expired, parse_cert_info, rfc3339
from basilisk.openpgp.packets import dearmor


def _algorithm_object(key: KeyInfo) -> dict[str, object] | None:
    """Table 9. ``code`` is REQUIRED, so omit the object entirely without one."""
    if key.algorithm is None:
        return None
    out: dict[str, object] = {"code": key.algorithm}
    name = key.algorithm_name
    if name:
        out["name"] = name
    if key.bit_length:
        out["bitLength"] = key.bit_length
    return out


def _key_object(key: KeyInfo, *, now: datetime) -> dict[str, object] | None:
    """Tables 8/11 key fields. ``version`` and ``fingerprint`` are REQUIRED."""
    if key.fingerprint is None:
        return None
    out: dict[str, object] = {
        "version": key.version,
        "fingerprint": key.fingerprint.lower(),
    }
    creation = rfc3339(key.creation)
    if creation:
        out["creation"] = creation
    expiration = rfc3339(key.expiration)
    if expiration:
        out["expiration"] = expiration
        out["isExpired"] = is_expired(key.expiration, now=now)
    out["isRevoked"] = key.is_revoked
    algorithm = _algorithm_object(key)
    if algorithm:
        out["algorithm"] = algorithm
    return out


def _uid_objects(
    info: CertInfo, record: CertRecord, identity: str | None, *, now: datetime
) -> list[dict[str, object]]:
    """Table 10. ``uidString`` is REQUIRED.

    A User ID reaches complete confidence (§8) only when it is on this
    server's approved list, which requires mailbox proof.
    """
    approved = {u.strip().casefold() for u in (record.approved_uids or [])}
    out: list[dict[str, object]] = []
    for uid in info.user_ids:
        obj: dict[str, object] = {"uidString": uid.uid}
        creation = rfc3339(uid.creation)
        if creation:
            obj["creation"] = creation
        expiration = rfc3339(uid.expiration)
        if expiration:
            obj["expiration"] = expiration
            obj["isExpired"] = is_expired(uid.expiration, now=now)
        obj["isRevoked"] = uid.is_revoked
        obj["confidence"] = (
            CONFIDENCE_APPROVED
            if uid.uid.strip().casefold() in approved
            else CONFIDENCE_UNVERIFIED
        )
        out.append(obj)
    if identity:
        # §5.1.5: sorted in decreasing order of confidence.
        out.sort(key=lambda o: int(o.get("confidence", 0)), reverse=True)
        out.sort(key=lambda o: uid_matches_identity(str(o["uidString"]), identity), reverse=True)
    return out


def cert_object(
    record: CertRecord,
    binary: bytes,
    *,
    identity: str | None = None,
    now: datetime | None = None,
) -> dict[str, object] | None:
    """Build one Table 8 certificate object, or ``None`` if it cannot be parsed."""
    now = now or datetime.now(timezone.utc)
    info = parse_cert_info(binary)
    if info is None:
        return None
    obj = _key_object(info.primary, now=now)
    if obj is None:
        # Fall back to the stored fingerprint when the packet parser cannot
        # derive one (e.g. an unknown key version); version stays authoritative.
        obj = {"version": info.primary.version, "fingerprint": record.fingerprint.lower()}
    if record.revoked:
        obj["isRevoked"] = True
    uids = _uid_objects(info, record, identity, now=now)
    if uids:
        obj["userIDs"] = uids
    subkeys = [k for k in (_key_object(s, now=now) for s in info.subkeys) if k]
    if subkeys:
        obj["subkeys"] = subkeys
    return obj


def index_for_identity(
    identity: str,
    store: CertStore | None = None,
    blobs: LocalBlobStore | None = None,
    settings: Settings | None = None,
) -> HttpResponse:
    """§5.1.5 — JSON index of certificates whose User IDs match ``identity``."""
    store, blobs, settings = resolve_stores(store, blobs, settings)
    records = records_for_identity(identity, store)
    if not records:
        return v2_response(404, "Not found")

    now = datetime.now(timezone.utc)
    out: list[dict[str, object]] = []
    for record in records:
        try:
            binary = dearmor(blobs.read(record.blob_uri))
        except Exception:  # noqa: BLE001 - one unreadable blob must not fail the index
            continue
        obj = cert_object(record, binary, identity=identity, now=now)
        if obj:
            out.append(obj)
    if not out:
        return v2_response(404, "Not found")
    return v2_response(200, json.dumps(out), mimetype=JSON_MEDIA_TYPE)
