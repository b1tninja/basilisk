from __future__ import annotations

from basilisk.auth.azure import parse_easy_auth_headers
from basilisk.config import get_settings
from basilisk.db.factory import get_cert_store
from basilisk.messaging.bus import (
    enqueue_claim_submitted,
    enqueue_key_approved,
    service_bus_configured,
)
from basilisk.openpgp.approve import approve_cert
from basilisk.openpgp.canonical import emails_from_uids


def match_claimer_uids(headers: dict[str, str], pending_uids: list[str]) -> list[str]:
    principal = parse_easy_auth_headers(headers)
    if not principal or not principal.get("email"):
        return []
    email = principal["email"].lower()
    matched: list[str] = []
    for uid in pending_uids:
        for em in emails_from_uids([uid]):
            if em == email:
                matched.append(uid)
    return matched


def submit_claim(
    fingerprint: str,
    headers: dict[str, str],
    pending_uids: list[str],
) -> tuple[bool, str]:
    principal = parse_easy_auth_headers(headers)
    if not principal:
        return False, "Authentication required"
    matched = match_claimer_uids(headers, pending_uids)
    if not matched:
        return False, "Email does not match pending UIDs"

    settings = get_settings()
    store = get_cert_store(settings)
    store.record_claim(fingerprint, principal["email"], principal.get("oid", ""))

    if settings.require_manager_approval:
        enqueue_claim_submitted(
            fingerprint,
            principal["email"],
            principal.get("oid", ""),
            matched,
        )
        return True, "Claim submitted for manager approval"

    if service_bus_configured():
        enqueue_key_approved(fingerprint, matched)
        return True, "Claim submitted"

    approve_cert(get_cert_store(settings), fingerprint, matched)
    return True, "Key approved"
