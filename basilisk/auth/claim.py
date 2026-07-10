from __future__ import annotations

import re

from basilisk.auth.azure import parse_easy_auth_headers
from basilisk.messaging.bus import enqueue_claim_submitted
from basilisk.openpgp.canonical import emails_from_uids
from basilisk.openpgp.types import uid_string


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
    enqueue_claim_submitted(
        fingerprint,
        principal["email"],
        principal.get("oid", ""),
        matched,
    )
    return True, "Claim submitted"
