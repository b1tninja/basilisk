from __future__ import annotations

import json
from typing import Any


class InMemoryBus:
    """Local dev queue stub."""

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    def enqueue(self, queue: str, message: dict[str, Any]) -> None:
        self.messages.append({"queue": queue, "body": message})


_bus = InMemoryBus()


def get_bus() -> InMemoryBus:
    return _bus


def enqueue_key_pending(fingerprint: str, uids: list[str], claim_url: str) -> None:
    _bus.enqueue(
        "key-events",
        {
            "event": "key.pending",
            "fingerprint": fingerprint,
            "uids": uids,
            "claim_url": claim_url,
        },
    )


def enqueue_key_approved(fingerprint: str, approved_uids: list[str]) -> None:
    _bus.enqueue(
        "key-events",
        {
            "event": "key.approved",
            "fingerprint": fingerprint,
            "approved_uids": approved_uids,
        },
    )


def enqueue_sendtoken(email: str, token: str, url: str, expires: str, json_ld: dict) -> None:
    _bus.enqueue(
        "sendtoken-events",
        {
            "event": "sendtoken",
            "email": email,
            "token": token,
            "url": url,
            "expires": expires,
            "json_ld": json_ld,
        },
    )


def enqueue_claim_submitted(
    fingerprint: str, claimer_email: str, claimer_oid: str, matched_uids: list[str]
) -> None:
    _bus.enqueue(
        "key-events",
        {
            "event": "claim.submitted",
            "fingerprint": fingerprint,
            "claimer_email": claimer_email,
            "claimer_oid": claimer_oid,
            "matched_uids": matched_uids,
        },
    )
