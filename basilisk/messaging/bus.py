from __future__ import annotations

import json
import os
from typing import Any, Protocol


class MessageBus(Protocol):
    def enqueue(self, queue: str, message: dict[str, Any]) -> None: ...


class InMemoryBus:
    """Local dev queue stub."""

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    def enqueue(self, queue: str, message: dict[str, Any]) -> None:
        self.messages.append({"queue": queue, "body": message})


class ServiceBusBus:
    """Publish JSON events to Azure Service Bus queues."""

    def __init__(self, connection_string: str) -> None:
        self._connection_string = connection_string
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            from azure.servicebus import ServiceBusClient

            self._client = ServiceBusClient.from_connection_string(self._connection_string)
        return self._client

    def enqueue(self, queue: str, message: dict[str, Any]) -> None:
        from azure.servicebus import ServiceBusMessage

        payload = json.dumps(message).encode("utf-8")
        with self._get_client().get_queue_sender(queue_name=queue) as sender:
            sender.send_messages(
                ServiceBusMessage(body=payload, content_type="application/json")
            )


_bus: MessageBus = InMemoryBus()


def _connection_string() -> str | None:
    for name in ("ServiceBusConnection", "AZURE_SERVICEBUS_CONNECTION_STRING"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


def service_bus_configured() -> bool:
    return _connection_string() is not None


def reset_bus() -> None:
    global _bus
    _bus = InMemoryBus()


def get_bus() -> MessageBus:
    return _bus


def _ensure_bus() -> MessageBus:
    global _bus
    conn = _connection_string()
    if conn and not isinstance(_bus, ServiceBusBus):
        _bus = ServiceBusBus(conn)
    elif not conn and not isinstance(_bus, InMemoryBus):
        _bus = InMemoryBus()
    return _bus


KEY_EVENTS_QUEUE = "key-events"
KEY_APPROVED_QUEUE = "key-approved"
SENDTOKEN_EVENTS_QUEUE = "sendtoken-events"


def enqueue_key_pending(fingerprint: str, uids: list[str], claim_url: str) -> None:
    _ensure_bus().enqueue(
        KEY_EVENTS_QUEUE,
        {
            "event": "key.pending",
            "fingerprint": fingerprint,
            "uids": uids,
            "claim_url": claim_url,
        },
    )


def enqueue_key_approved(fingerprint: str, approved_uids: list[str]) -> None:
    _ensure_bus().enqueue(
        KEY_APPROVED_QUEUE,
        {
            "event": "key.approved",
            "fingerprint": fingerprint,
            "approved_uids": approved_uids,
        },
    )


def enqueue_sendtoken(email: str, token: str, url: str, expires: str, json_ld: dict) -> None:
    _ensure_bus().enqueue(
        SENDTOKEN_EVENTS_QUEUE,
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
    _ensure_bus().enqueue(
        KEY_EVENTS_QUEUE,
        {
            "event": "claim.submitted",
            "fingerprint": fingerprint,
            "claimer_email": claimer_email,
            "claimer_oid": claimer_oid,
            "matched_uids": matched_uids,
        },
    )
