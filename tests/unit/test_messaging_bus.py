import pytest

from basilisk.messaging.bus import (
    KEY_APPROVED_QUEUE,
    KEY_EVENTS_QUEUE,
    InMemoryBus,
    enqueue_claim_submitted,
    enqueue_key_approved,
    enqueue_key_pending,
    get_bus,
    reset_bus,
    service_bus_configured,
)


@pytest.mark.unit
def test_in_memory_enqueue_key_pending():
    reset_bus()
    enqueue_key_pending("ABCD" * 10, ["a@example.com"], "http://localhost/claim/ABCD")
    bus = get_bus()
    assert isinstance(bus, InMemoryBus)
    assert len(bus.messages) == 1
    msg = bus.messages[0]
    assert msg["queue"] == KEY_EVENTS_QUEUE
    assert msg["body"]["event"] == "key.pending"
    assert msg["body"]["claim_url"] == "http://localhost/claim/ABCD"


@pytest.mark.unit
def test_in_memory_enqueue_key_approved_uses_approved_queue():
    reset_bus()
    enqueue_key_approved("ABCD" * 10, ["a@example.com"])
    bus = get_bus()
    assert bus.messages[0]["queue"] == KEY_APPROVED_QUEUE
    assert bus.messages[0]["body"]["event"] == "key.approved"


@pytest.mark.unit
def test_in_memory_enqueue_claim_submitted():
    reset_bus()
    enqueue_claim_submitted("ABCD" * 10, "a@example.com", "oid-1", ["a@example.com"])
    bus = get_bus()
    assert bus.messages[0]["queue"] == KEY_EVENTS_QUEUE
    assert bus.messages[0]["body"]["event"] == "claim.submitted"


@pytest.mark.unit
def test_service_bus_configured_false_without_env(monkeypatch):
    monkeypatch.delenv("ServiceBusConnection", raising=False)
    monkeypatch.delenv("AZURE_SERVICEBUS_CONNECTION_STRING", raising=False)
    reset_bus()
    assert service_bus_configured() is False
