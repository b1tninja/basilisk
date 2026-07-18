"""Quorum signaling mailbox unit tests."""

from __future__ import annotations

import pytest

from basilisk.portal.quorum_store import (
    MAX_MESSAGES_PER_ROOM,
    MAX_PAYLOAD_BYTES,
    QuorumMailboxStore,
    reset_quorum_store,
)
from basilisk.security.rate_limit import reset_limiter


@pytest.fixture(autouse=True)
def _reset():
    reset_quorum_store()
    reset_limiter()
    yield
    reset_quorum_store()
    reset_limiter()


@pytest.mark.unit
def test_post_and_poll():
    store = QuorumMailboxStore()
    room = "ABCD2345EFGH67YZ"
    r1 = store.post(room, "msg-one")
    assert r1["seq"] == 1
    r2 = store.post(room, "msg-two")
    assert r2["seq"] == 2
    batch = store.poll(room, since=0)
    assert len(batch["messages"]) == 2
    assert batch["messages"][0]["payload"] == "msg-one"
    mid = store.poll(room, since=1)
    assert len(mid["messages"]) == 1
    assert mid["messages"][0]["seq"] == 2


@pytest.mark.unit
def test_payload_size_cap():
    store = QuorumMailboxStore()
    big = "x" * (MAX_PAYLOAD_BYTES + 1)
    with pytest.raises(ValueError):
        store.post("ABCD2345EFGH67YZ", big)


@pytest.mark.unit
def test_message_cap():
    store = QuorumMailboxStore()
    room = "ABCD2345EFGH67YZ"
    for i in range(MAX_MESSAGES_PER_ROOM):
        store.post(room, f"m{i}")
    with pytest.raises(RuntimeError):
        store.post(room, "overflow")


@pytest.mark.unit
def test_api_post_poll():
    from basilisk.serve import create_app

    client = create_app().test_client()
    room = "ABCD2345EFGH67YZ"
    r = client.post(
        f"/api/v1/quorum/room/{room}/messages",
        json={"payload": "-----BEGIN PGP MESSAGE-----\nhello\n-----END PGP MESSAGE-----"},
    )
    assert r.status_code == 200
    assert r.get_json()["seq"] == 1
    g = client.get(f"/api/v1/quorum/room/{room}/messages?since=0")
    assert g.status_code == 200
    body = g.get_json()
    assert len(body["messages"]) == 1


@pytest.mark.unit
def test_api_rejects_bad_room_id():
    from basilisk.serve import create_app

    client = create_app().test_client()
    r = client.post("/api/v1/quorum/room/not-valid!!!/messages", json={"payload": "x"})
    assert r.status_code == 400
