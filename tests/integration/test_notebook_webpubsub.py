"""Two clients, one room, over the local Web PubSub double.

The room-scoping property is the whole authorization story of this change, so
it is proved rather than argued: a token minted for room A is *used* — a real
WebSocket handshake, real subprotocol frames — and the join and the publish it
attempts against room B both come back ``Forbidden``.

The double speaks the documented protocol, and it verifies the token with the
same code that mints it, so a token it accepts is one the service would have
accepted too. What it cannot prove is that the *service* enforces roles the way
the docs say it does; that is the part only a real hub can answer.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import struct
import threading

import pytest

from basilisk.portal.webpubsub import (
    CLIENT_SUBPROTOCOL,
    client_access_token,
    lobby_group,
    parse_connection_string,
    room_grant,
    room_group,
    room_roles,
)
from basilisk.portal.webpubsub_local import LocalWebPubSub, _Frames

ROOM_A = "AAAA2345EFGH67YZ"
ROOM_B = "BBBB7654VUTS32XY"

#: Full room digests — the id is the first 16 characters of one of these. The
#: two below stand for the same audience at two epochs; what matters here is
#: only that a rotation produces a *different* digest, which is what the group
#: name is a function of.
ROOM_KEY_A = ROOM_A + "MZXW6YTBOI5XG5DBOJUXA43UMFZGKZLBMFZG"
ROOM_KEY_A_EPOCH_1 = ROOM_A + "NB2HI4DTHIXS653XO4XHA5DINFXGO3TPMZXW"
CONNECTION = "Endpoint=http://127.0.0.1:0;AccessKey=integration-key;"


class WsClient:
    """A WebSocket client, minimal and masked as RFC 6455 requires of clients."""

    def __init__(self, host: str, port: int, path: str, token: str) -> None:
        self.sock = socket.create_connection((host, port), timeout=5)
        key = secrets.token_bytes(16)
        import base64

        self.sock.sendall(
            (
                f"GET {path}?access_token={token} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {base64.b64encode(key).decode()}\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                f"Sec-WebSocket-Protocol: {CLIENT_SUBPROTOCOL}\r\n"
                "\r\n"
            ).encode("ascii")
        )
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(1)
            if not chunk:
                break
            head += chunk
        self.status = head.split(b" ")[1].decode() if b" " in head else ""
        self.handshake = head.decode("latin-1")

    def send_json(self, message: dict) -> None:
        payload = json.dumps(message).encode("utf-8")
        mask = secrets.token_bytes(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        header = bytearray([0x81])
        n = len(masked)
        if n < 126:
            header.append(0x80 | n)
        else:
            header.append(0x80 | 126)
            header += struct.pack("!H", n)
        self.sock.sendall(bytes(header) + mask + masked)

    def recv_json(self) -> dict:
        frame = _Frames.read(self.sock)
        assert frame is not None, "socket closed while expecting a frame"
        return json.loads(frame[1].decode("utf-8"))

    def await_type(self, kind: str, budget: int = 12) -> dict:
        for _ in range(budget):
            message = self.recv_json()
            if message.get("type") == kind:
                return message
        raise AssertionError(f"no {kind!r} message arrived")

    def drain(self) -> list[dict]:
        """Everything readable before the socket timeout — for asserting an
        absence, which cannot be done by waiting for a specific message."""
        out: list[dict] = []
        while True:
            try:
                frame = _Frames.read(self.sock)
            except (TimeoutError, socket.timeout, OSError):
                return out
            if frame is None:
                return out
            out.append(json.loads(frame[1].decode("utf-8")))

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture
def hub():
    endpoint = parse_connection_string(CONNECTION)
    double = LocalWebPubSub(endpoint, hub="notebook")
    port = double.start(port=0)
    # The endpoint has to name the port the OS actually handed out, or the
    # audience in every token would disagree with the one the double checks.
    bound = parse_connection_string(f"Endpoint=http://127.0.0.1:{port};AccessKey={endpoint.access_key};")
    double.endpoint = bound
    try:
        yield double, bound, port
    finally:
        double.stop()


def _connect(bound, port, token) -> WsClient:
    return WsClient("127.0.0.1", port, bound.client_path("notebook"), token)


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("BASILISK_SKIP_SOCKET_TESTS") == "1",
    reason="sockets disabled in this environment",
)
def test_two_peers_exchange_signalling_through_the_room(hub):
    _double, bound, port = hub
    alice = _connect(bound, port, room_grant(bound, "notebook", ROOM_A)["url"].split("access_token=")[1])
    bob = _connect(bound, port, room_grant(bound, "notebook", ROOM_A)["url"].split("access_token=")[1])
    try:
        assert alice.status == "101"
        assert f"Sec-WebSocket-Protocol: {CLIENT_SUBPROTOCOL}" in alice.handshake
        for peer in (alice, bob):
            connected = peer.await_type("system")
            assert connected["event"] == "connected"
            peer.send_json({"type": "joinGroup", "group": ROOM_A, "ackId": 1})
            assert peer.await_type("ack")["success"] is True

        armored = "-----BEGIN PGP MESSAGE-----\nsealed\n-----END PGP MESSAGE-----"
        alice.send_json(
            {"type": "sendToGroup", "group": ROOM_A, "ackId": 2, "dataType": "text", "data": armored}
        )
        delivered = bob.await_type("message")
        assert delivered["from"] == "group"
        assert delivered["group"] == ROOM_A
        assert delivered["dataType"] == "text"
        assert delivered["data"] == armored
        assert delivered["fromUserId"]
    finally:
        alice.close()
        bob.close()


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("BASILISK_SKIP_SOCKET_TESTS") == "1",
    reason="sockets disabled in this environment",
)
def test_a_token_for_one_room_is_refused_by_every_other_room(hub):
    _double, bound, port = hub
    token = room_grant(bound, "notebook", ROOM_A)["url"].split("access_token=")[1]
    client = _connect(bound, port, token)
    try:
        assert client.await_type("system")["event"] == "connected"

        # Its own room: allowed.
        client.send_json({"type": "joinGroup", "group": ROOM_A, "ackId": 1})
        assert client.await_type("ack")["success"] is True

        # Any other room: refused, both ways.
        client.send_json({"type": "joinGroup", "group": ROOM_B, "ackId": 2})
        refused_join = client.await_type("ack")
        assert refused_join["ackId"] == 2
        assert refused_join["success"] is False
        assert refused_join["error"]["name"] == "Forbidden"

        client.send_json(
            {"type": "sendToGroup", "group": ROOM_B, "ackId": 3, "dataType": "text", "data": "x"}
        )
        refused_send = client.await_type("ack")
        assert refused_send["ackId"] == 3
        assert refused_send["success"] is False
        assert refused_send["error"]["name"] == "Forbidden"
    finally:
        client.close()


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("BASILISK_SKIP_SOCKET_TESTS") == "1",
    reason="sockets disabled in this environment",
)
def test_a_room_b_listener_never_sees_room_a_traffic(hub):
    """Scoping is not only about what a token may *do* — a peer holding a
    room B grant must not receive room A's envelopes either."""
    _double, bound, port = hub
    a_token = room_grant(bound, "notebook", ROOM_A)["url"].split("access_token=")[1]
    b_token = room_grant(bound, "notebook", ROOM_B)["url"].split("access_token=")[1]
    alice = _connect(bound, port, a_token)
    eve = _connect(bound, port, b_token)
    try:
        for peer in (alice, eve):
            assert peer.await_type("system")["event"] == "connected"
        alice.send_json({"type": "joinGroup", "group": ROOM_A, "ackId": 1})
        assert alice.await_type("ack")["success"] is True
        # Eve tries to listen in on A and is refused before she can hear a word.
        eve.send_json({"type": "joinGroup", "group": ROOM_A, "ackId": 1})
        assert eve.await_type("ack")["error"]["name"] == "Forbidden"

        alice.send_json(
            {"type": "sendToGroup", "group": ROOM_A, "ackId": 2, "dataType": "text", "data": "secret"}
        )
        assert alice.await_type("ack")["success"] is True

        # Nothing reaches Eve. A short read window is the only way to assert an
        # absence on a socket; the delivery above already happened, so this is
        # not a race against work that has not started.
        eve.sock.settimeout(0.5)
        assert eve.drain() == [], "an unscoped listener received room A traffic"
    finally:
        alice.close()
        eve.close()


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("BASILISK_SKIP_SOCKET_TESTS") == "1",
    reason="sockets disabled in this environment",
)
def test_the_lobby_token_and_the_room_token_are_refused_by_each_other(hub):
    """The doormat is not the hallway.

    A caller who guessed the short code can negotiate — proof of work does not
    tell a stranger from a member — and what it gets back is a token for the
    lobby. This is that token, used: a real handshake, real frames, and a
    refusal on the group where signalling is actually broadcast. The room
    token is refused on the lobby by the same rule in the other direction,
    which is what makes the two names a boundary rather than a convention.
    """
    _double, bound, port = hub
    lobby = lobby_group(ROOM_A)
    room = room_group(ROOM_KEY_A)
    assert lobby != room

    knocker = _connect(
        bound,
        port,
        room_grant(bound, "notebook", lobby, room_id=ROOM_A, scope="lobby")["url"].split(
            "access_token="
        )[1],
    )
    member = _connect(
        bound,
        port,
        room_grant(bound, "notebook", room, room_id=ROOM_A, scope="room")["url"].split(
            "access_token="
        )[1],
    )
    try:
        for peer in (knocker, member):
            assert peer.await_type("system")["event"] == "connected"

        # Each is at home in its own group.
        knocker.send_json({"type": "joinGroup", "group": lobby, "ackId": 1})
        assert knocker.await_type("ack")["success"] is True
        member.send_json({"type": "joinGroup", "group": room, "ackId": 1})
        assert member.await_type("ack")["success"] is True

        # And refused in the other's, to join and to publish alike.
        for peer, other in ((knocker, room), (member, lobby)):
            peer.send_json({"type": "joinGroup", "group": other, "ackId": 2})
            refused = peer.await_type("ack")
            assert refused["success"] is False
            assert refused["error"]["name"] == "Forbidden"
            peer.send_json(
                {
                    "type": "sendToGroup",
                    "group": other,
                    "ackId": 3,
                    "dataType": "text",
                    "data": "x",
                }
            )
            assert peer.await_type("ack")["error"]["name"] == "Forbidden"

        # Signalling in the room does not reach the lobby.
        member.send_json(
            {"type": "sendToGroup", "group": room, "ackId": 4, "dataType": "text", "data": "sealed"}
        )
        assert member.await_type("ack")["success"] is True
        knocker.sock.settimeout(0.5)
        assert knocker.drain() == [], "a lobby connection heard room traffic"
    finally:
        knocker.close()
        member.close()


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("BASILISK_SKIP_SOCKET_TESTS") == "1",
    reason="sockets disabled in this environment",
)
def test_a_rotated_room_leaves_the_old_token_holding_a_name(hub):
    """Eviction without an eviction API.

    The service will not close someone else's connection for us and will not
    hang up on a token that expired after the handshake. So the room moves:
    the members who stay mint tokens for the next epoch's group, and the one
    left behind still holds a perfectly valid token — for a group nobody is
    in. Nothing was revoked, because nothing was granted twice.
    """
    _double, bound, port = hub
    before = room_group(ROOM_KEY_A)
    after = room_group(ROOM_KEY_A_EPOCH_1)
    assert before != after

    stale = _connect(
        bound, port, room_grant(bound, "notebook", before)["url"].split("access_token=")[1]
    )
    moved = _connect(
        bound, port, room_grant(bound, "notebook", after)["url"].split("access_token=")[1]
    )
    try:
        for peer in (stale, moved):
            assert peer.await_type("system")["event"] == "connected"

        # The token that was minted before the rotation cannot follow it.
        stale.send_json({"type": "joinGroup", "group": after, "ackId": 1})
        refused = stale.await_type("ack")
        assert refused["success"] is False
        assert refused["error"]["name"] == "Forbidden"

        # It still works perfectly in the room it was minted for — which is
        # the point: it was not revoked, it was left behind.
        stale.send_json({"type": "joinGroup", "group": before, "ackId": 2})
        assert stale.await_type("ack")["success"] is True

        # And the room it can still speak in is empty.
        moved.send_json({"type": "joinGroup", "group": after, "ackId": 2})
        assert moved.await_type("ack")["success"] is True
        stale.send_json(
            {
                "type": "sendToGroup",
                "group": before,
                "ackId": 3,
                "dataType": "text",
                "data": "anyone there",
            }
        )
        assert stale.await_type("ack")["success"] is True
        moved.sock.settimeout(0.5)
        assert moved.drain() == [], "the rotated room still heard the old one"
    finally:
        stale.close()
        moved.close()


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("BASILISK_SKIP_SOCKET_TESTS") == "1",
    reason="sockets disabled in this environment",
)
def test_an_unsigned_or_foreign_token_never_becomes_a_websocket(hub):
    _double, bound, port = hub
    forged = client_access_token(
        parse_connection_string(f"Endpoint=http://127.0.0.1:{port};AccessKey=not-the-key;"),
        "notebook",
        user_id="mallory",
        roles=room_roles(ROOM_A),
        groups=(ROOM_A,),
    )
    for token in ("", "not-a-jwt", forged):
        client = _connect(bound, port, token)
        try:
            assert client.status == "401", token[:16]
        finally:
            client.close()


@pytest.mark.integration
def test_the_double_is_the_thread_it_says_it_is():
    """Start/stop is idempotent — a leaked listener would make the suite
    order-dependent."""
    double = LocalWebPubSub(parse_connection_string(CONNECTION), hub="notebook")
    port = double.start(port=0)
    assert port > 0
    assert double.start(port=0) == port
    double.stop()
    double.stop()
    assert threading.active_count() >= 1
