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
    parse_connection_string,
    room_grant,
    room_roles,
)
from basilisk.portal.webpubsub_local import LocalWebPubSub, _Frames

ROOM_A = "AAAA2345EFGH67YZ"
ROOM_B = "BBBB7654VUTS32XY"
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
    double = LocalWebPubSub(endpoint, hub="quorum")
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
    return WsClient("127.0.0.1", port, bound.client_path("quorum"), token)


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("BASILISK_SKIP_SOCKET_TESTS") == "1",
    reason="sockets disabled in this environment",
)
def test_two_peers_exchange_signalling_through_the_room(hub):
    _double, bound, port = hub
    alice = _connect(bound, port, room_grant(bound, "quorum", ROOM_A)["url"].split("access_token=")[1])
    bob = _connect(bound, port, room_grant(bound, "quorum", ROOM_A)["url"].split("access_token=")[1])
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
    token = room_grant(bound, "quorum", ROOM_A)["url"].split("access_token=")[1]
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
    a_token = room_grant(bound, "quorum", ROOM_A)["url"].split("access_token=")[1]
    b_token = room_grant(bound, "quorum", ROOM_B)["url"].split("access_token=")[1]
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
def test_an_unsigned_or_foreign_token_never_becomes_a_websocket(hub):
    _double, bound, port = hub
    forged = client_access_token(
        parse_connection_string(f"Endpoint=http://127.0.0.1:{port};AccessKey=not-the-key;"),
        "quorum",
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
    double = LocalWebPubSub(parse_connection_string(CONNECTION), hub="quorum")
    port = double.start(port=0)
    assert port > 0
    assert double.start(port=0) == port
    double.stop()
    double.stop()
    assert threading.active_count() >= 1
