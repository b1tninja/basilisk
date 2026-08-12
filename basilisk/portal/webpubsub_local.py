"""A local stand-in for Azure Web PubSub that speaks the real wire.

Web PubSub cannot run on a laptop or in CI, and the alternative — a second
signalling transport behind a flag — is the thing this change exists to remove.
So this is the azurite pattern: a small server that implements the *documented*
protocol (``json.webpubsub.azure.v1``: joinGroup / leaveGroup / sendToGroup /
ping, ack responses, group broadcast, the ``connected`` system message) and is
selected the way ``db/factory.py`` selects SQLite over Azure Table — by whether
the connection string points at it. There is still exactly one client
implementation, because the client cannot tell the two apart.

What it deliberately does **not** stub is authorization: every connection's
token is verified with the same code that mints it, and the ``role`` claims are
enforced per request. A token scoped to room A gets ``Forbidden`` here for the
same reason it would get ``Forbidden`` from the service.

Not implemented, because notebook signalling does not use them: ``event``
requests and upstream event handlers, the streaming frames, ``protobuf``,
binary ``dataType``, permission changes at runtime, and per-connection or
per-user REST sends. A frame this server does not recognise is answered with an
ack error rather than silently dropped, so a client that starts relying on one
fails loudly here instead of only in production.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import socket
import struct
import threading
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

from basilisk.portal.webpubsub import (
    CLIENT_SUBPROTOCOL,
    WebPubSubConfigError,
    WebPubSubEndpoint,
    parse_connection_string,
    verify_token,
)

logger = logging.getLogger(__name__)

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

_OP_TEXT = 0x1
_OP_BINARY = 0x2
_OP_CLOSE = 0x8
_OP_PING = 0x9
_OP_PONG = 0xA


class _Frames:
    """RFC 6455 framing, only as much as the subprotocol needs."""

    @staticmethod
    def encode(payload: bytes, opcode: int = _OP_TEXT) -> bytes:
        header = bytearray([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header.append(n)
        elif n < (1 << 16):
            header.append(126)
            header += struct.pack("!H", n)
        else:
            header.append(127)
            header += struct.pack("!Q", n)
        # Server-to-client frames are never masked (RFC 6455 §5.1).
        return bytes(header) + payload

    @staticmethod
    def read(sock: socket.socket) -> tuple[int, bytes] | None:
        """Next frame as ``(opcode, payload)``, or None at end of stream."""
        head = _recv_exactly(sock, 2)
        if head is None:
            return None
        opcode = head[0] & 0x0F
        masked = bool(head[1] & 0x80)
        length = head[1] & 0x7F
        if length == 126:
            ext = _recv_exactly(sock, 2)
            if ext is None:
                return None
            length = struct.unpack("!H", ext)[0]
        elif length == 127:
            ext = _recv_exactly(sock, 8)
            if ext is None:
                return None
            length = struct.unpack("!Q", ext)[0]
        mask = b""
        if masked:
            got = _recv_exactly(sock, 4)
            if got is None:
                return None
            mask = got
        payload = _recv_exactly(sock, length) if length else b""
        if payload is None:
            return None
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return opcode, payload


def _recv_exactly(sock: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


class _Connection:
    def __init__(self, sock: socket.socket, connection_id: str, user_id: str, claims: dict) -> None:
        self.sock = sock
        self.connection_id = connection_id
        self.user_id = user_id
        self.claims = claims
        self.roles = tuple(str(r) for r in (claims.get("role") or []))
        self.groups: set[str] = set()
        self._lock = threading.Lock()

    def may(self, verb: str, group: str) -> bool:
        """``verb`` is ``joinLeaveGroup`` or ``sendToGroup``.

        Both the wide role and the group-scoped role grant the operation; the
        negotiate endpoint only ever mints the scoped one.
        """
        return f"webpubsub.{verb}" in self.roles or f"webpubsub.{verb}.{group}" in self.roles

    def send_json(self, message: dict) -> None:
        data = json.dumps(message, separators=(",", ":")).encode("utf-8")
        with self._lock:
            try:
                self.sock.sendall(_Frames.encode(data))
            except OSError:
                pass


class LocalWebPubSub:
    """The service, as far as one hub and a handful of groups are concerned."""

    def __init__(self, endpoint: WebPubSubEndpoint, hub: str = "notebook", host: str = "127.0.0.1") -> None:
        self.endpoint = endpoint
        self.hub = hub
        self._host = host
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._connections: set[_Connection] = set()
        self._lock = threading.Lock()
        self._next_id = 0
        self.port = 0

    # ---- lifecycle -------------------------------------------------------

    def start(self, port: int | None = None) -> int:
        if self._server is not None:
            return self.port
        # Three sources for the port, in order: the caller, the endpoint, and —
        # when neither names one — the OS. There used to be a constant here
        # instead of that last case, and a constant is a socket every process on
        # the machine tries to take. Two ``basilisk.serve`` runs side by side
        # meant the second one lost: on Linux it raised ``EADDRINUSE`` here and
        # took the whole server down before Flask started, and where
        # ``SO_REUSEADDR`` also permits a live second binder it came up sharing
        # a port with a double it cannot see. Neither is survivable, so the
        # contention is removed rather than handled.
        named = port if port is not None else urlsplit(self.endpoint.endpoint).port
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self._host, named or 0))
        srv.listen(64)
        self._server = srv
        self.port = srv.getsockname()[1]
        if named is None:
            # Nobody named an address, so nobody can have handed one out yet:
            # this is the last moment at which the endpoint can still be made
            # true, and it has to be, because ``verify_token`` checks every
            # token's ``aud`` against it. A caller that *did* name a port keeps
            # its endpoint — ``webpubsub-hub.js`` passes 0 precisely so the
            # advertised endpoint and the bound socket can differ.
            split = urlsplit(self.endpoint.endpoint)
            self.endpoint = replace(
                self.endpoint, endpoint=f"{split.scheme}://{split.hostname}:{self.port}"
            )
        self._thread = threading.Thread(target=self._accept_loop, name="webpubsub-local", daemon=True)
        self._thread.start()
        logger.info("Local Web PubSub double listening on ws://%s:%d", self._host, self.port)
        return self.port

    def stop(self) -> None:
        srv, self._server = self._server, None
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass
        with self._lock:
            connections = list(self._connections)
            self._connections.clear()
        for conn in connections:
            try:
                conn.sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def __enter__(self) -> LocalWebPubSub:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    # ---- connection handling --------------------------------------------

    def _accept_loop(self) -> None:
        while True:
            srv = self._server
            if srv is None:
                return
            try:
                sock, _addr = srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(sock,), daemon=True).start()

    def _serve(self, sock: socket.socket) -> None:
        try:
            conn = self._handshake(sock)
        except Exception:  # noqa: BLE001 - a bad client must not kill the double
            logger.debug("Local Web PubSub handshake failed", exc_info=True)
            try:
                sock.close()
            except OSError:
                pass
            return
        if conn is None:
            return
        with self._lock:
            self._connections.add(conn)
        conn.send_json(
            {
                "type": "system",
                "event": "connected",
                "userId": conn.user_id,
                "connectionId": conn.connection_id,
            }
        )
        # `webpubsub.group` claims auto-join on connect, exactly as the service
        # does — and exactly as narrowly, since the role check still applies.
        for group in conn.claims.get("webpubsub.group") or []:
            if conn.may("joinLeaveGroup", str(group)):
                conn.groups.add(str(group))
        try:
            self._pump(conn)
        finally:
            with self._lock:
                self._connections.discard(conn)
            try:
                sock.close()
            except OSError:
                pass

    def _handshake(self, sock: socket.socket) -> _Connection | None:
        raw = bytearray()
        while b"\r\n\r\n" not in raw:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            raw += chunk
            if len(raw) > 64 * 1024:
                return None
        head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = head.split("\r\n")
        request_line = lines[0].split(" ")
        if len(request_line) < 2:
            return self._refuse(sock, 400, "Bad Request")
        target = urlsplit(request_line[1])
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()

        if target.path != self.endpoint.client_path(self.hub):
            return self._refuse(sock, 404, "Unknown hub")
        offered = [p.strip() for p in (headers.get("sec-websocket-protocol") or "").split(",")]
        if CLIENT_SUBPROTOCOL not in offered:
            return self._refuse(sock, 400, "Subprotocol required")
        key = headers.get("sec-websocket-key")
        if not key:
            return self._refuse(sock, 400, "Missing Sec-WebSocket-Key")

        token = (parse_qs(target.query).get("access_token") or [""])[0]
        if not token:
            auth = headers.get("authorization") or ""
            if auth.lower().startswith("bearer "):
                token = auth.split(" ", 1)[1].strip()
        try:
            claims = verify_token(self.endpoint, self.hub, token)
        except (WebPubSubConfigError, ValueError):
            # The service answers an unauthorized handshake with 401 before the
            # upgrade; a client that gets here never sees a WebSocket at all.
            return self._refuse(sock, 401, "Unauthorized")

        accept = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()  # noqa: S324 - RFC 6455 mandates SHA-1 here
        ).decode("ascii")
        sock.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n"
                f"Sec-WebSocket-Protocol: {CLIENT_SUBPROTOCOL}\r\n"
                "\r\n"
            ).encode("ascii")
        )
        with self._lock:
            self._next_id += 1
            connection_id = f"local-{self._next_id:08d}"
        return _Connection(sock, connection_id, str(claims.get("sub") or ""), claims)

    def _refuse(self, sock: socket.socket, status: int, reason: str) -> None:
        try:
            sock.sendall(
                f"HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("ascii")
            )
            sock.close()
        except OSError:
            pass
        return None

    # ---- the subprotocol -------------------------------------------------

    def _pump(self, conn: _Connection) -> None:
        while True:
            frame = _Frames.read(conn.sock)
            if frame is None:
                return
            opcode, payload = frame
            if opcode == _OP_CLOSE:
                return
            if opcode == _OP_PING:
                conn.sock.sendall(_Frames.encode(payload, _OP_PONG))
                continue
            if opcode not in (_OP_TEXT, _OP_BINARY):
                continue
            try:
                message = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                # "The Web PubSub service declines the client if the message
                # doesn't match the described format."
                return
            if not isinstance(message, dict):
                return
            self._handle(conn, message)

    def _handle(self, conn: _Connection, message: dict) -> None:
        kind = message.get("type")
        ack_id = message.get("ackId")

        if kind == "ping":
            conn.send_json({"type": "pong"})
            return

        if kind in ("joinGroup", "leaveGroup"):
            group = str(message.get("group") or "")
            if not group:
                self._ack(conn, ack_id, False, "InternalServerError", "group is required")
                return
            if not conn.may("joinLeaveGroup", group):
                self._ack(conn, ack_id, False, "Forbidden", f"no joinLeaveGroup permission for {group}")
                return
            if kind == "joinGroup":
                conn.groups.add(group)
            else:
                conn.groups.discard(group)
            self._ack(conn, ack_id, True)
            return

        if kind == "sendToGroup":
            group = str(message.get("group") or "")
            if not group:
                self._ack(conn, ack_id, False, "InternalServerError", "group is required")
                return
            if not conn.may("sendToGroup", group):
                self._ack(conn, ack_id, False, "Forbidden", f"no sendToGroup permission for {group}")
                return
            data_type = str(message.get("dataType") or "json")
            out = {
                "type": "message",
                "from": "group",
                "group": group,
                "dataType": data_type,
                "data": message.get("data"),
                "fromUserId": conn.user_id,
            }
            no_echo = bool(message.get("noEcho"))
            with self._lock:
                targets = [c for c in self._connections if group in c.groups]
            for target in targets:
                if no_echo and target is conn:
                    continue
                target.send_json(out)
            self._ack(conn, ack_id, True)
            return

        self._ack(conn, ack_id, False, "InternalServerError", f"unsupported request type {kind!r}")

    @staticmethod
    def _ack(
        conn: _Connection,
        ack_id: object,
        success: bool,
        error_name: str = "",
        detail: str = "",
    ) -> None:
        if ack_id is None:
            return  # fire-and-forget, per the ack contract
        body: dict = {"type": "ack", "ackId": ack_id, "success": success}
        if not success:
            body["error"] = {"name": error_name, "message": detail}
        conn.send_json(body)


def start_local_double(connection_string: str, hub: str = "notebook") -> LocalWebPubSub:
    """Start the double described by a connection string pointing at loopback."""
    endpoint = parse_connection_string(connection_string)
    double = LocalWebPubSub(endpoint, hub=hub)
    double.start()
    return double


def main() -> None:  # pragma: no cover - developer entry point
    import argparse

    from basilisk.config import get_settings

    settings = get_settings()
    parser = argparse.ArgumentParser(description="Local Azure Web PubSub double")
    parser.add_argument("--connection-string", default=settings.web_pubsub_connection)
    parser.add_argument("--hub", default=settings.web_pubsub_hub)
    args = parser.parse_args()
    if not args.connection_string:
        raise SystemExit("No Web PubSub connection string configured")
    double = start_local_double(args.connection_string, args.hub)
    # The address, on stdout, because a connection string that names no port
    # gets one from the OS and this process is the only thing that knows it.
    print(f"Local Web PubSub double listening on {double.endpoint.ws_origin()}", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        double.stop()


if __name__ == "__main__":  # pragma: no cover
    main()
