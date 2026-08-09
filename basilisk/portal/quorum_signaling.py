"""Quorum signalling negotiation — proof of work in, room-scoped grant out.

This replaced a process-global mailbox dict. On Consumption Functions there is
no shared memory between instances and instances recycle when idle, so two
peers polling the same room only ever met when they happened to land on the
same warm worker: quorum signalling did not reliably work in production. The
signalling state now lives in the service, and this endpoint holds none of it.

The contract is deliberately provider-neutral — a proof of work and a room id
in, a URL, a subprotocol and an expiry out. Nothing above this route (and
nothing in ``lib/quorum/session.js``) names a vendor; the Azure specifics are
all in ``webpubsub.py``.

Two things the mailbox never did:

* **Anti-abuse.** ``verify_proof`` gates this the way it already gates
  ``sendtoken`` and both v2 upload routes. ``quorum_post`` was open to anyone.
* **Authorization.** The minted token carries ``webpubsub.joinLeaveGroup.<room>``
  and ``webpubsub.sendToGroup.<room>`` and nothing wider, so a caller who
  negotiates for room A cannot read or write room B. The old mailbox let any
  caller POST to any room, and its global 256-room cap meant filling rooms
  denied service to everyone.
"""

from __future__ import annotations

import json
import logging
import re

from flask import Flask, Response, request

from basilisk.config import get_settings
from basilisk.observability.metrics import inc
from basilisk.portal.webpubsub import (
    WebPubSubConfigError,
    parse_connection_string,
    room_grant,
)
from basilisk.security.proof import ProofError, verify_proof
from basilisk.security.rate_limit import (
    RateLimitError,
    check_upload_rate,
    client_ip,
    get_limiter,
)

logger = logging.getLogger(__name__)

#: Room ids are derived client-side (hostname + sorted audience fingerprints,
#: base32). The same shape is also a legal Web PubSub group name and a legal
#: role suffix — no dots, no separators the role string would swallow.
ROOM_ID_RE = r"^[A-Z2-7]{8,32}$"


def _json(body: dict, status: int = 200) -> Response:
    return Response(json.dumps(body), status=status, mimetype="application/json")


def check_negotiate_rate(ip: str, room_id: str) -> None:
    """One negotiation per session rather than one call per signalling message,
    so these windows are far looser than they look next to the old mailbox."""
    limiter = get_limiter()
    if not limiter.allow(f"quorum:ip:{ip}", 0.5):
        raise RateLimitError("Quorum rate limit exceeded for this IP")
    if not limiter.allow(f"quorum:room:{room_id}", 0.25):
        raise RateLimitError("Quorum rate limit exceeded for this room")


def register_quorum_signaling(app: Flask) -> None:
    @app.post("/api/v1/quorum/negotiate")
    def quorum_negotiate() -> Response:
        body = request.get_json(silent=True) or {}
        room_id = str(body.get("room") or body.get("room_id") or "").strip().upper()
        if not re.fullmatch(ROOM_ID_RE, room_id):
            return _json({"error": "Invalid room id"}, 400)

        ip = client_ip(dict(request.headers), request.remote_addr)
        try:
            verify_proof(request.headers.get("X-Basilisk-Proof"))
            check_upload_rate(ip)
            check_negotiate_rate(ip, room_id)
        except (ProofError, RateLimitError) as exc:
            inc("rate_limited")
            return _json({"error": str(exc)}, exc.status)

        settings = get_settings()
        if not settings.web_pubsub_connection:
            return _json({"error": "Quorum signalling is not configured"}, 503)
        try:
            endpoint = parse_connection_string(settings.web_pubsub_connection)
        except WebPubSubConfigError as exc:
            # The message names the connection string, never its contents.
            logger.error("Web PubSub connection string rejected: %s", exc)
            return _json({"error": "Quorum signalling is not configured"}, 503)

        return _json(
            room_grant(
                endpoint,
                settings.web_pubsub_hub,
                room_id,
                lifetime_sec=settings.web_pubsub_token_ttl_sec,
            )
        )
