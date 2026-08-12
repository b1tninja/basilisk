"""Notebook signalling negotiation — proof of work in, room-scoped grant out.

This replaced a process-global mailbox dict. On Consumption Functions there is
no shared memory between instances and instances recycle when idle, so two
peers polling the same room only ever met when they happened to land on the
same warm worker: notebook signalling did not reliably work in production. The
signalling state now lives in the service, and this endpoint holds none of it.

The contract is deliberately provider-neutral — a proof of work and a room id
in, a URL, a subprotocol and an expiry out. Nothing above this route (and
nothing in ``lib/notebook/session.js``) names a vendor; the Azure specifics are
all in ``webpubsub.py``.

Two things the mailbox never did:

* **Anti-abuse.** ``verify_proof`` gates this the way it already gates
  ``sendtoken`` and both v2 upload routes. ``quorum_post`` was open to anyone.
* **Authorization.** The minted token carries ``webpubsub.joinLeaveGroup.<g>``
  and ``webpubsub.sendToGroup.<g>`` for exactly one group ``g`` and nothing
  wider, so a caller who negotiates for room A cannot read or write room B. The
  old mailbox let any caller POST to any room, and its global 256-room cap
  meant filling rooms denied service to everyone.

**Lobby and room are different groups.** Proof of work is an anti-abuse gate,
not an admission decision: it costs a stranger the same as a member. So a
request carrying only a room id gets a token for that room's *lobby*, and only
a request that also carries the room **key** — the full digest, of which the id
is the first 80 bits — gets a token for the group where signalling is actually
broadcast. Computing the key takes the relying party and the full audience, so
holding it means having been told who is meeting rather than having guessed a
short code. The endpoint never sees the audience: it checks that the key it was
given starts with the id it was given, which is a property of the two strings
and tells it nothing about their preimage.
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
    lobby_group,
    parse_connection_string,
    room_grant,
    room_group,
)
from basilisk.security.proof import ProofError, verify_proof
from basilisk.security.rate_limit import (
    RateLimitError,
    client_ip,
    get_limiter,
)

logger = logging.getLogger(__name__)

#: Room ids are derived client-side (hostname + sorted audience fingerprints,
#: base32). The same shape is also a legal Web PubSub group name and a legal
#: role suffix — no dots, no separators the role string would swallow.
ROOM_ID_RE = r"^[A-Z2-7]{8,32}$"

#: The room key is the whole SHA-256 digest in base32 — 52 characters, which
#: is longer than any legal room id, so the two shapes can never be confused
#: for one another.
ROOM_KEY_RE = r"^[A-Z2-7]{52}$"


def _json(body: dict, status: int = 200) -> Response:
    return Response(json.dumps(body), status=status, mimetype="application/json")


#: A full mesh — ``MESH_SOFT_CAP`` in ``lib/notebook/relay.js`` is 8, and the
#: room panel says so out loud past that. One NAT can present a whole room as
#: one address, so a per-IP budget that cannot hold a full mesh refuses an
#: office starting a session together.
MESH_SOFT_CAP = 8

#: A room's audience is fixed when the room is derived, so the largest
#: legitimate burst is every member negotiating at once. Doubled because a
#: reconnect is correlated — when a shared uplink blips, every link fails and
#: every peer re-dials in the same instant — so a full mesh may plausibly spend
#: its whole membership twice before anything has had time to refill. The same
#: size serves both keys: they differ in what they cap (one address, versus one
#: room across every address), not in how large a legitimate burst is. If
#: anything the correlation is stronger per-IP, because sharing an address is
#: sharing the uplink whose blip dropped every link at once.
NEGOTIATE_BURST = MESH_SOFT_CAP * 2

#: Steady state is one negotiation per peer per recycle cycle: at the shipped
#: 300 s token TTL ``signaling.js`` recycles at 240 s, so a full mesh behind one
#: address is one call every 30 s. Two seconds is fifteen times that and still
#: holds a client that has stopped backing off to half a call per second.
NEGOTIATE_REFILL_SEC = 2.0


def check_negotiate_rate(ip: str, room_id: str) -> None:
    """One negotiation per session rather than one call per signalling message.

    A burst rather than a minimum gap, because refusing here is not a delay:
    ``signaling.js`` rejects its ``ready`` promise on a failed first dial, so a
    refused negotiation surfaces as ``quorum.offer`` throwing and the run
    stopping. The calls that arrive together are a start, a join and a
    reconnect from every peer that shares an address — all of them ordinary.

    This is deliberately *not* ``check_upload_rate``. Publishing a key and
    starting a session are unrelated acts, and charging them to one bucket made
    each one lock the other out for the upload window.
    """
    limiter = get_limiter()
    if not limiter.allow_burst(f"notebook:ip:{ip}", NEGOTIATE_BURST, NEGOTIATE_REFILL_SEC):
        raise RateLimitError("Session negotiation rate limit exceeded for this IP")
    if not limiter.allow_burst(f"notebook:room:{room_id}", NEGOTIATE_BURST, NEGOTIATE_REFILL_SEC):
        raise RateLimitError("Session negotiation rate limit exceeded for this room")


def register_notebook_signaling(app: Flask) -> None:
    @app.post("/api/v1/notebook/negotiate")
    def notebook_negotiate() -> Response:
        body = request.get_json(silent=True) or {}
        room_id = str(body.get("room") or body.get("room_id") or "").strip().upper()
        if not re.fullmatch(ROOM_ID_RE, room_id):
            return _json({"error": "Invalid room id"}, 400)

        room_key = str(body.get("key") or body.get("room_key") or "").strip().upper()
        if room_key:
            if not re.fullmatch(ROOM_KEY_RE, room_key):
                return _json({"error": "Invalid room key"}, 400)
            # The id must be the prefix of the key, or the two describe
            # different rooms and the rate limit was charged to the wrong one.
            if not room_key.startswith(room_id):
                return _json({"error": "Room key does not match room id"}, 400)

        ip = client_ip(dict(request.headers), request.remote_addr)
        try:
            verify_proof(request.headers.get("X-Basilisk-Proof"))
            check_negotiate_rate(ip, room_id)
        except (ProofError, RateLimitError) as exc:
            inc("rate_limited")
            return _json({"error": str(exc)}, exc.status)

        settings = get_settings()
        if not settings.web_pubsub_connection:
            return _json({"error": "Notebook signalling is not configured"}, 503)
        try:
            endpoint = parse_connection_string(settings.web_pubsub_connection)
        except WebPubSubConfigError as exc:
            # The message names the connection string, never its contents.
            logger.error("Web PubSub connection string rejected: %s", exc)
            return _json({"error": "Notebook signalling is not configured"}, 503)

        return _json(
            room_grant(
                endpoint,
                settings.web_pubsub_hub,
                room_group(room_key) if room_key else lobby_group(room_id),
                room_id=room_id,
                scope="room" if room_key else "lobby",
                lifetime_sec=settings.web_pubsub_token_ttl_sec,
            )
        )
