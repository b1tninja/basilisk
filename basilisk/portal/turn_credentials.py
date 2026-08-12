"""TURN relay credentials — proof of work in, a short-lived ICE server list out.

The relay is a **fallback**, and the endpoint is shaped by that. A browser calls
it only after a connection has already reached ``failed``: on the large majority
of connections, which form directly, this route is never reached and the relay
operator learns nothing — not an address, not a timestamp, not that a
connection was attempted. That property lives in the client
(``lib/webrtc/relay-fallback.js`` gathers and connects with no TURN first), and
this route is what makes it affordable, because there is no standing credential
to hand out ahead of time.

Modelled on ``notebook_signaling.py``, which has the same shape — a gated,
stateless mint in front of a vendor file:

* **Nothing stored.** No TTL bookkeeping, no per-room record, no cache. The
  credential Cloudflare returns already carries its own expiry and is spent
  within seconds. A cache here would be a secret with a lifetime to manage, in
  a process that recycles when idle.
* **Anti-abuse.** ``verify_proof`` gates it exactly as it gates
  ``notebook_negotiate``, ``sendtoken`` and both v2 upload routes, and
  ``check_turn_rate`` meters it behind that. The meter is this route's own and
  not the key-publishing one: a relay mint and a key upload are unrelated acts,
  and a shared bucket meant either could take a failing link's one escalation
  away. Unlike those routes, an unmetered caller here spends the deployment's
  *own* relay egress — Cloudflare's free tier is 1 TB/month — so the gate is
  the difference between a fallback and an open relay.
* **Provider-neutral above, vendor-specific below.** This file deals in an
  ``iceServers`` list; ``cloudflare_turn.py`` knows the URL, the bearer token
  and the response shape. Nothing above this route names a vendor.

Unconfigured is the shipped state and answers 503. There is no default relay:
a TURN server that appears because an env var was left at a default is a third
party carrying every byte of a connection nobody chose it for.
"""

from __future__ import annotations

import json
import logging
import time

from flask import Flask, Response, request

from basilisk.config import get_settings
from basilisk.observability.metrics import inc
from basilisk.portal.cloudflare_turn import TurnKey, TurnProviderError, generate_ice_servers
from basilisk.security.proof import ProofError, verify_proof
from basilisk.security.rate_limit import (
    RateLimitError,
    client_ip,
    get_limiter,
)

logger = logging.getLogger(__name__)

#: What the browser is told the relay can and cannot observe, in the same words
#: the UI uses. Carried in the response so a credential and its disclosure
#: cannot drift apart, and so a downloaded artifact explains itself.
DISCLOSURE = {
    "reads_traffic": False,
    "sees_addresses": True,
    "summary": (
        "A TURN relay forwards this connection's packets. It cannot read them — "
        "the data channel is DTLS end-to-end between the two peers and the relay "
        "carries ciphertext it holds no key for. It can see both peers' IP "
        "addresses, when the connection ran, and how much data crossed it."
    ),
}


def _json(body: dict, status: int = 200) -> Response:
    return Response(json.dumps(body), status=status, mimetype="application/json")


def check_turn_rate(ip: str) -> None:
    """One mint per failed connection, not one per candidate pair.

    Looser than it looks: escalation happens once per link and the client is
    forbidden from asking twice for the same one, so a caller hitting this
    window is retrying by hand or is not the client.
    """
    if not get_limiter().allow(f"turn:ip:{ip}", 5.0):
        raise RateLimitError("TURN credential rate limit exceeded for this IP")


def register_turn_credentials(app: Flask) -> None:
    @app.post("/api/v1/turn/credentials")
    def turn_credentials() -> Response:
        ip = client_ip(dict(request.headers), request.remote_addr)
        try:
            verify_proof(request.headers.get("X-Basilisk-Proof"))
            check_turn_rate(ip)
        except (ProofError, RateLimitError) as exc:
            inc("rate_limited")
            return _json({"error": str(exc)}, exc.status)

        settings = get_settings()
        if not settings.turn_key_id or not settings.turn_api_token:
            # Both halves or nothing. A half-configured deployment is a
            # deployment with no relay, and saying so is better than a 500 from
            # inside the provider call.
            return _json({"error": "TURN relay is not configured"}, 503)

        ttl = max(60, int(settings.turn_credential_ttl_sec))
        try:
            servers = generate_ice_servers(
                TurnKey(settings.turn_key_id, settings.turn_api_token), ttl
            )
        except TurnProviderError as exc:
            # The message names the provider's behaviour and never the key.
            logger.error("TURN credential mint failed: %s", exc)
            return _json({"error": "TURN relay is unavailable"}, 503)

        return _json(
            {
                "v": 1,
                "provider": "cloudflare",
                "iceServers": servers,
                "ttl": ttl,
                # Derived, not recorded. Nothing here remembers having issued
                # it; this is the client's cue to stop reusing it, not a
                # server-side lifetime.
                "expires_at": int(time.time()) + ttl,
                "disclosure": DISCLOSURE,
            }
        )
