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
# The documented full-mesh ceiling, imported rather than restated: a second
# copy is a second thing that can disagree about how large a room may be.
from basilisk.portal.notebook_signaling import MESH_SOFT_CAP


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


#: One browser in a full mesh holds ``MESH_SOFT_CAP - 1`` links, and
#: ``turn-credentials.js`` states it keeps no cache — "no prefetch, no cache, no
#: warm" — so every link that escalates mints on its own. A shared uplink blip
#: fails all of them in the same instant, which is the burst this must survive.
#: Eight is that ceiling plus one, and deliberately not a budget for eight
#: browsers behind one address all relaying at once: that is the case where the
#: egress bill should push back.
TURN_BURST = MESH_SOFT_CAP

#: Slower than negotiate's two seconds, because the two workloads differ in the
#: way that matters. A negotiation recycles every 240 s forever; a relay
#: escalation happens **once per link, ever** (`relay-fallback.js`: "One
#: escalation per link"), so there is no steady state to fund — only a later,
#: independent incident. Thirty seconds refills the whole bucket in four
#: minutes, which covers a second blip without funding a stream of mints.
#:
#: Note this is *stricter* sustained than the gap it replaces: 5 s allowed 12
#: mints a minute indefinitely, this allows 2. Against a 600 s credential TTL
#: that caps a caller at roughly twenty concurrently-valid credentials rather
#: than a hundred and twenty. The bucket is more permissive only in the instant,
#: which is the only place the real client needed it.
TURN_REFILL_SEC = 30.0


def check_turn_rate(ip: str) -> None:
    """One mint per failed link, and a mesh's worth of links may fail together.

    The gap this replaced assumed links fail one at a time, and said a caller
    hitting the window "is retrying by hand or is not the client". That was
    wrong in the case the fallback exists for: when a shared uplink drops,
    every link fails at once, and `relay-fallback.js` does not retry a refused
    mint -- its `catch` sets phase `unavailable` and no further connection-state
    change re-triggers `_evaluate`. So a refusal here did not delay a link, it
    stranded it until the user restarted the connection by hand.
    """
    if not get_limiter().allow_burst(f"turn:ip:{ip}", TURN_BURST, TURN_REFILL_SEC):
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
