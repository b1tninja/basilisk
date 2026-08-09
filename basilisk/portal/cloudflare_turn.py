"""Cloudflare Realtime TURN credentials — the one file that knows the vendor.

Everything provider-specific about the relay lives here: the API host, the URL
shape, the bearer header, the request body and the response field this app
reads back out. ``turn_credentials.py`` above it deals in *a short-lived ICE
server list*, so a second provider would be a sibling of this file rather than
an edit to the route — the same seam ``webpubsub.py`` holds for signalling.

**Why this call is made server-side, and cannot be made from the browser.**
Cloudflare's own instruction is to "keep your TURN key on the server side
(don't share it with the browser/app)": the key is a long-term secret that mints
unlimited short-lived credentials, and a page holding it hands every visitor the
ability to spend the deployment's egress. The second reason is this app's CSP —
``connect-src`` is built by ``Settings.csp_connect_src`` and lists ``'self'``,
the allowlisted keyserver hosts and the signalling socket. Reaching
``rtc.live.cloudflare.com`` from the page would mean widening that policy for
every page load, permanently, to serve a request that happens on the small
minority of connections that fail. The server-side call widens nothing.

**Why ``urllib`` and no new dependency.** One POST with one header and one JSON
body. ``mds_cache.py`` already fetches an upstream blob this way.

**What is not here.** No storage, no cache, no TTL bookkeeping. The credential
Cloudflare returns is already short-lived and is spent within seconds of being
minted; holding one would mean holding a secret with an expiry to track, and
the whole point of the endpoint is that it is stateless.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass

logger = logging.getLogger(__name__)

#: Cloudflare Realtime's credential API. `$TURN_KEY_ID` is a path segment.
API_BASE = "https://rtc.live.cloudflare.com/v1/turn/keys"

#: Seconds. The whole point of the request is that it happens on a connection
#: that has *already* failed, so a caller is waiting on it — long enough to
#: cross the internet, short enough that a hung relay API does not become a
#: hung page.
FETCH_TIMEOUT_SEC = 10


class TurnProviderError(RuntimeError):
    """The provider refused, was unreachable, or answered something unusable."""


@dataclass(frozen=True)
class TurnKey:
    """The long-term secret pair. Never leaves the server."""

    key_id: str
    api_token: str

    def url(self) -> str:
        return f"{API_BASE}/{self.key_id}/credentials/generate-ice-servers"


def generate_ice_servers(key: TurnKey, ttl_sec: int, *, opener=None) -> list[dict]:
    """POST for a fresh credential and return the ``iceServers`` list.

    ``opener`` exists so a test can drive every branch — refusal, garbage,
    timeout — without a network or a real Cloudflare account. It defaults to
    ``urllib.request.urlopen`` and nothing in production passes it.

    :raises TurnProviderError: on any answer this app would not hand a browser.
    """
    if not key.key_id or not key.api_token:
        raise TurnProviderError("TURN key is not configured")
    body = json.dumps({"ttl": int(ttl_sec)}).encode("utf-8")
    req = urllib.request.Request(
        key.url(),
        data=body,
        headers={
            # Bearer, per Cloudflare's docs. The token is the secret; it appears
            # in this header and in no log line, no error message and no
            # response — `_refuse` below is why the except clauses are narrow.
            "Authorization": f"Bearer {key.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "basilisk-turn/1.0",
        },
        method="POST",
    )
    send = opener or urllib.request.urlopen
    try:
        with send(req, timeout=FETCH_TIMEOUT_SEC) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        # The status is news (401 means the token is wrong, 429 means the
        # account is throttled); the body may echo the request and is not
        # logged.
        logger.warning("TURN credential request refused: HTTP %s", exc.code)
        raise TurnProviderError(f"TURN provider refused the request (HTTP {exc.code})") from exc
    except Exception as exc:  # noqa: BLE001 - urllib raises a wide family here
        logger.warning("TURN credential request failed: %s", type(exc).__name__)
        raise TurnProviderError("TURN provider was unreachable") from exc

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise TurnProviderError("TURN provider returned something that is not JSON") from exc

    servers = parsed.get("iceServers") if isinstance(parsed, dict) else None
    # Cloudflare documents a single object; accepting a list of them too costs
    # one branch and means a provider that batches does not need a new parser.
    if isinstance(servers, dict):
        servers = [servers]
    if not isinstance(servers, list) or not servers:
        raise TurnProviderError("TURN provider returned no iceServers")

    clean = [_clean_server(s) for s in servers if isinstance(s, dict)]
    clean = [s for s in clean if s]
    if not clean:
        raise TurnProviderError("TURN provider returned no usable iceServers")
    if not any(_is_relay(s) for s in clean):
        # A list with no `turn:`/`turns:` URL in it is not a relay, and handing
        # it back as one would arm the browser's fallback with servers that
        # cannot carry a byte — the failure would then read as "the relay did
        # not help" rather than "no relay was ever supplied".
        raise TurnProviderError("TURN provider returned no relay URL")
    return clean


def _clean_server(server: dict) -> dict | None:
    """One ``RTCIceServer``, with only the fields WebRTC reads.

    A pass-through would forward whatever the provider chose to include into a
    dictionary the browser hands to ``RTCPeerConnection``. Naming the four
    fields keeps that surface exactly as wide as the WebRTC dictionary is.
    """
    urls = server.get("urls") or server.get("url")
    if isinstance(urls, str):
        urls = [urls]
    if not isinstance(urls, list):
        return None
    kept = [u for u in urls if isinstance(u, str) and _is_ice_url(u)]
    if not kept:
        return None
    out: dict = {"urls": kept}
    for field in ("username", "credential"):
        value = server.get(field)
        if isinstance(value, str) and value:
            out[field] = value
    return out


def _is_ice_url(url: str) -> bool:
    return url.lower().startswith(("stun:", "stuns:", "turn:", "turns:"))


def _is_relay(server: dict) -> bool:
    return any(str(u).lower().startswith(("turn:", "turns:")) for u in server.get("urls", []))
