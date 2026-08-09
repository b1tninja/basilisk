"""Azure Web PubSub client access tokens — the one file that knows the vendor.

Everything provider-specific about quorum signalling lives here (and in
``webpubsub_local.py``, which speaks the same wire): the connection-string
format, the JWT claim names, the client URL shape, and the subprotocol name.
``quorum_signaling.py`` above it deals in *rooms* and *grants*, so a second
provider would be a sibling of this file rather than an edit to the route.

**Why the JWT is hand-rolled.** The alternative is
``azure-messaging-webpubsubservice``, which pulls ``azure-core``, ``PyJWT`` and
``msrest`` in for one HMAC. The token is a JWS Compact Serialization with a
fixed header — two base64url segments and an HMAC-SHA256 over their
concatenation (RFC 7519 §7.1, RFC 7515 §3.1) — and ``hkp_v2/tokens.py`` already
mints HMAC-SHA256 tokens by hand. The claim structure below is taken from the
service SDK's own local signer (``JwtBuilder`` /
``GenerateTokenFromAzureKeyCredential`` in ``Azure.Messaging.WebPubSub``), not
from memory: ``sub``/``nbf``/``exp``/``iat``/``aud`` as numbers or strings and
``role``/``webpubsub.group`` as JSON **arrays** of strings. Repeated claims in
the docs' prose ("specify multiple ``role`` claims") are arrays in JWT terms —
a JSON object cannot hold a duplicate key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

#: The subprotocol a browser must ask for. A plain ``WebSocket`` speaks it, so
#: the portal needs no npm dependency for signalling.
CLIENT_SUBPROTOCOL = "json.webpubsub.azure.v1"

#: ``{"alg":"HS256","typ":"JWT"}``, base64url with padding stripped. Fixed
#: rather than computed so the bytes that get signed are visible here.
_JWT_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"


class WebPubSubConfigError(RuntimeError):
    """The connection string is missing or malformed."""


@dataclass(frozen=True)
class WebPubSubEndpoint:
    """The two halves of a Web PubSub connection string."""

    endpoint: str
    """Absolute HTTP(S) origin, no trailing slash — e.g. ``https://x.webpubsub.azure.com``."""
    access_key: str
    """The signing key, used as raw UTF-8 bytes (not base64-decoded)."""

    @property
    def host(self) -> str:
        return urlsplit(self.endpoint).netloc

    @property
    def ws_scheme(self) -> str:
        return "ws" if urlsplit(self.endpoint).scheme == "http" else "wss"

    def ws_origin(self) -> str:
        """The ``connect-src`` source a browser needs to open the socket."""
        return f"{self.ws_scheme}://{self.host}"

    def client_path(self, hub: str) -> str:
        return f"/client/hubs/{hub}"

    def audience(self, hub: str) -> str:
        """The ``aud`` claim: the HTTP form of the client endpoint."""
        return f"{self.endpoint}{self.client_path(hub)}"


def parse_connection_string(raw: str) -> WebPubSubEndpoint:
    """``Endpoint=https://…;AccessKey=…;Port=…;Version=1.0;`` → endpoint + key.

    Keys are matched case-insensitively because the portal, the Azure CLI and
    the Bicep output all spell them differently.
    """
    fields: dict[str, str] = {}
    for segment in str(raw or "").split(";"):
        if not segment.strip():
            continue
        if "=" not in segment:
            raise WebPubSubConfigError(
                "Malformed Web PubSub connection string — expected 'key=value' segments"
            )
        key, value = segment.split("=", 1)
        fields.setdefault(key.strip().lower(), value.strip())
    endpoint = fields.get("endpoint", "").rstrip("/")
    access_key = fields.get("accesskey", "")
    if not endpoint:
        raise WebPubSubConfigError("Web PubSub connection string is missing 'Endpoint'")
    if not access_key:
        raise WebPubSubConfigError("Web PubSub connection string is missing 'AccessKey'")
    split = urlsplit(endpoint)
    if split.scheme not in ("http", "https") or not split.netloc:
        raise WebPubSubConfigError(f"Web PubSub 'Endpoint' is not an http(s) URL: {endpoint!r}")
    port = fields.get("port")
    if port:
        if not port.isdigit() or not (0 < int(port) <= 0xFFFF):
            raise WebPubSubConfigError(f"Web PubSub 'Port' is not a port number: {port!r}")
        endpoint = f"{split.scheme}://{split.hostname}:{port}"
    return WebPubSubEndpoint(endpoint=endpoint, access_key=access_key)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def client_access_token(
    endpoint: WebPubSubEndpoint,
    hub: str,
    *,
    user_id: str,
    roles: tuple[str, ...] = (),
    groups: tuple[str, ...] = (),
    lifetime_sec: int = 300,
    issued_at: int | None = None,
) -> str:
    """Sign a client access token (JWS Compact, HS256) for one connection."""
    now = int(time.time()) if issued_at is None else int(issued_at)
    claims: dict[str, object] = {"sub": user_id}
    if roles:
        claims["role"] = list(roles)
    if groups:
        claims["webpubsub.group"] = list(groups)
    claims["nbf"] = now
    claims["exp"] = now + int(lifetime_sec)
    claims["iat"] = now
    claims["aud"] = endpoint.audience(hub)
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{_JWT_HEADER}.{payload}".encode("ascii")
    sig = hmac.new(endpoint.access_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{_JWT_HEADER}.{payload}.{_b64url(sig)}"


def decode_token_claims(token: str) -> dict:
    """Read a token's claims **without** verifying it — for the local double
    and for tests that assert claim shape. Never a trust decision."""
    try:
        payload = token.split(".")[1]
    except IndexError as exc:  # pragma: no cover - malformed input
        raise WebPubSubConfigError("Not a JWS Compact token") from exc
    padded = payload + "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))


def verify_token(endpoint: WebPubSubEndpoint, hub: str, token: str, *, now: float | None = None) -> dict:
    """Verify signature, ``exp``/``nbf`` and ``aud``; return the claims.

    The service does this; the local double calls it so that a token the double
    accepts is a token the service would have accepted too.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise WebPubSubConfigError("Not a JWS Compact token")
    header, payload, sig = parts
    if header != _JWT_HEADER:
        raise WebPubSubConfigError("Unsupported JWT header (expected HS256)")
    expected = hmac.new(
        endpoint.access_key.encode("utf-8"),
        f"{header}.{payload}".encode("ascii"),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(_b64url(expected), sig):
        raise WebPubSubConfigError("Bad token signature")
    claims = decode_token_claims(token)
    ts = time.time() if now is None else now
    if float(claims.get("exp", 0)) < ts:
        raise WebPubSubConfigError("Token expired")
    if float(claims.get("nbf", 0)) > ts + 60:
        raise WebPubSubConfigError("Token not yet valid")
    if claims.get("aud") != endpoint.audience(hub):
        raise WebPubSubConfigError("Token audience does not match this hub")
    return claims


def room_roles(room_id: str) -> tuple[str, ...]:
    """The two role strings that scope a connection to exactly one room.

    A token carrying these cannot join or publish to any other group: the
    service matches the suffix literally, and the unsuffixed
    ``webpubsub.joinLeaveGroup`` / ``webpubsub.sendToGroup`` (which *would* be
    room-wide) are never minted here.
    """
    return (
        f"webpubsub.joinLeaveGroup.{room_id}",
        f"webpubsub.sendToGroup.{room_id}",
    )


def room_grant(
    endpoint: WebPubSubEndpoint,
    hub: str,
    room_id: str,
    *,
    lifetime_sec: int = 300,
    user_id: str | None = None,
) -> dict:
    """A room-scoped connection grant, in the provider-neutral shape the
    ``/api/v1/quorum/negotiate`` contract promises.

    Nothing is stored: the grant *is* the token, and the token expires on its
    own. There is no room record, no TTL sweep and no global room cap to fill.
    """
    uid = user_id or secrets.token_hex(16)
    token = client_access_token(
        endpoint,
        hub,
        user_id=uid,
        roles=room_roles(room_id),
        # Auto-join on connect: one fewer round trip before the first offer,
        # and the client still sends an explicit joinGroup so that a token
        # without this claim behaves identically.
        groups=(room_id,),
        lifetime_sec=lifetime_sec,
    )
    now = int(time.time())
    return {
        "v": 1,
        "room": room_id,
        "transport": "webpubsub",
        "url": f"{endpoint.ws_scheme}://{endpoint.host}{endpoint.client_path(hub)}?access_token={token}",
        "protocol": CLIENT_SUBPROTOCOL,
        "user_id": uid,
        "expires_at": now + int(lifetime_sec),
    }
