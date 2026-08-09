"""The quorum negotiate endpoint and the tokens it mints.

Three properties carry the change and are asserted here rather than assumed:
the endpoint is gated by proof of work (the mailbox it replaced was gated by
nothing), the token it returns is scoped to exactly one group, and *which*
group depends on whether the caller could produce the room key or only the
room id. Proof of work is an anti-abuse gate and costs a stranger exactly what
it costs a member, so it decides how often anyone may ask — never who gets in.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from basilisk.config import get_settings
from basilisk.portal.webpubsub import (
    WebPubSubConfigError,
    client_access_token,
    decode_token_claims,
    lobby_group,
    parse_connection_string,
    room_grant,
    room_group,
    room_roles,
    verify_token,
)
from basilisk.security.rate_limit import reset_limiter

CONNECTION = "Endpoint=https://basilisk.webpubsub.azure.com;AccessKey=super-secret-key;Version=1.0;"
ROOM = "ABCD2345EFGH67YZ"
OTHER_ROOM = "ZYXW7654VUTS32BA"

#: A room key is the whole base32 digest and a room id is its first 16
#: characters, so a key that belongs to `ROOM` has to start with it.
ROOM_KEY = ROOM + "MZXW6YTBOI5XG5DBOJUXA43UMFZGKZLBMFZG"
assert len(ROOM_KEY) == 52


def _claims_of(grant: dict) -> dict:
    return decode_token_claims(grant["url"].split("access_token=")[1])


@pytest.fixture(autouse=True)
def _reset():
    reset_limiter()
    get_settings.cache_clear()
    yield
    reset_limiter()
    get_settings.cache_clear()


def _client(monkeypatch, env: dict[str, str] | None = None):
    """A test client whose settings come from the environment, the way the
    process's do — `verify_proof` reads `get_settings` through its own module
    import, so patching one binding of it would leave the gate untested."""
    from basilisk.serve import create_app

    monkeypatch.setenv("AZURE_WEBPUBSUB_CONNECTION_STRING", CONNECTION)
    monkeypatch.setenv("BASILISK_WEBPUBSUB_HUB", "quorum")
    for name, value in (env or {}).items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    return create_app().test_client()


@pytest.mark.unit
def test_connection_string_is_parsed_like_the_sdk_parses_it():
    endpoint = parse_connection_string(CONNECTION)
    assert endpoint.endpoint == "https://basilisk.webpubsub.azure.com"
    assert endpoint.access_key == "super-secret-key"
    assert endpoint.ws_origin() == "wss://basilisk.webpubsub.azure.com"
    assert endpoint.audience("quorum") == "https://basilisk.webpubsub.azure.com/client/hubs/quorum"

    # A local endpoint keeps its port and drops to ws:// — the double is
    # addressed exactly like the service.
    local = parse_connection_string("Endpoint=http://127.0.0.1:8081;AccessKey=k;")
    assert local.ws_origin() == "ws://127.0.0.1:8081"

    for bad in ("", "nonsense", "AccessKey=k", "Endpoint=ftp://x;AccessKey=k"):
        with pytest.raises(WebPubSubConfigError):
            parse_connection_string(bad)


@pytest.mark.unit
def test_token_is_a_jws_the_service_would_accept():
    endpoint = parse_connection_string(CONNECTION)
    token = client_access_token(
        endpoint,
        "quorum",
        user_id="u1",
        roles=room_roles(ROOM),
        groups=(ROOM,),
        lifetime_sec=300,
        issued_at=1_700_000_000,
    )
    header_b64, payload_b64, sig_b64 = token.split(".")

    def unb64(seg: str) -> bytes:
        return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))

    assert json.loads(unb64(header_b64)) == {"alg": "HS256", "typ": "JWT"}
    # Base64url, unpadded — a `=` in a query string would be re-encoded and the
    # signature would no longer verify.
    assert "=" not in token and "+" not in token and "/" not in token

    claims = json.loads(unb64(payload_b64))
    assert claims["sub"] == "u1"
    # Repeated `role` / `webpubsub.group` claims are JSON arrays: an object
    # cannot hold a duplicate key, and the service's own signer writes arrays.
    assert claims["role"] == list(room_roles(ROOM))
    assert claims["webpubsub.group"] == [ROOM]
    assert claims["iat"] == claims["nbf"] == 1_700_000_000
    assert claims["exp"] == 1_700_000_300
    assert claims["aud"] == "https://basilisk.webpubsub.azure.com/client/hubs/quorum"

    expected = hmac.new(
        b"super-secret-key", f"{header_b64}.{payload_b64}".encode("ascii"), hashlib.sha256
    ).digest()
    assert base64.urlsafe_b64encode(expected).rstrip(b"=").decode() == sig_b64


@pytest.mark.unit
def test_verify_rejects_a_tampered_or_stale_or_misaudienced_token():
    endpoint = parse_connection_string(CONNECTION)
    token = client_access_token(endpoint, "quorum", user_id="u1", lifetime_sec=300)
    assert verify_token(endpoint, "quorum", token)["sub"] == "u1"

    header, payload, sig = token.split(".")
    with pytest.raises(WebPubSubConfigError):
        verify_token(endpoint, "quorum", f"{header}.{payload}.{'A' * len(sig)}")
    # Same key, different hub — the audience binds the token to one endpoint.
    with pytest.raises(WebPubSubConfigError):
        verify_token(endpoint, "other-hub", token)
    expired = client_access_token(
        endpoint, "quorum", user_id="u1", lifetime_sec=1, issued_at=int(time.time()) - 3600
    )
    with pytest.raises(WebPubSubConfigError):
        verify_token(endpoint, "quorum", expired)


@pytest.mark.unit
def test_the_grant_is_scoped_to_one_room_and_names_no_other():
    endpoint = parse_connection_string(CONNECTION)
    grant = room_grant(endpoint, "quorum", ROOM, lifetime_sec=300)
    assert grant["transport"] == "webpubsub"
    assert grant["protocol"] == "json.webpubsub.azure.v1"
    assert grant["url"].startswith(
        "wss://basilisk.webpubsub.azure.com/client/hubs/quorum?access_token="
    )
    claims = decode_token_claims(grant["url"].split("access_token=")[1])
    # The wide roles would let a holder read and write every room on the hub.
    assert "webpubsub.joinLeaveGroup" not in claims["role"]
    assert "webpubsub.sendToGroup" not in claims["role"]
    assert all(role.endswith(f".{ROOM}") for role in claims["role"])
    assert claims["webpubsub.group"] == [ROOM]
    assert OTHER_ROOM not in json.dumps(claims)

    # Nothing is stored, so two grants for the same room are independent
    # connections rather than a shared record.
    other = room_grant(endpoint, "quorum", ROOM)
    assert other["user_id"] != grant["user_id"]


@pytest.mark.unit
def test_a_guessed_room_id_reaches_the_lobby_and_stops(monkeypatch):
    """Proof of work costs a stranger exactly what it costs a member, so it
    cannot be the thing that decides admission. A caller holding nothing but a
    room id gets a token for that room's lobby — a real group, joinable, and
    not the one signalling is broadcast in."""
    client = _client(monkeypatch)
    r = client.post("/api/v1/quorum/negotiate", json={"room": ROOM})
    assert r.status_code == 200
    body = r.get_json()
    assert body["room"] == ROOM
    assert body["scope"] == "lobby"
    assert body["group"] == lobby_group(ROOM)
    assert body["expires_at"] > time.time()

    claims = _claims_of(body)
    assert set(claims["role"]) == set(room_roles(lobby_group(ROOM)))
    assert claims["webpubsub.group"] == [lobby_group(ROOM)]
    # The hallway is not named anywhere in what the doormat was handed.
    assert room_group(ROOM_KEY) not in json.dumps(claims)


@pytest.mark.unit
def test_the_room_key_is_what_buys_the_room(monkeypatch):
    client = _client(monkeypatch)
    r = client.post("/api/v1/quorum/negotiate", json={"room": ROOM, "key": ROOM_KEY})
    assert r.status_code == 200
    body = r.get_json()
    assert body["scope"] == "room"
    assert body["group"] == room_group(ROOM_KEY)
    # Same room, two scopes, two groups that share no role string.
    assert room_group(ROOM_KEY) != lobby_group(ROOM)
    claims = _claims_of(body)
    assert set(claims["role"]) == set(room_roles(room_group(ROOM_KEY)))
    assert not set(claims["role"]) & set(room_roles(lobby_group(ROOM)))


@pytest.mark.unit
def test_a_room_key_that_is_not_this_rooms_is_refused(monkeypatch):
    client = _client(monkeypatch)
    for key in (
        OTHER_ROOM + ROOM_KEY[len(OTHER_ROOM) :],  # right shape, wrong room
        ROOM_KEY[:-1],  # too short to be a digest
        ROOM_KEY + "A",  # too long
        ROOM_KEY[:-1] + "1",  # not base32
    ):
        r = client.post("/api/v1/quorum/negotiate", json={"room": ROOM, "key": key})
        assert r.status_code == 400, key
        assert "url" not in (r.get_json() or {})


@pytest.mark.unit
def test_the_lobby_and_the_room_are_never_the_same_group():
    """Domain separation, not luck: the two names come from different labels
    over different material, so no room id can name another room's group."""
    seen = set()
    for i in range(64):
        room = f"ABCD2345EFGH67{chr(ord('A') + i % 26)}{chr(ord('A') + i // 26)}"
        key = room + ROOM_KEY[len(room) :]
        seen.add(lobby_group(room))
        seen.add(room_group(key))
    assert len(seen) == 128
    # A lobby is a function of the id alone; a room is a function of the whole
    # digest. Truncating one can never produce the other.
    assert lobby_group(ROOM) != room_group(ROOM)
    assert room_group(ROOM_KEY) != room_group(OTHER_ROOM + ROOM_KEY[16:])


@pytest.mark.unit
def test_negotiate_rejects_a_missing_or_invalid_proof(monkeypatch):
    client = _client(
        monkeypatch,
        {"BASILISK_REQUIRE_PROOF": "1", "BASILISK_PROOF_DIFFICULTY": "0"},
    )

    missing = client.post("/api/v1/quorum/negotiate", json={"room": ROOM})
    assert missing.status_code == 403
    assert "proof" in missing.get_json()["error"].lower()

    for bad in ("garbage", "nonce:notanumber:sig", f"nonce:{int(time.time())}:deadbeef"):
        r = client.post(
            "/api/v1/quorum/negotiate",
            json={"room": ROOM},
            headers={"X-Basilisk-Proof": bad},
        )
        assert r.status_code == 403, bad
        assert "url" not in (r.get_json() or {})

    # The challenge the server issues is the header it accepts.
    from basilisk.security.proof import issue_challenge

    good = client.post(
        "/api/v1/quorum/negotiate",
        json={"room": ROOM},
        headers={"X-Basilisk-Proof": str(issue_challenge()["hint"])},
    )
    assert good.status_code == 200


@pytest.mark.unit
def test_negotiate_rejects_a_room_id_that_is_not_one(monkeypatch):
    client = _client(monkeypatch)
    for bad in ("not-valid!!!", "short", "", "abcd2345efgh67yz-<script>"):
        r = client.post("/api/v1/quorum/negotiate", json={"room": bad})
        assert r.status_code == 400, bad


@pytest.mark.unit
def test_negotiate_says_so_when_signalling_is_unconfigured(monkeypatch):
    from basilisk.serve import create_app

    monkeypatch.delenv("AZURE_WEBPUBSUB_CONNECTION_STRING", raising=False)
    # Without the dev fallback there is no connection string at all, and the
    # endpoint must say that rather than mint a token against nothing.
    monkeypatch.delenv("BASILISK_ALLOW_DEV_SECRET", raising=False)
    monkeypatch.delenv("BASILISK_DEV_APPROVE", raising=False)
    monkeypatch.setenv("BASILISK_TOKEN_SECRET", "unit-test-secret")
    get_settings.cache_clear()
    r = create_app().test_client().post("/api/v1/quorum/negotiate", json={"room": ROOM})
    assert r.status_code == 503


@pytest.mark.unit
def test_the_mailbox_is_gone(monkeypatch):
    """One transport, one path — the old relay must not still answer."""
    client = _client(monkeypatch)
    assert client.post(f"/api/v1/quorum/room/{ROOM}/messages", json={"payload": "x"}).status_code == 404
    assert client.get(f"/api/v1/quorum/room/{ROOM}/messages").status_code == 404
