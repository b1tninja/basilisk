"""The TURN credential endpoint: who may ask, and what leaves the server.

Three properties carry this route and none of them is assumed here.

* **It is gated.** A caller with no proof of work, or a forged one, gets nothing.
  An ungated relay mint is an open relay billed to this deployment — every byte
  of every connection it carries is the operator's egress.
* **Unconfigured is the shipped state.** There is no default relay, so a
  deployment that has set no key answers 503 rather than inventing one.
* **The long-term key never leaves.** It goes into an `Authorization` header on
  a server-side request and appears in no response and no error body, including
  the error bodies produced when the provider itself refuses.

The provider call is driven through an injected opener, so every branch —
refusal, garbage, unreachable, a list with no relay in it — runs offline. What
this file cannot prove is that Cloudflare's live API answers this request the
way its documentation says; see the note in `cloudflare_turn.py`.
"""

from __future__ import annotations

import json
import time
import urllib.error

import pytest

from basilisk.config import get_settings
from basilisk.portal.cloudflare_turn import (
    API_BASE,
    TurnKey,
    TurnProviderError,
    generate_ice_servers,
)
from basilisk.security.rate_limit import reset_limiter

KEY_ID = "turn-key-id"
API_TOKEN = "super-secret-turn-token"

CLOUDFLARE_BODY = {
    "iceServers": [
        {"urls": ["stun:stun.cloudflare.com:3478", "stun:stun.cloudflare.com:53"]},
        {
            "urls": [
                "turn:turn.cloudflare.com:3478?transport=udp",
                "turns:turn.cloudflare.com:5349?transport=tcp",
            ],
            "username": "minted-username",
            "credential": "minted-credential",
        },
    ]
}


@pytest.fixture(autouse=True)
def _reset():
    reset_limiter()
    get_settings.cache_clear()
    yield
    reset_limiter()
    get_settings.cache_clear()


class _Response:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _opener(payload, record: list | None = None):
    """An opener that records the request and answers with `payload`."""

    def send(req, timeout=None):  # noqa: ANN001
        if record is not None:
            record.append(req)
        if isinstance(payload, Exception):
            raise payload
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        return _Response(body)

    return send


def _client(monkeypatch, env: dict[str, str] | None = None):
    """A client whose settings come from the environment, the way the process's
    do — `verify_proof` reads `get_settings` through its own module import."""
    from basilisk.serve import create_app

    monkeypatch.setenv("CLOUDFLARE_TURN_KEY_ID", KEY_ID)
    monkeypatch.setenv("CLOUDFLARE_TURN_API_TOKEN", API_TOKEN)
    for name, value in (env or {}).items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    return create_app().test_client()


def _mint(monkeypatch, payload=CLOUDFLARE_BODY, record: list | None = None):
    """Point the route's provider call at `payload` instead of the network."""
    import basilisk.portal.turn_credentials as route

    monkeypatch.setattr(
        route,
        "generate_ice_servers",
        lambda key, ttl: generate_ice_servers(key, ttl, opener=_opener(payload, record)),
    )


@pytest.mark.unit
def test_the_request_is_the_one_cloudflare_documents():
    record: list = []
    servers = generate_ice_servers(
        TurnKey(KEY_ID, API_TOKEN), 600, opener=_opener(CLOUDFLARE_BODY, record)
    )
    (req,) = record
    assert req.full_url == f"{API_BASE}/{KEY_ID}/credentials/generate-ice-servers"
    assert req.get_method() == "POST"
    assert req.headers["Authorization"] == f"Bearer {API_TOKEN}"
    assert json.loads(req.data.decode()) == {"ttl": 600}
    # Pass-through of the fields WebRTC reads, and only those.
    relay = [s for s in servers if any(u.startswith("turn") for u in s["urls"])]
    assert relay and relay[0]["username"] == "minted-username"
    assert set(relay[0]) <= {"urls", "username", "credential"}


@pytest.mark.unit
def test_the_provider_answer_is_believed_only_when_it_is_a_relay():
    key = TurnKey(KEY_ID, API_TOKEN)

    # A list with no turn:/turns: URL is not a relay. Handing it back would arm
    # the browser's fallback with servers that cannot carry a byte, and the
    # failure would then read as "the relay did not help".
    stun_only = {"iceServers": [{"urls": ["stun:stun.cloudflare.com:3478"]}]}
    with pytest.raises(TurnProviderError, match="no relay URL"):
        generate_ice_servers(key, 600, opener=_opener(stun_only))

    for payload, match in (
        ({}, "no iceServers"),
        ({"iceServers": []}, "no iceServers"),
        (b"<html>not json</html>", "not JSON"),
        ({"iceServers": [{"urls": ["ftp://relay.example"]}]}, "no usable iceServers"),
    ):
        with pytest.raises(TurnProviderError):
            generate_ice_servers(key, 600, opener=_opener(payload))

    # A refusal names the status and never the token.
    http_error = urllib.error.HTTPError(key.url(), 401, "Unauthorized", {}, None)
    with pytest.raises(TurnProviderError) as exc:
        generate_ice_servers(key, 600, opener=_opener(http_error))
    assert "401" in str(exc.value)
    assert API_TOKEN not in str(exc.value)

    with pytest.raises(TurnProviderError, match="unreachable"):
        generate_ice_servers(key, 600, opener=_opener(TimeoutError("timed out")))


@pytest.mark.unit
def test_a_configured_deployment_mints_a_short_lived_list(monkeypatch):
    client = _client(monkeypatch, {"BASILISK_TURN_TTL_SEC": "600"})
    _mint(monkeypatch)
    r = client.post("/api/v1/turn/credentials")
    assert r.status_code == 200
    body = r.get_json()
    assert body["provider"] == "cloudflare"
    assert body["ttl"] == 600
    assert body["expires_at"] > time.time()
    urls = [u for s in body["iceServers"] for u in s["urls"]]
    assert any(u.startswith(("turn:", "turns:")) for u in urls)
    # The long-term key is not in the answer, in any field.
    assert API_TOKEN not in json.dumps(body)
    assert KEY_ID not in json.dumps(body)


@pytest.mark.unit
def test_the_disclosure_travels_with_the_credential(monkeypatch):
    """The one claim that must not drift: the relay carries the bytes and
    cannot read them, and it can see who is talking to whom."""
    client = _client(monkeypatch)
    _mint(monkeypatch)
    disclosure = client.post("/api/v1/turn/credentials").get_json()["disclosure"]
    assert disclosure["reads_traffic"] is False
    assert disclosure["sees_addresses"] is True
    summary = disclosure["summary"].lower()
    assert "cannot read" in summary
    assert "dtls" in summary and "end-to-end" in summary
    assert "ip address" in summary


@pytest.mark.unit
def test_credentials_are_refused_without_a_valid_proof(monkeypatch):
    client = _client(
        monkeypatch,
        {"BASILISK_REQUIRE_PROOF": "1", "BASILISK_PROOF_DIFFICULTY": "0"},
    )
    calls: list = []
    _mint(monkeypatch, record=calls)

    missing = client.post("/api/v1/turn/credentials")
    assert missing.status_code == 403
    assert "proof" in missing.get_json()["error"].lower()

    for bad in ("garbage", "nonce:notanumber:sig", f"nonce:{int(time.time())}:deadbeef"):
        r = client.post("/api/v1/turn/credentials", headers={"X-Basilisk-Proof": bad})
        assert r.status_code == 403, bad
        assert "iceServers" not in (r.get_json() or {})

    # A refused caller must not have cost the deployment a mint: the gate runs
    # before the provider is contacted at all.
    assert calls == []

    from basilisk.security.proof import issue_challenge

    reset_limiter()
    good = client.post(
        "/api/v1/turn/credentials",
        headers={"X-Basilisk-Proof": str(issue_challenge()["hint"])},
    )
    assert good.status_code == 200
    assert len(calls) == 1


@pytest.mark.unit
def test_an_unconfigured_deployment_has_no_relay(monkeypatch):
    from basilisk.serve import create_app

    monkeypatch.setenv("BASILISK_TOKEN_SECRET", "unit-test-secret")
    monkeypatch.delenv("CLOUDFLARE_TURN_KEY_ID", raising=False)
    monkeypatch.delenv("CLOUDFLARE_TURN_API_TOKEN", raising=False)
    get_settings.cache_clear()
    settings = get_settings()
    # Unset is the shipped state — there is no default relay anywhere.
    assert settings.turn_key_id is None and settings.turn_api_token is None

    r = create_app().test_client().post("/api/v1/turn/credentials")
    assert r.status_code == 503

    # Half-configured is unconfigured, not a 500 from inside the provider call.
    monkeypatch.setenv("CLOUDFLARE_TURN_KEY_ID", KEY_ID)
    get_settings.cache_clear()
    reset_limiter()
    assert create_app().test_client().post("/api/v1/turn/credentials").status_code == 503


@pytest.mark.unit
def test_a_provider_failure_is_a_503_that_names_no_secret(monkeypatch):
    client = _client(monkeypatch)
    _mint(monkeypatch, payload=urllib.error.HTTPError("u", 401, "Unauthorized", {}, None))
    r = client.post("/api/v1/turn/credentials")
    assert r.status_code == 503
    assert API_TOKEN not in json.dumps(r.get_json())


@pytest.mark.unit
def test_reaching_cloudflare_needs_no_widening_of_the_page_policy(monkeypatch):
    """The browser never talks to the provider, so `connect-src` is untouched.

    This is the reason the call is server-side rather than a fetch from the
    page: `connect-src` is built once per deployment and applies to every page
    load, and widening it for a request that happens on the minority of
    connections that fail would be permanent.
    """
    monkeypatch.setenv("CLOUDFLARE_TURN_KEY_ID", KEY_ID)
    monkeypatch.setenv("CLOUDFLARE_TURN_API_TOKEN", API_TOKEN)
    get_settings.cache_clear()
    connect_src = get_settings().csp_connect_src()
    assert "rtc.live.cloudflare.com" not in connect_src
    assert "'self'" in connect_src
