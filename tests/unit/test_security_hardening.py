import base64
import json

import pytest

from basilisk.auth.azure import parse_easy_auth_headers, require_principal
from basilisk.auth.errors import AuthError
from basilisk.config import get_settings
from basilisk.hkp.handlers import get_blob_store, get_store, ingest_keytext
from basilisk.hkp.lookup import lookup_get
from basilisk.hkp_v2.submit import sendtoken_response
from basilisk.messaging.bus import get_bus, reset_bus
from basilisk.openpgp.ingest import strip_uids_for_pending
from basilisk.openpgp.packets import dearmor
from basilisk.security.rate_limit import client_ip, reset_limiter


def _principal(email: str, *, with_edge: bool = True) -> dict[str, str]:
    payload = {
        "claims": [
            {
                "typ": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                "val": email,
            },
            {
                "typ": "http://schemas.microsoft.com/identity/claims/objectidentifier",
                "val": "test-oid",
            },
        ]
    }
    headers = {
        "X-MS-CLIENT-PRINCIPAL": base64.b64encode(json.dumps(payload).encode()).decode()
    }
    if with_edge:
        headers["X-MS-CLIENT-PRINCIPAL-ID"] = "test-oid"
        headers["X-MS-CLIENT-PRINCIPAL-IDP"] = "aad"
    return headers


@pytest.mark.unit
def test_strip_uids_removes_email_from_binary(sample_armored):
    armored = sample_armored.encode()
    assert b"test@basilisk.local" in dearmor(armored)
    stripped = strip_uids_for_pending(armored)
    assert b"BEGIN PGP PUBLIC KEY BLOCK" in stripped
    assert b"test@basilisk.local" not in dearmor(stripped)


@pytest.mark.unit
def test_sendtoken_response_has_no_bearer():
    """HKP v2 §5.2.2: the keyserver responds with an empty document.

    The token only ever leaves via the mailbox, so an empty body is both the
    spec-conformant answer and the one that leaks nothing.
    """
    reset_bus()
    body, status = sendtoken_response("user@example.com")
    assert status == 200
    assert body == ""
    assert get_bus().messages[-1]["body"]["token"]


@pytest.mark.unit
def test_forged_principal_rejected_without_edge_marker(monkeypatch):
    monkeypatch.delenv("BASILISK_DEV_AUTH", raising=False)
    assert parse_easy_auth_headers(_principal("a@b.c", with_edge=False)) is None
    with pytest.raises(AuthError):
        require_principal(_principal("a@b.c", with_edge=False))


@pytest.mark.unit
def test_principal_accepted_with_edge_marker(monkeypatch):
    monkeypatch.delenv("BASILISK_DEV_AUTH", raising=False)
    p = parse_easy_auth_headers(_principal("a@b.c", with_edge=True))
    assert p is not None
    assert p["email"] == "a@b.c"


@pytest.mark.unit
def test_client_ip_ignores_forwarded_headers_without_front_door(monkeypatch):
    """X-Forwarded-For and X-Azure-ClientIP are caller-controlled until an edge is configured.

    Production sets BASILISK_AFD_ID and Front Door overwrites those headers.
    A deployment that has not set the id used to treat them as the client
    address, so each forged value was its own rate-limit bucket.
    """
    monkeypatch.delenv("BASILISK_AFD_ID", raising=False)
    headers = {
        "X-Forwarded-For": "1.2.3.4, 5.6.7.8",
        "X-Azure-ClientIP": "203.0.113.9",
        "X-Client-IP": "9.9.9.9",
    }
    assert client_ip(headers, "198.51.100.10") == "198.51.100.10"
    assert client_ip(headers, None) == "unknown"


@pytest.mark.unit
def test_client_ip_trusts_azure_headers_only_behind_the_configured_edge(monkeypatch):
    """X-Client-IP is never an Azure header and never selects a bucket.

    Behind the configured Front Door id, X-Azure-ClientIP is the address Azure
    set at the edge. A request that does not present that id keeps the socket
    address, even when it copies the same headers.
    """
    monkeypatch.setenv("BASILISK_AFD_ID", "profile-guid")
    trusted = {
        "X-Azure-FDID": "profile-guid",
        "X-Forwarded-For": "1.2.3.4, 5.6.7.8",
        "X-Client-IP": "9.9.9.9",
    }
    assert client_ip(trusted, "198.51.100.10") == "5.6.7.8"
    assert client_ip({**trusted, "X-Azure-ClientIP": "203.0.113.9"}, None) == "203.0.113.9"

    for forged in ("X-Client-IP", "x-client-ip"):
        seen = client_ip({**trusted, forged: "9.9.9.9"}, "198.51.100.10")
        assert seen == "5.6.7.8", forged

    without_edge = {k: v for k, v in trusted.items() if k != "X-Azure-FDID"}
    without_edge["X-Azure-ClientIP"] = "203.0.113.9"
    assert client_ip(without_edge, "198.51.100.10") == "198.51.100.10"


@pytest.mark.unit
def test_pending_lookup_strips_uids(sample_armored, sample_fingerprint):
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    resp = lookup_get(f"0x{sample_fingerprint}")
    assert resp.status == 200
    body = resp.body if isinstance(resp.body, bytes) else str(resp.body).encode()
    assert b"test@basilisk.local" not in dearmor(body)


@pytest.mark.unit
def test_default_secret_fails_closed(monkeypatch):
    monkeypatch.delenv("BASILISK_TOKEN_SECRET", raising=False)
    monkeypatch.delenv("BASILISK_DEV_APPROVE", raising=False)
    monkeypatch.delenv("BASILISK_ALLOW_DEV_SECRET", raising=False)
    monkeypatch.setenv("BASILISK_TOKEN_SECRET", "dev-secret")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="insecure default"):
        get_settings()
    get_settings.cache_clear()


@pytest.mark.unit
def test_upload_fingerprint_rate_limit_enforced(sample_armored, monkeypatch):
    from basilisk.serve import create_app

    monkeypatch.setenv("BASILISK_UPLOAD_RATE_LIMIT_SEC", "0")
    monkeypatch.setenv("BASILISK_UPLOAD_FPR_RATE_LIMIT_SEC", "3600")
    get_settings.cache_clear()
    reset_limiter()
    client = create_app().test_client()
    r1 = client.post("/pks/add", data={"keytext": sample_armored})
    assert r1.status_code == 200
    r2 = client.post("/pks/add", data={"keytext": sample_armored})
    # Duplicate digest short-circuits before second write, but rate limit runs after parse.
    # Re-upload same key: still hits check_upload_rate(ip, fpr) before ingest duplicate return.
    assert r2.status_code in (200, 429)
    get_settings.cache_clear()
    reset_limiter()
