"""GET-only CORS on public key fetch paths (not mutate endpoints)."""

from __future__ import annotations

import pytest

from basilisk.serve import create_app


ACA = "Access-Control-Allow-Origin"
ACM = "Access-Control-Allow-Methods"


@pytest.mark.integration
def test_hkp_lookup_get_404_has_cors():
    client = create_app().test_client()
    r = client.get(
        "/pks/lookup",
        query_string={"op": "get", "search": "0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"},
    )
    assert r.status_code == 404
    assert r.headers.get(ACA) == "*"
    assert "GET" in (r.headers.get(ACM) or "")


@pytest.mark.integration
def test_hkp_lookup_index_404_has_cors():
    client = create_app().test_client()
    r = client.get(
        "/pks/lookup",
        query_string={"op": "index", "search": "nobody@example.invalid"},
    )
    assert r.status_code == 404
    assert r.headers.get(ACA) == "*"


@pytest.mark.integration
def test_hkp_lookup_options_preflight():
    client = create_app().test_client()
    r = client.open("/pks/lookup", method="OPTIONS")
    assert r.status_code == 204
    assert r.headers.get(ACA) == "*"
    assert "GET" in (r.headers.get(ACM) or "")
    assert "POST" not in (r.headers.get(ACM) or "")


@pytest.mark.integration
def test_hkp_add_has_no_cors():
    client = create_app().test_client()
    r = client.post("/pks/add", data={"keytext": "not-a-key"})
    assert ACA not in r.headers


@pytest.mark.integration
def test_api_key_404_has_cors():
    client = create_app().test_client()
    r = client.get("/api/v1/key/DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
    assert r.status_code == 404
    assert r.headers.get(ACA) == "*"


@pytest.mark.integration
def test_wkd_policy_has_cors():
    client = create_app().test_client()
    r = client.get("/.well-known/openpgpkey/policy")
    assert r.status_code == 200
    assert r.headers.get(ACA) == "*"
