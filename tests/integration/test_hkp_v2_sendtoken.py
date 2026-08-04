"""HKP v2 sendtoken + canonical submission (draft-gallagher-openpgp-hkp-10 §5.2.2, §5.2.3)."""

import pytest

from basilisk.hkp_v2.tokens import issue_token
from basilisk.messaging.bus import get_bus, reset_bus
from basilisk.openpgp.packets import dearmor
from basilisk.serve import create_app


@pytest.mark.integration
def test_v2_sendtoken_takes_text_plain_and_returns_empty_document(sample_armored):
    """§5.2.2: "The body of the POST request is a single email address. It
    SHOULD have a content-type of text/plain. The keyserver SHOULD respond
    with an empty document."
    """
    reset_bus()
    client = create_app().test_client()
    r = client.post(
        "/pks/v2/sendtoken",
        data="test@basilisk.local",
        content_type="text/plain",
    )
    assert r.status_code == 200
    assert r.get_data() == b""

    # The token is delivered out-of-band only (in-memory bus in tests).
    bus = get_bus()
    assert bus.messages
    token = bus.messages[-1]["body"]["token"]
    assert token
    assert token.encode() not in r.get_data()

    put = client.put(
        "/pks/v2/canonical/test@basilisk.local",
        data=dearmor(sample_armored.encode()),
        content_type="application/pgp-keys;armor=no",
        headers={"Authentication": f"Bearer {token}"},
    )
    assert put.status_code == 200
    get = client.get("/pks/v2/canonical/test@basilisk.local")
    assert get.status_code == 200


@pytest.mark.integration
def test_v2_sendtoken_still_accepts_legacy_json_callers():
    """The pre-spec JSON caller shape keeps working, with the new empty body."""
    reset_bus()
    client = create_app().test_client()
    r = client.post("/pks/v2/sendtoken", json={"email": "test@basilisk.local"})
    assert r.status_code == 200
    assert r.get_data() == b""
    assert get_bus().messages[-1]["body"]["token"]


@pytest.mark.integration
def test_v2_sendtoken_expiry_is_utc_zulu():
    """§5.2.2: "The expiry time MUST be given in UTC, in the format
    yyyy-mm-ddThh:mm:ssZ"."""
    reset_bus()
    client = create_app().test_client()
    client.post("/pks/v2/sendtoken", data="test@basilisk.local", content_type="text/plain")
    expires = get_bus().messages[-1]["body"]["expires"]
    assert len(expires) == 20
    assert expires.endswith("Z")
    assert expires[4] == "-" and expires[10] == "T"


@pytest.mark.integration
def test_v2_canonical_rejects_mismatched_identity(sample_armored):
    """§5.2.4.1: the token "MUST correspond to one of the identities present
    in the canonical bundle being submitted"."""
    client = create_app().test_client()
    token = issue_token("other@example.com")
    put = client.put(
        "/pks/v2/canonical/other@example.com",
        data=dearmor(sample_armored.encode()),
        content_type="application/pgp-keys;armor=no",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert put.status_code == 422
    body = put.get_json()
    assert [c["fingerprint"] for c in body["invalid"]]
    assert all("version" in c for c in body["invalid"])


@pytest.mark.integration
def test_v2_canonical_put_without_token_is_401(sample_armored):
    client = create_app().test_client()
    put = client.put(
        "/pks/v2/canonical/test@basilisk.local",
        data=dearmor(sample_armored.encode()),
        content_type="application/pgp-keys;armor=no",
    )
    assert put.status_code == 401
