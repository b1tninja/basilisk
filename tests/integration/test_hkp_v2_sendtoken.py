import pytest

from basilisk.hkp_v2.tokens import issue_token
from basilisk.messaging.bus import get_bus, reset_bus
from basilisk.serve import create_app


@pytest.mark.integration
def test_v2_sendtoken_does_not_echo_token(sample_armored):
    reset_bus()
    client = create_app().test_client()
    r = client.post("/pks/v2/sendtoken", json={"email": "test@basilisk.local"})
    assert r.status_code == 200
    data = r.get_json()
    assert "token" not in data
    assert data["status"] == "sent"

    # Token is delivered out-of-band (in-memory bus in tests).
    bus = get_bus()
    assert bus.messages
    token = bus.messages[-1]["body"]["token"]
    assert token

    put = client.put(
        "/pks/v2/canonical/test@basilisk.local",
        data=sample_armored,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert put.status_code == 200
    get = client.get("/pks/v2/canonical/test@basilisk.local")
    assert get.status_code == 200


@pytest.mark.integration
def test_v2_canonical_rejects_mismatched_identity(sample_armored):
    client = create_app().test_client()
    token = issue_token("other@example.com")
    put = client.put(
        "/pks/v2/canonical/other@example.com",
        data=sample_armored,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert put.status_code == 422
