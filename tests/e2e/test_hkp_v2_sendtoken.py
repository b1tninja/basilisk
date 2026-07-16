import httpx
import pytest

from basilisk.hkp_v2.tokens import issue_token


@pytest.mark.e2e
def test_hkp_v2_sendtoken_bearer(basilisk_url, sample_armored):
    email = "test@basilisk.local"
    with httpx.Client(base_url=basilisk_url, timeout=30) as client:
        r = client.post("/pks/v2/sendtoken", json={"email": email})
        assert r.status_code == 200
        data = r.json()
        assert "token" not in data
        assert data.get("status") == "sent"

        # E2E cannot read the mail queue; mint the same HMAC locally with the
        # shared BASILISK_TOKEN_SECRET (ci-test-secret / compose env).
        token = issue_token(email)
        put = client.put(
            f"/pks/v2/canonical/{email}",
            content=sample_armored,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert put.status_code == 200
        get = client.get(f"/pks/v2/canonical/{email}")
        assert get.status_code == 200
