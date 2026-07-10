import httpx
import pytest


@pytest.mark.e2e
def test_hkp_v2_sendtoken_bearer(basilisk_url, sample_armored):
    email = "test@basilisk.local"
    with httpx.Client(base_url=basilisk_url, timeout=30) as client:
        r = client.post("/pks/v2/sendtoken", json={"email": email})
        assert r.status_code == 200
        data = r.json()
        token = data["token"]
        put = client.put(
            f"/pks/v2/canonical/{email}",
            content=sample_armored,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert put.status_code == 200
        get = client.get(f"/pks/v2/canonical/{email}")
        assert get.status_code == 200
