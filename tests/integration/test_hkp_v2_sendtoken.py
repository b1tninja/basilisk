import pytest
from basilisk.serve import create_app


@pytest.mark.integration
def test_v2_sendtoken(sample_armored):
    client = create_app().test_client()
    r = client.post("/pks/v2/sendtoken", json={"email": "test@basilisk.local"})
    assert r.status_code == 200
    data = r.get_json()
    token = data["token"]
    put = client.put(
        "/pks/v2/canonical/test@basilisk.local",
        data=sample_armored,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert put.status_code == 200
    get = client.get("/pks/v2/canonical/test@basilisk.local")
    assert get.status_code == 200
