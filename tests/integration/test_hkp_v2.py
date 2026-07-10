import pytest
from basilisk.serve import create_app


@pytest.mark.integration
def test_v2_options():
    client = create_app().test_client()
    r = client.open("/pks/v2/certs", method="OPTIONS")
    assert r.status_code == 200
    assert "application/pgp-keys" in r.headers.get("Accept", "")
