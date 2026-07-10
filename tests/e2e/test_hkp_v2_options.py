import httpx
import pytest


@pytest.mark.e2e
def test_hkp_v2_options(basilisk_url):
    with httpx.Client(base_url=basilisk_url, timeout=30) as client:
        r = client.request("OPTIONS", "/pks/v2/certs")
        assert r.status_code == 200
        assert "application/pgp-keys" in r.headers.get("Accept", "")
