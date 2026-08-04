import httpx
import pytest


@pytest.mark.e2e
def test_hkp_v2_submission_options(basilisk_url):
    """§5.2.6: 200, an ``Allow:`` including POST, and one or more ``Accept:``."""
    with httpx.Client(base_url=basilisk_url, timeout=30) as client:
        r = client.request("OPTIONS", "/pks/v2/certs")
        assert r.status_code == 200
        assert "POST" in r.headers.get("Allow", "")
        assert "application/pgp-keys" in r.headers.get("Accept", "")
        assert r.headers["access-control-allow-origin"] == "*"


@pytest.mark.e2e
@pytest.mark.parametrize(
    "category", ["certs/by-identity", "certs/by-vfingerprint", "certs/by-keyid", "index"]
)
def test_hkp_v2_lookup_options(basilisk_url, category):
    """§5.1.7: a supported lookup category answers 200 with ``Allow: GET``."""
    with httpx.Client(base_url=basilisk_url, timeout=30) as client:
        r = client.request("OPTIONS", f"/pks/v2/{category}")
        assert r.status_code == 200
        assert "GET" in r.headers.get("Allow", "")


@pytest.mark.e2e
def test_hkp_v2_unsupported_category_options(basilisk_url):
    """§5.1.7: otherwise "SHOULD respond with an error code such as 501"."""
    with httpx.Client(base_url=basilisk_url, timeout=30) as client:
        assert client.request("OPTIONS", "/pks/v2/prefixlog").status_code == 501
