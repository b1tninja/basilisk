import httpx
import pytest

from basilisk.hkp_v2.tokens import issue_token
from basilisk.openpgp.packets import dearmor

V2_MEDIA_TYPE = "application/pgp-keys;armor=no"


@pytest.mark.e2e
def test_hkp_v2_sendtoken_bearer(basilisk_url, sample_armored):
    """§5.2.2 empty response, §5.2.4 binary submission, §7.1 binary lookup."""
    email = "test@basilisk.local"
    binary = dearmor(sample_armored.encode())
    with httpx.Client(base_url=basilisk_url, timeout=30) as client:
        r = client.post("/pks/v2/sendtoken", content=email, headers={"Content-Type": "text/plain"})
        assert r.status_code == 200
        # §5.2.2: "The keyserver SHOULD respond with an empty document."
        assert r.content == b""

        # E2E cannot read the mail queue; mint the same HMAC locally with the
        # shared BASILISK_TOKEN_SECRET (ci-test-secret / compose env).
        token = issue_token(email)
        put = client.put(
            f"/pks/v2/canonical/{email}",
            content=binary,
            headers={
                "Authentication": f"Bearer {token}",
                "Content-Type": V2_MEDIA_TYPE,
            },
        )
        assert put.status_code == 200
        body = put.json()
        assert set(body) == {"inserted", "updated", "deleted", "ignored", "invalid"}

        get = client.get(f"/pks/v2/canonical/{email}")
        assert get.status_code == 200
        # §7.1: non-armored bundles, with the armor=no media type.
        assert b"-----BEGIN PGP" not in get.content
        assert get.content == binary
        assert get.headers["content-type"].replace(" ", "").startswith(V2_MEDIA_TYPE)
        assert get.headers["access-control-allow-origin"] == "*"


@pytest.mark.e2e
def test_hkp_v2_index(basilisk_url, sample_armored):
    """§5.1.5 / §7.1.1 — JSON index over a live server."""
    email = "test@basilisk.local"
    binary = dearmor(sample_armored.encode())
    with httpx.Client(base_url=basilisk_url, timeout=30) as client:
        client.put(
            f"/pks/v2/canonical/{email}",
            content=binary,
            headers={
                "Authentication": f"Bearer {issue_token(email)}",
                "Content-Type": V2_MEDIA_TYPE,
            },
        )
        r = client.get(f"/pks/v2/index/{email}")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/json")
        certs = r.json()
        assert certs and certs[0]["version"] == 4
        assert not certs[0]["fingerprint"].startswith("0x")
        assert certs[0]["userIDs"][0]["uidString"] == email
