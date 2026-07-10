import uuid

import httpx
import pytest

from tests.helpers.hkp_client import lookup_get


@pytest.mark.e2e
def test_cache_headers_304(basilisk_url, gpg_runner):
    homedir = f"/tmp/gpg-{uuid.uuid4().hex}"
    email = f"test-{uuid.uuid4().hex[:8]}@basilisk.e2e"
    key = gpg_runner.generate_key(email, homedir)
    gpg_runner.send_keys("hkp://basilisk:8080", key.key_id, homedir)
    with httpx.Client(base_url=basilisk_url, timeout=30) as client:
        client.post(
            "/api/v1/dev/approve",
            json={"fingerprint": key.fingerprint, "approved_uids": [email]},
        )
        r1 = lookup_get(client, f"0x{key.fingerprint}")
        etag = r1.headers.get("ETag")
        assert etag
        r2 = client.get(
            "/pks/lookup",
            params={"op": "get", "search": f"0x{key.fingerprint}"},
            headers={"If-None-Match": etag},
        )
        assert r2.status_code == 304
