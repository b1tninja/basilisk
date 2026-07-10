import uuid

import httpx
import pytest

from tests.helpers.hkp_client import dev_approve


@pytest.mark.e2e
def test_hkp_index(basilisk_url, gpg_runner):
    homedir = f"/tmp/gpg-{uuid.uuid4().hex}"
    email = f"test-{uuid.uuid4().hex[:8]}@basilisk.e2e"
    key = gpg_runner.generate_key(email, homedir)
    gpg_runner.send_keys("hkp://basilisk:8080", key.key_id, homedir)
    with httpx.Client(base_url=basilisk_url, timeout=30) as client:
        dev_approve(client, key.fingerprint, [email])
        r = client.get("/pks/lookup", params={"op": "index", "search": f"0x{key.key_id}"})
        assert r.status_code == 200
        assert "pub:" in r.text
