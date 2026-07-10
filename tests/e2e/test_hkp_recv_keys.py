import uuid

import httpx
import pytest

from tests.helpers.hkp_client import dev_approve, lookup_get


@pytest.mark.e2e
def test_hkp_recv_keys(basilisk_url, gpg_runner):
    homedir = f"/tmp/gpg-{uuid.uuid4().hex}"
    email = f"test-{uuid.uuid4().hex[:8]}@basilisk.e2e"
    key = gpg_runner.generate_key(email, homedir)
    gpg_runner.send_keys("hkp://basilisk:8080", key.key_id, homedir)
    with httpx.Client(base_url=basilisk_url, timeout=30) as client:
        dev_approve(client, key.fingerprint, [email])
        recv = gpg_runner.recv_keys("hkp://basilisk:8080", key.key_id, homedir)
        assert recv.returncode == 0, recv.stderr
        r = lookup_get(client, f"0x{key.fingerprint}")
        assert r.status_code == 200
