import uuid

import httpx
import pytest

from tests.helpers.hkp_client import lookup_get


@pytest.mark.e2e
def test_hkp_send_keys_pending(basilisk_url, gpg_runner, tmp_path):
    homedir = f"/tmp/gpg-{uuid.uuid4().hex}"
    email = f"test-{uuid.uuid4().hex[:8]}@basilisk.e2e"
    key = gpg_runner.generate_key(email, homedir)
    result = gpg_runner.send_keys(f"hkp://basilisk:8080", key.key_id, homedir)
    assert result.returncode == 0, result.stderr
    with httpx.Client(base_url=basilisk_url, timeout=30) as client:
        r = lookup_get(client, email)
        assert r.status_code == 404
