"""Offline tests for the optional read-only MCP tools."""

from __future__ import annotations

import importlib
import json

import pytest

from basilisk.hkp.handlers import get_blob_store, get_store, ingest_keytext
from basilisk.mcp.tools import key_status, lookup_key, search
from basilisk.openpgp.approve import approve_cert
from basilisk.openpgp.packets import dearmor


def _load(text: str) -> dict:
    return json.loads(text)


@pytest.mark.unit
def test_pending_lookup_strips_the_address_and_status_omits_it(sample_armored, sample_fingerprint):
    ingest_keytext(get_store(), get_blob_store(), sample_armored)
    looked = _load(lookup_key(f"0x{sample_fingerprint}"))
    assert looked["status"] == 200
    assert b"test@basilisk.local" not in dearmor(looked["armored"].encode())
    status = _load(key_status(sample_fingerprint))
    assert status["approval_state"] == "pending"
    assert status["integrity"] == "ok"
    assert status["published_uids"] == []
    assert "test@basilisk.local" not in json.dumps(status)
    assert _load(search("test@basilisk.local"))["status"] == 404


@pytest.mark.unit
def test_approved_search_and_lookup_publish_the_address(sample_armored, sample_fingerprint):
    ingest_keytext(get_store(), get_blob_store(), sample_armored)
    approve_cert(get_store(), sample_fingerprint, ["test@basilisk.local"])
    looked = _load(lookup_key("test@basilisk.local"))
    assert looked["status"] == 200
    assert "BEGIN PGP PUBLIC KEY BLOCK" in looked["armored"]
    found = _load(search(sample_fingerprint))
    assert found["status"] == 200
    assert "uid:test%40basilisk.local" in found["index"]
    status = _load(key_status(sample_fingerprint))
    assert status["approval_state"] == "approved"
    assert status["published_uids"] == ["test@basilisk.local"]
    assert status["revoked"] is False


@pytest.mark.unit
def test_unknown_fingerprint_is_not_found():
    assert _load(key_status("AB" * 20))["status"] == 404
    assert _load(lookup_key("0x" + "AB" * 20))["status"] == 404


@pytest.mark.unit
def test_importing_the_server_does_not_require_fastmcp():
    import basilisk.mcp.server as server

    importlib.reload(server)
    assert server.main.__name__ == "main"
    # FastMCP stays behind build_server(), so a missing extra is not an import error.
    assert "fastmcp" not in server.__dict__
