import base64
import json

import pytest

from basilisk.auth.claim import submit_claim
from basilisk.config import get_settings
from basilisk.hkp.handlers import get_blob_store, get_store, ingest_keytext
from basilisk.messaging.bus import get_bus, reset_bus


def _principal_header(email: str) -> dict[str, str]:
    payload = {
        "claims": [
            {
                "typ": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                "val": email,
            },
            {
                "typ": "http://schemas.microsoft.com/identity/claims/objectidentifier",
                "val": "test-oid",
            },
        ]
    }
    return {"X-MS-CLIENT-PRINCIPAL": base64.b64encode(json.dumps(payload).encode()).decode()}


@pytest.mark.unit
def test_submit_claim_auto_approves_locally(sample_armored, sample_fingerprint, monkeypatch):
    monkeypatch.setenv("BASILISK_REQUIRE_MANAGER_APPROVAL", "0")
    monkeypatch.delenv("ServiceBusConnection", raising=False)
    get_settings.cache_clear()
    reset_bus()

    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)

    ok, msg = submit_claim(
        sample_fingerprint,
        _principal_header("test@basilisk.local"),
        ["test@basilisk.local"],
    )
    assert ok is True
    assert msg == "Key approved"
    record = store.get_by_fingerprint(sample_fingerprint)
    assert record is not None
    assert record.approval_state == "approved"
    get_settings.cache_clear()


@pytest.mark.unit
def test_submit_claim_enqueues_manager_review(sample_armored, sample_fingerprint, monkeypatch):
    monkeypatch.setenv("BASILISK_REQUIRE_MANAGER_APPROVAL", "1")
    get_settings.cache_clear()
    reset_bus()

    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)

    ok, msg = submit_claim(
        sample_fingerprint,
        _principal_header("test@basilisk.local"),
        ["test@basilisk.local"],
    )
    assert ok is True
    assert "manager approval" in msg
    bus = get_bus()
    assert bus.messages[-1]["body"]["event"] == "claim.submitted"
    record = store.get_by_fingerprint(sample_fingerprint)
    assert record.approval_state == "pending"
    get_settings.cache_clear()
