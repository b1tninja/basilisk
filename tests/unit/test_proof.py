import hashlib
import hmac
import time

import pytest

from basilisk.security.proof import ProofError, issue_challenge, verify_proof


@pytest.mark.unit
def test_proof_disabled_by_default():
    verify_proof(None)  # no-op when BASILISK_REQUIRE_PROOF=0


@pytest.mark.unit
def test_proof_required_when_enabled(monkeypatch):
    monkeypatch.setenv("BASILISK_REQUIRE_PROOF", "1")
    monkeypatch.setenv("BASILISK_PROOF_DIFFICULTY", "0")
    from basilisk.config import get_settings

    get_settings.cache_clear()
    with pytest.raises(ProofError):
        verify_proof(None)
    get_settings.cache_clear()


@pytest.mark.unit
def test_issue_challenge():
    ch = issue_challenge()
    assert "nonce" in ch
    assert "timestamp" in ch
