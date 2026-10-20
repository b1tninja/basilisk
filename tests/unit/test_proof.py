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


@pytest.mark.unit
def test_difficulty_zero_accepts_the_hint(monkeypatch):
    monkeypatch.setenv("BASILISK_REQUIRE_PROOF", "1")
    monkeypatch.setenv("BASILISK_PROOF_DIFFICULTY", "0")
    from basilisk.config import get_settings

    get_settings.cache_clear()
    verify_proof(str(issue_challenge()["hint"]))
    get_settings.cache_clear()


@pytest.mark.unit
def test_positive_difficulty_requires_a_real_counter(monkeypatch):
    """Echoing the hint is not work, and the hash being searched must not contain the secret."""
    monkeypatch.setenv("BASILISK_REQUIRE_PROOF", "1")
    monkeypatch.setenv("BASILISK_PROOF_DIFFICULTY", "2")
    from basilisk.config import get_settings

    get_settings.cache_clear()
    hint = str(issue_challenge()["hint"])
    with pytest.raises(ProofError):
        verify_proof(hint)
    nonce, ts_s, signature = hint.split(":")
    counter = 0
    while True:
        digest = hashlib.sha256(f"{nonce}:{ts_s}:{counter}".encode()).hexdigest()
        if digest.startswith("00"):
            break
        counter += 1
        assert counter < 100_000
    verify_proof(f"{nonce}:{ts_s}:{counter}:{signature}")
    get_settings.cache_clear()
