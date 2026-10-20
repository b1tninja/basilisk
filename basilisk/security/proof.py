from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from basilisk.config import get_settings


class ProofError(Exception):
    def __init__(self, message: str = "Invalid proof") -> None:
        super().__init__(message)
        self.status = 403


def issue_challenge() -> dict[str, str | int]:
    settings = get_settings()
    nonce = secrets.token_hex(16)
    ts = int(time.time())
    payload = f"{nonce}:{ts}"
    sig = hmac.new(settings.token_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return {
        "nonce": nonce,
        "timestamp": ts,
        "difficulty": settings.proof_difficulty,
        "hint": f"{payload}:{sig}",
    }


def verify_proof(header: str | None) -> None:
    """Check ``X-Basilisk-Proof``.

    The header is ``nonce:timestamp:signature`` when difficulty is 0. That
    signature is the HMAC from ``issue_challenge``; echoing ``hint`` is the
    whole check, and it only proves the caller fetched a fresh challenge.

    When ``BASILISK_PROOF_DIFFICULTY`` is greater than 0 the header is
    ``nonce:timestamp:counter:signature``. ``counter`` is chosen by the caller
    so that ``SHA-256(nonce:timestamp:counter)`` has that many leading zero
    nibbles. The HMAC does not cover the counter, which is what makes the
    search possible, and it does not include the server secret in the hash
    being searched — a puzzle the caller cannot compute is not proof of work.
    """
    settings = get_settings()
    if not settings.require_proof:
        return
    if not header:
        raise ProofError("X-Basilisk-Proof header required")
    parts = header.split(":")
    difficulty = settings.proof_difficulty
    if difficulty <= 0:
        if len(parts) != 3:
            raise ProofError("Malformed proof header")
        nonce, ts_s, proof_hash = parts
        counter = None
    else:
        if len(parts) != 4:
            raise ProofError("Malformed proof header")
        nonce, ts_s, counter, proof_hash = parts
    try:
        ts = int(ts_s)
    except ValueError as exc:
        raise ProofError("Invalid proof timestamp") from exc
    if abs(time.time() - ts) > settings.proof_max_age_sec:
        raise ProofError("Proof expired")
    expected = hmac.new(
        settings.token_secret.encode(), f"{nonce}:{ts}".encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(proof_hash, expected):
        raise ProofError("Invalid proof signature")
    if difficulty > 0:
        digest = hashlib.sha256(f"{nonce}:{ts_s}:{counter}".encode()).hexdigest()
        if not digest.startswith("0" * difficulty):
            raise ProofError("Proof of work insufficient")
