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
    settings = get_settings()
    if not settings.require_proof:
        return
    if not header:
        raise ProofError("X-Basilisk-Proof header required")
    parts = header.split(":")
    if len(parts) != 3:
        raise ProofError("Malformed proof header")
    nonce, ts_s, proof_hash = parts
    try:
        ts = int(ts_s)
    except ValueError as exc:
        raise ProofError("Invalid proof timestamp") from exc
    if abs(time.time() - ts) > settings.proof_max_age_sec:
        raise ProofError("Proof expired")
    payload = f"{nonce}:{ts}:{settings.token_secret}"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    difficulty = settings.proof_difficulty
    if not digest.startswith("0" * difficulty):
        raise ProofError("Proof of work insufficient")
    expected = hmac.new(settings.token_secret.encode(), f"{nonce}:{ts}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(proof_hash, expected):
        raise ProofError("Invalid proof signature")
