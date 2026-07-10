from __future__ import annotations

import hashlib
import hmac
import time
from datetime import datetime, timedelta, timezone

from basilisk.config import get_settings


def issue_token(email: str) -> str:
    settings = get_settings()
    exp = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())
    payload = f"{email}:{exp}"
    sig = hmac.new(settings.token_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_token(token: str, email: str) -> bool:
    settings = get_settings()
    try:
        parts = token.split(":")
        if len(parts) != 3:
            return False
        em, exp_s, sig = parts
        if em.lower() != email.lower():
            return False
        if int(exp_s) < time.time():
            return False
        payload = f"{em}:{exp_s}"
        expected = hmac.new(settings.token_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)
    except (ValueError, TypeError):
        return False
