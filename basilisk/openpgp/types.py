from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from pysequoia import Cert


@dataclass
class ParsedCert:
    fingerprint: str
    key_id: str
    uids: list[str]
    armored: bytes
    raw_cert: Cert
    expiration: datetime | None = None
    is_revoked: bool = False


def uid_string(uid) -> str:
    return str(uid)
