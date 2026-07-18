from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_DEFAULT_TOKEN_SECRET = "dev-secret"


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name, "").strip().lower()
    if not val:
        return default
    return val in ("1", "true", "yes", "on")


def _allow_insecure_default_secret() -> bool:
    """Permit the built-in token secret only for explicit local/dev use."""
    return _env_bool("BASILISK_ALLOW_DEV_SECRET") or _env_bool("BASILISK_DEV_APPROVE")


@dataclass(frozen=True)
class Settings:
    base_url: str
    token_secret: str
    db_path: str
    blob_path: str
    dev_approve: bool
    mail_provider: str
    cache_mode: str
    lru_cache_size: int
    fd_base_url: str | None
    storage_connection: str | None
    service_bus_namespace: str | None
    max_upload_bytes: int
    max_uids: int
    max_subkey_blocks: int
    max_packets: int
    require_email_uid: bool
    reject_revoked_keys: bool
    blocked_email_domains: str
    upload_rate_limit_sec: float
    upload_fingerprint_rate_limit_sec: float
    lookup_rate_limit_sec: float
    sendtoken_rate_limit_sec: float
    require_manager_approval: bool
    require_proof: bool
    proof_difficulty: int
    proof_max_age_sec: int
    auth_providers: tuple[str, ...]
    pending_ttl_days: int
    expired_grace_days: int

    @classmethod
    def from_env(cls) -> Settings:
        token_secret = os.environ.get("BASILISK_TOKEN_SECRET", _DEFAULT_TOKEN_SECRET)
        if token_secret == _DEFAULT_TOKEN_SECRET:
            if not _allow_insecure_default_secret():
                raise RuntimeError(
                    "BASILISK_TOKEN_SECRET is unset or still the insecure default. "
                    "Set a strong secret, or set BASILISK_ALLOW_DEV_SECRET=1 / "
                    "BASILISK_DEV_APPROVE=1 for local development only."
                )
            logger.warning(
                "BASILISK_TOKEN_SECRET is using the insecure default %r (dev mode)",
                _DEFAULT_TOKEN_SECRET,
            )
        return cls(
            base_url=os.environ.get("BASILISK_BASE_URL", "http://localhost:8080").rstrip("/"),
            token_secret=token_secret,
            db_path=os.environ.get("BASILISK_DB_PATH", "./data/basilisk.db"),
            blob_path=os.environ.get("BASILISK_BLOB_PATH", "./data/blobs"),
            dev_approve=_env_bool("BASILISK_DEV_APPROVE"),
            mail_provider=os.environ.get("BASILISK_MAIL_PROVIDER", "office365"),
            cache_mode=os.environ.get("BASILISK_CACHE_MODE", "inline"),
            lru_cache_size=int(os.environ.get("BASILISK_LRU_CACHE", "1000")),
            fd_base_url=os.environ.get("BASILISK_FD_BASE_URL") or None,
            storage_connection=os.environ.get("AZURE_STORAGE_CONNECTION_STRING") or None,
            service_bus_namespace=os.environ.get("SERVICE_BUS_NAMESPACE") or None,
            max_upload_bytes=int(os.environ.get("BASILISK_MAX_UPLOAD_BYTES", str(64 * 1024))),
            max_uids=int(os.environ.get("BASILISK_MAX_UIDS", "20")),
            max_subkey_blocks=int(os.environ.get("BASILISK_MAX_SUBKEYS", "32")),
            max_packets=int(os.environ.get("BASILISK_MAX_PACKETS", "1000")),
            require_email_uid=_env_bool("BASILISK_REQUIRE_EMAIL_UID", True),
            reject_revoked_keys=_env_bool("BASILISK_REJECT_REVOKED", True),
            blocked_email_domains=os.environ.get("BASILISK_BLOCKED_EMAIL_DOMAINS", ""),
            upload_rate_limit_sec=float(os.environ.get("BASILISK_UPLOAD_RATE_LIMIT_SEC", "60")),
            upload_fingerprint_rate_limit_sec=float(
                os.environ.get("BASILISK_UPLOAD_FPR_RATE_LIMIT_SEC", "60")
            ),
            lookup_rate_limit_sec=float(os.environ.get("BASILISK_LOOKUP_RATE_LIMIT_SEC", "0")),
            sendtoken_rate_limit_sec=float(os.environ.get("BASILISK_SENDTOKEN_RATE_LIMIT_SEC", "3600")),
            require_manager_approval=_env_bool("BASILISK_REQUIRE_MANAGER_APPROVAL"),
            require_proof=_env_bool("BASILISK_REQUIRE_PROOF"),
            proof_difficulty=int(os.environ.get("BASILISK_PROOF_DIFFICULTY", "0")),
            proof_max_age_sec=int(os.environ.get("BASILISK_PROOF_MAX_AGE_SEC", "300")),
            auth_providers=tuple(
                p.strip()
                for p in os.environ.get("BASILISK_AUTH_PROVIDERS", "microsoft").split(",")
                if p.strip()
            ),
            pending_ttl_days=int(os.environ.get("BASILISK_PENDING_TTL_DAYS", "30")),
            expired_grace_days=int(os.environ.get("BASILISK_EXPIRED_GRACE_DAYS", "30")),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()
