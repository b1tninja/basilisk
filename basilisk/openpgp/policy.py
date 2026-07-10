from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from basilisk.config import get_settings
from basilisk.openpgp.errors import IngestError
from basilisk.openpgp.types import ParsedCert

IngestPath = Literal["v1", "v2"]

ARMOR_PUBLIC = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
ARMOR_REVOCATION = "-----BEGIN PGP PUBLIC KEY BLOCK-----"  # revocations use same or SIGNATURE

DEFAULT_MAX_ARMORED_BYTES = 64 * 1024
DEFAULT_MAX_UIDS = 20
DEFAULT_MAX_SUBKEY_BLOCKS = 32

# Common disposable domains; extend via BASILISK_BLOCKED_EMAIL_DOMAINS
DEFAULT_BLOCKED_DOMAINS = frozenset(
    {
        "mailinator.com",
        "guerrillamail.com",
        "tempmail.com",
        "throwaway.email",
        "yopmail.com",
    }
)


@dataclass(frozen=True)
class PolicyConfig:
    max_armored_bytes: int
    max_uids: int
    max_subkey_blocks: int
    require_email_uid: bool
    reject_revoked: bool
    blocked_domains: frozenset[str]

    @classmethod
    def from_settings(cls) -> PolicyConfig:
        settings = get_settings()
        extra = {
            d.strip().lower()
            for d in settings.blocked_email_domains.split(",")
            if d.strip()
        }
        return cls(
            max_armored_bytes=settings.max_upload_bytes,
            max_uids=settings.max_uids,
            max_subkey_blocks=settings.max_subkey_blocks,
            require_email_uid=settings.require_email_uid,
            reject_revoked=settings.reject_revoked_keys,
            blocked_domains=DEFAULT_BLOCKED_DOMAINS | extra,
        )


def _email_from_uid(uid: str) -> str | None:
    m = re.search(r"<([^>]+)>", uid)
    if m and "@" in m.group(1):
        return m.group(1).lower()
    if "@" in uid:
        return uid.strip().lower()
    return None


def validate_armor_format(keytext: str) -> None:
    if ARMOR_PUBLIC not in keytext:
        if "BEGIN PGP" in keytext and ARMOR_PUBLIC not in keytext:
            raise IngestError("Only armored public key blocks are accepted", 422)
        raise IngestError("Missing PGP public key armor", 422)
    if not keytext.strip().endswith("-----END PGP PUBLIC KEY BLOCK-----"):
        # allow trailing whitespace/newlines
        stripped = keytext.rstrip()
        if not stripped.endswith("-----END PGP PUBLIC KEY BLOCK-----"):
            raise IngestError("Malformed PGP armor", 422)


def validate_single_cert(keytext: str, path: IngestPath) -> None:
    public_blocks = keytext.count(ARMOR_PUBLIC)
    if path == "v1" and public_blocks != 1:
        raise IngestError("Exactly one public key per upload is required", 422)
    if public_blocks == 0:
        raise IngestError("No public key found in upload", 422)


def validate_options_nm(keytext: str) -> None:
    if re.search(r"(?:^|[?&])options=nm(?:&|$)", keytext, re.IGNORECASE):
        raise IngestError("options=nm is not supported; remove name/email from UIDs before upload", 422)
    if "options=nm" in keytext.lower():
        raise IngestError("options=nm is not supported", 422)


def fingerprint_version(fpr: str) -> str:
    fpr = fpr.lower()
    if len(fpr) == 40 and re.fullmatch(r"[0-9a-f]{40}", fpr):
        return "v4"
    if len(fpr) == 64 and re.fullmatch(r"[0-9a-f]{64}", fpr):
        return "v6"
    if len(fpr) == 8 and re.fullmatch(r"[0-9a-f]{8}", fpr):
        return "v3"
    return "unknown"


def validate_fingerprint_version(fpr: str, path: IngestPath) -> None:
    version = fingerprint_version(fpr)
    if path == "v1":
        if version != "v4":
            if version == "v6":
                raise IngestError("OpenPGP v6 keys are only accepted on HKP v2 paths", 422)
            if version == "v3":
                raise IngestError("OpenPGP v3 keys are not supported", 422)
            raise IngestError("Only OpenPGP v4 keys are accepted on legacy HKP", 422)
    # v2: allow v4 and v6; reject v3
    if path == "v2" and version == "v3":
        raise IngestError("OpenPGP v3 keys are not supported", 422)


def validate_cert_policy(parsed: ParsedCert, path: IngestPath, *, config: PolicyConfig | None = None) -> None:
    config = config or PolicyConfig.from_settings()
    cert = parsed.raw_cert
    keytext = parsed.armored.decode("utf-8", errors="replace")

    if len(parsed.armored) > config.max_armored_bytes:
        raise IngestError("Payload too large", 413)

    validate_armor_format(keytext)
    validate_single_cert(keytext, path)
    validate_options_nm(keytext)

    if cert.has_secret_keys:
        raise IngestError("Secret keys are not accepted", 422)

    validate_fingerprint_version(parsed.fingerprint, path)

    if config.reject_revoked and cert.is_revoked:
        raise IngestError("Revoked keys cannot be uploaded", 422)

    uids = parsed.uids
    if len(uids) > config.max_uids:
        raise IngestError(f"Too many user IDs (max {config.max_uids})", 422)

    subkey_blocks = keytext.count("-----BEGIN PGP PUBLIC SUBKEY BLOCK-----")
    if subkey_blocks > config.max_subkey_blocks:
        raise IngestError(f"Too many subkeys (max {config.max_subkey_blocks})", 422)

    if config.require_email_uid:
        emails = [_email_from_uid(u) for u in uids]
        if not any(emails):
            raise IngestError("At least one user ID with an email address is required", 422)
        for email in emails:
            if email is None:
                continue
            domain = email.split("@")[-1]
            if domain in config.blocked_domains:
                raise IngestError(f"Email domain not allowed: {domain}", 422)
