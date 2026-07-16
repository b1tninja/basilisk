"""Attested third-party certifications (controlled web-of-trust foundation)."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from pysequoia import ArmorKind, Cert, armor

from basilisk.db.blob_store import BlobStore
from basilisk.db.store import CertStore
from basilisk.openpgp.errors import IngestError
from basilisk.openpgp.ingest import normalize_fingerprint
from basilisk.openpgp.packets import (
    armor_public_key,
    dearmor,
    list_third_party_certifications,
    strip_third_party_from_armored,
    strip_third_party_sigs,
)

logger = logging.getLogger(__name__)

DEFAULT_MAX_THIRD_PARTY_CERTS = 64


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def approved_issuer_allowlist(store: CertStore) -> set[str]:
    """Fingerprints (and key IDs) of approved, non-revoked keys — certification allowlist."""
    allow: set[str] = set()
    list_approved = getattr(store, "list_approved", None)
    records = list_approved() if callable(list_approved) else []
    for rec in records:
        if rec.approval_state != "approved" or rec.revoked:
            continue
        fpr = normalize_fingerprint(rec.fingerprint)
        allow.add(fpr)
        allow.add(fpr[-16:])
        if rec.key_id:
            allow.add(str(rec.key_id).upper().removeprefix("0X"))
    return allow


def certifications_for_armored(armored: bytes, primary_fingerprint: str) -> list[dict[str, Any]]:
    """List third-party certifications present on an armored cert."""
    try:
        binary = dearmor(armored)
    except Exception:
        return []
    return list_third_party_certifications(binary, primary_fingerprint)


def resolve_certification_display(
    store: CertStore, items: list[dict[str, Any]]
) -> list[dict[str, str | None]]:
    """Enrich issuer key IDs to full fingerprints when the signer is on this server."""
    out: list[dict[str, str | None]] = []
    seen: set[str] = set()
    for item in items:
        fpr = item.get("signer_fingerprint")
        kid = item.get("signer_key_id")
        resolved = None
        if fpr and len(str(fpr)) >= 40:
            resolved = normalize_fingerprint(str(fpr))
        elif kid:
            rec = store.get_by_identifier(str(kid).lower())
            if rec:
                resolved = normalize_fingerprint(rec.fingerprint)
        if not resolved:
            # Keep key-ID-only entries visible but not linkable as full fpr.
            key = str(fpr or kid or "")
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "signer_fingerprint": key if len(key) >= 40 else "",
                    "signer_key_id": kid or (key[-16:] if key else None),
                    "uid": item.get("uid"),
                }
            )
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        out.append(
            {
                "signer_fingerprint": resolved,
                "signer_key_id": resolved[-16:],
                "uid": item.get("uid"),
            }
        )
    return out


def merge_attested_certifications(
    store: CertStore,
    blobs: BlobStore,
    target_fingerprint: str,
    uploaded_armored: str | bytes,
    *,
    max_third_party: int = DEFAULT_MAX_THIRD_PARTY_CERTS,
) -> dict[str, Any]:
    """Merge allowlisted third-party certifications into a stored approved cert.

    ``uploaded_armored`` must be a public key with the same primary fingerprint as
    the target (typically the target key plus one or more certification packets).
    """
    fpr = normalize_fingerprint(target_fingerprint)
    record = store.get_by_fingerprint(fpr)
    if not record:
        raise IngestError("Target key not found", 404)
    if record.approval_state != "approved":
        raise IngestError("Target key is not approved", 422)
    if record.revoked:
        raise IngestError("Target key is revoked", 422)

    raw_upload = (
        uploaded_armored.encode("utf-8")
        if isinstance(uploaded_armored, str)
        else uploaded_armored
    )
    try:
        upload_cert = Cert.from_bytes(raw_upload)
    except Exception as exc:
        raise IngestError(f"Invalid OpenPGP data: {exc}", 422) from exc

    upload_fpr = normalize_fingerprint(upload_cert.fingerprint)
    if upload_fpr != fpr:
        raise IngestError(
            "Uploaded certificate fingerprint does not match the target key", 422
        )

    stored = blobs.read(record.blob_uri)
    try:
        base_cert = Cert.from_bytes(stored)
    except Exception as exc:
        raise IngestError(f"Stored certificate unreadable: {exc}", 422) from exc

    # Collect third-party issuers present in the upload (before strip).
    upload_binary = dearmor(raw_upload)
    new_certs = list_third_party_certifications(upload_binary, fpr)
    if not new_certs:
        raise IngestError("No third-party certifications found in upload", 422)

    # Every new issuer must be an approved key on this server (prefer fingerprint).
    allow: set[str] = set()
    for item in new_certs:
        issuer_fpr = item.get("signer_fingerprint")
        issuer_kid = item.get("signer_key_id")
        signer = None
        if issuer_fpr and len(str(issuer_fpr)) >= 40:
            signer = store.get_by_fingerprint(str(issuer_fpr))
        elif issuer_kid:
            signer = store.get_by_identifier(str(issuer_kid).lower())
        if not signer or signer.approval_state != "approved" or signer.revoked:
            raise IngestError(
                "Certification issuer is not an approved key on this server", 422
            )
        allow.add(normalize_fingerprint(signer.fingerprint))
        allow.add(normalize_fingerprint(signer.fingerprint)[-16:])

    # Also keep any already-accepted attested issuers on the stored cert.
    existing = list_third_party_certifications(dearmor(stored), fpr)
    for item in existing:
        sf = item.get("signer_fingerprint") or item.get("signer_key_id")
        if not sf:
            continue
        rec = (
            store.get_by_fingerprint(str(sf))
            if len(str(sf)) >= 40
            else store.get_by_identifier(str(sf).lower())
        )
        if rec and rec.approval_state == "approved" and not rec.revoked:
            allow.add(normalize_fingerprint(rec.fingerprint))
            allow.add(normalize_fingerprint(rec.fingerprint)[-16:])

    try:
        merged = base_cert.merge(upload_cert)
        merged_bin = bytes(merged)
        merged_armored = armor(merged_bin, ArmorKind.PublicKey).encode("utf-8")
    except Exception as exc:
        raise IngestError(f"Could not merge certificates: {exc}", 422) from exc

    cleaned = strip_third_party_from_armored(merged_armored, fpr, allowlist=allow)
    if cleaned == merged_armored:
        # strip may no-op on failure; force binary path
        cleaned_bin = strip_third_party_sigs(dearmor(merged_armored), fpr, allowlist=allow)
        cleaned = armor_public_key(cleaned_bin)

    # Cap third-party certifications.
    final_binary = dearmor(cleaned)
    final_certs = list_third_party_certifications(final_binary, fpr)
    if len(final_certs) > max_third_party:
        raise IngestError(
            f"Too many third-party certifications (max {max_third_party})", 422
        )

    # Ensure still parseable.
    try:
        Cert.from_bytes(cleaned)
    except Exception as exc:
        raise IngestError(f"Merged certificate invalid: {exc}", 422) from exc

    digest = _sha256_hex(cleaned)
    blob_uri = blobs.write_cert(fpr, digest, cleaned)
    store.refresh_approved(
        fpr,
        blob_uri,
        digest,
        record.key_id,
        expiration=record.key_expiration,
        revoked=record.revoked,
    )
    display = resolve_certification_display(store, final_certs)
    return {
        "fingerprint": fpr,
        "sha256": digest,
        "certifications": display,
        "count": len(display),
    }
