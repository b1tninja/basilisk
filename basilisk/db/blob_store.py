from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol

# certs/{V4 or V6 fingerprint}/{first 16 hex of sha256}.asc
_BLOB_URI = re.compile(r"certs/(?:[0-9A-F]{40}|[0-9A-F]{64})/[0-9a-f]{16}\.asc")


class BlobConflict(Exception):
    """A write-once blob name already holds different bytes."""


class BlobStore(Protocol):
    def write_cert(self, fingerprint: str, sha256: str, data: bytes) -> str: ...

    def read(self, blob_uri: str) -> bytes: ...

    def delete(self, blob_uri: str) -> None:
        """Best-effort delete of a blob (may be a no-op on immutable/WORM stores)."""
        ...


def cert_blob_uri(fingerprint: str, sha256: str) -> str:
    """The content-addressed name for one certificate blob.

    The fingerprint and the digest are part of the path, so both have to be
    hex. Anything else is rejected rather than joined onto the filesystem.
    """
    fpr = fingerprint.strip().upper()
    digest = sha256.strip().lower()
    if not re.fullmatch(r"[0-9A-F]{40}|[0-9A-F]{64}", fpr):
        raise ValueError("fingerprint is not a v4 or v6 hex fingerprint")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("sha256 is not 64 hex characters")
    return f"certs/{fpr}/{digest[:16]}.asc"


def validate_blob_uri(blob_uri: str) -> str:
    """Return ``blob_uri`` when it is a certificate blob name, else raise."""
    uri = (blob_uri or "").replace("\\", "/").lstrip("/")
    if not _BLOB_URI.fullmatch(uri):
        raise ValueError("invalid certificate blob path")
    return uri


class LocalBlobStore:
    """Filesystem blob store mirroring certs/{fpr}/{sha256_prefix}.asc layout.

    Writes are idempotent and otherwise refused. A second call with the same
    name and the same bytes succeeds; a second call with different bytes does
    not replace the first. Reads stay inside the store root.
    """

    def __init__(self, root: str) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _path(self, blob_uri: str) -> Path:
        uri = validate_blob_uri(blob_uri)
        root = self._root.resolve()
        path = (root / uri).resolve()
        if path != root and root not in path.parents:
            raise ValueError("invalid certificate blob path")
        return path

    def write_cert(self, fingerprint: str, sha256: str, data: bytes) -> str:
        rel = cert_blob_uri(fingerprint, sha256)
        path = self._path(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_file():
            if path.read_bytes() != data:
                raise BlobConflict(rel)
            return rel
        path.write_bytes(data)
        return rel

    def read(self, blob_uri: str) -> bytes:
        return self._path(blob_uri).read_bytes()

    def delete(self, blob_uri: str) -> None:
        path = self._path(blob_uri)
        if path.is_file():
            path.unlink()

    def uri_to_absolute(self, blob_uri: str) -> Path:
        return self._path(blob_uri)
