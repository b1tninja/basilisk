from __future__ import annotations

from pathlib import Path
from typing import Protocol


class BlobStore(Protocol):
    def write_cert(self, fingerprint: str, sha256: str, data: bytes) -> str: ...

    def read(self, blob_uri: str) -> bytes: ...

    def delete(self, blob_uri: str) -> None:
        """Best-effort delete of a blob (may be a no-op on immutable/WORM stores)."""
        ...


class LocalBlobStore:
    """Filesystem blob store mirroring certs/{fpr}/{sha256_prefix}.asc layout."""

    def __init__(self, root: str) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def write_cert(self, fingerprint: str, sha256: str, data: bytes) -> str:
        fpr = fingerprint.upper()
        prefix = sha256[:16]
        rel = Path("certs") / fpr / f"{prefix}.asc"
        path = self._root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return str(rel).replace("\\", "/")

    def read(self, blob_uri: str) -> bytes:
        path = self._root / blob_uri
        return path.read_bytes()

    def delete(self, blob_uri: str) -> None:
        path = self._root / blob_uri
        if path.is_file():
            path.unlink()

    def uri_to_absolute(self, blob_uri: str) -> Path:
        return self._root / blob_uri
