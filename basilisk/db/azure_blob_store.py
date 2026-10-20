from __future__ import annotations

import logging
from pathlib import Path

from azure.core.exceptions import ResourceExistsError
from azure.storage.blob import BlobServiceClient, ContentSettings

from basilisk.db.blob_store import BlobConflict, cert_blob_uri, validate_blob_uri

logger = logging.getLogger(__name__)


class AzureBlobStore:
    """Azure Blob WORM certs container; write-on-upload."""

    def __init__(self, connection_string: str, container: str = "certs") -> None:
        self._client = BlobServiceClient.from_connection_string(connection_string)
        self._container = self._client.get_container_client(container)
        try:
            self._container.create_container()
        except Exception:
            logger.warning("Could not create blob container %s (may already exist)", container, exc_info=True)

    def write_cert(self, fingerprint: str, sha256: str, data: bytes) -> str:
        blob_name = cert_blob_uri(fingerprint, sha256)
        blob = self._container.get_blob_client(blob_name)
        try:
            blob.upload_blob(
                data,
                overwrite=False,
                content_settings=ContentSettings(content_type="application/pgp-keys"),
            )
        except ResourceExistsError:
            existing = blob.download_blob().readall()
            if existing != data:
                raise BlobConflict(blob_name) from None
        return blob_name

    def read(self, blob_uri: str) -> bytes:
        blob = self._container.get_blob_client(validate_blob_uri(blob_uri))
        return blob.download_blob().readall()

    def delete(self, blob_uri: str) -> None:
        """Best-effort delete; WORM/immutability policies may reject this."""
        try:
            blob = self._container.get_blob_client(validate_blob_uri(blob_uri))
            blob.delete_blob()
        except Exception:
            logger.warning("Could not delete blob %s (may be immutable)", blob_uri, exc_info=True)

    def uri_to_absolute(self, blob_uri: str) -> Path:
        raise NotImplementedError("Azure blobs have no local path")
