from __future__ import annotations

from basilisk.config import get_settings
from basilisk.db.blob_store import BlobStore, LocalBlobStore
from basilisk.db.sqlite_store import SqliteCertStore
from basilisk.db.store import CertStore


def get_cert_store(settings=None) -> CertStore:
    settings = settings or get_settings()
    if settings.storage_connection:
        from basilisk.db.table_store import AzureTableCertStore

        return AzureTableCertStore(settings.storage_connection)
    return SqliteCertStore(settings.db_path)


def get_blob_store(settings=None) -> BlobStore:
    settings = settings or get_settings()
    if settings.storage_connection:
        from basilisk.db.azure_blob_store import AzureBlobStore

        return AzureBlobStore(settings.storage_connection, container="certs")
    return LocalBlobStore(settings.blob_path)
