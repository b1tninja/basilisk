from __future__ import annotations

from basilisk.config import Settings, get_settings
from basilisk.db.factory import get_blob_store as _factory_blob
from basilisk.db.factory import get_cert_store
from basilisk.db.store import CertStore
from basilisk.hkp.add import ingest_keytext, parse_add_form
from basilisk.hkp.lookup import lookup_get, lookup_index, lookup_stats
from basilisk.hkp.response import HttpResponse


def get_store(settings: Settings | None = None) -> CertStore:
    return get_cert_store(settings)


def get_blob_store(settings: Settings | None = None):
    return _factory_blob(settings)


__all__ = [
    "HttpResponse",
    "get_store",
    "get_blob_store",
    "ingest_keytext",
    "parse_add_form",
    "lookup_get",
    "lookup_index",
    "lookup_stats",
]
