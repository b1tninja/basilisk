"""Regression: user-controlled strings must never break out of SQL / search binding."""

import pytest

from basilisk.db.hex_aliases import normalize_hex_needle
from basilisk.db.sqlite_store import SqliteCertStore
from basilisk.hkp.handlers import get_blob_store, get_store, ingest_keytext
from basilisk.openpgp.approve import approve_cert
from basilisk.portal.search import search_keys


INJECTION_PAYLOADS = (
    "'; DROP TABLE certs;--",
    "1' OR '1'='1",
    "aabbccdd' OR 1=1--",
    "0x' UNION SELECT * FROM certs--",
    "alice@example.com' OR '1'='1",
    "Robert'); DROP TABLE certs;--",
)


@pytest.mark.unit
def test_normalize_hex_needle_rejects_injection_text():
    for payload in INJECTION_PAYLOADS:
        assert normalize_hex_needle(payload) == ""


@pytest.mark.unit
def test_sqlite_identifier_lookup_ignores_sql_metacharacters(tmp_path):
    store = SqliteCertStore(str(tmp_path / "inj.db"))
    # Parameterized path: values with quotes must not alter SQL structure.
    for payload in ("foo' OR '1'='1", "x'; DROP TABLE certs;--"):
        assert store.get_by_identifier(payload) is None
        assert store.list_by_email(payload) == []
        assert store.list_by_fingerprint_substring(payload) == []
        assert store.list_by_claimer_oid(payload) == []
    # Tables still exist / writable after attempted injection strings.
    assert store.stats()["total"] == 0


@pytest.mark.unit
def test_search_keys_injection_payloads_do_not_error_or_leak(
    sample_armored, sample_fingerprint
):
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    approve_cert(store, sample_fingerprint, ["test@basilisk.local"])
    for payload in INJECTION_PAYLOADS:
        result = search_keys(payload, store)
        assert "results" in result
        # Must not return the approved key unless the payload legitimately matches.
        fps = {r.get("fingerprint") for r in result["results"]}
        assert sample_fingerprint not in fps or payload.lower() in {
            "test@basilisk.local",
        }
