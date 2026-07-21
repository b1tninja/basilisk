import pytest

from basilisk.auth.azure import require_principal
from basilisk.auth.errors import AuthError
from basilisk.hkp.handlers import get_blob_store, get_store, ingest_keytext
from basilisk.openpgp.approve import approve_cert
from basilisk.portal.me import my_keys
from basilisk.portal.search import search_keys
from basilisk.portal.view import can_view_key
from tests.unit.test_claim import _principal_header


@pytest.mark.unit
def test_search_approved_by_email(sample_armored, sample_fingerprint):
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    approve_cert(store, sample_fingerprint, ["test@basilisk.local"])
    result = search_keys("test@basilisk.local", store)
    assert len(result["results"]) == 1
    hit = result["results"][0]
    assert hit["fingerprint"] == sample_fingerprint
    assert "key_expiration" in hit
    assert "revoked" in hit
    assert hit["revoked"] is False
    assert "label" in hit


@pytest.mark.unit
def test_search_pending_email_hidden(sample_armored):
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    result = search_keys("test@basilisk.local", store)
    assert result["results"] == []
    assert result["reason"] == "pending"


@pytest.mark.unit
def test_search_pending_by_fingerprint(sample_armored, sample_fingerprint):
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    result = search_keys(f"0x{sample_fingerprint}", store)
    assert result["results"] == []
    assert result["reason"] == "pending"
    assert result.get("fingerprint") == sample_fingerprint.upper()


@pytest.mark.unit
def test_search_approved_by_partial_fingerprint(sample_armored, sample_fingerprint):
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    approve_cert(store, sample_fingerprint, ["test@basilisk.local"])
    # Indexed half-fingerprint: suffix and prefix (not arbitrary mid-string)
    suffix = sample_fingerprint[-32:]
    result = search_keys(suffix, store)
    assert result["reason"] == "ok"
    assert len(result["results"]) == 1
    assert result["results"][0]["fingerprint"] == sample_fingerprint

    prefix = sample_fingerprint[:32]
    result_prefix = search_keys(prefix, store)
    assert result_prefix["reason"] == "ok"
    assert result_prefix["results"][0]["fingerprint"] == sample_fingerprint

    spaced = " ".join(suffix[i : i + 4] for i in range(0, len(suffix), 4))
    result2 = search_keys(spaced, store)
    assert result2["reason"] == "ok"
    assert result2["results"][0]["fingerprint"] == sample_fingerprint

    # Arbitrary lengths (e.g. 12 hex) are not partial-fingerprint searches
    assert search_keys(sample_fingerprint[-12:], store)["reason"] in (
        "not_found",
        "name",
    )


@pytest.mark.unit
def test_search_approved_by_short_keyid_warns(sample_armored, sample_fingerprint):
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    approve_cert(store, sample_fingerprint, ["test@basilisk.local"])
    short = sample_fingerprint[-8:]
    result = search_keys(short, store)
    assert result["reason"] == "short_keyid"
    assert result.get("warning")
    assert "collision" in result["warning"].lower()
    assert len(result["results"]) == 1
    assert result["results"][0]["fingerprint"] == sample_fingerprint

    result_0x = search_keys(f"0x{short}", store)
    assert result_0x["reason"] == "short_keyid"
    assert len(result_0x["results"]) == 1


@pytest.mark.unit
def test_my_keys_lists_pending_by_email(sample_armored, sample_fingerprint):
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    keys = my_keys({"email": "test@basilisk.local", "oid": "oid-1"}, store)
    assert len(keys) == 1
    assert keys[0]["fingerprint"] == sample_fingerprint
    assert keys[0]["can_claim"] is True


@pytest.mark.unit
def test_my_keys_includes_claimed(sample_armored, sample_fingerprint):
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    store.record_claim(sample_fingerprint, "other@example.com", "oid-2")
    keys = my_keys({"email": "other@example.com", "oid": "oid-2"}, store)
    assert any(k["fingerprint"] == sample_fingerprint for k in keys)


@pytest.mark.unit
def test_can_view_pending_for_owner(sample_armored, sample_fingerprint):
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    record = store.get_by_fingerprint(sample_fingerprint)
    assert record is not None
    assert can_view_key(record, "test@basilisk.local", None) is True
    assert can_view_key(record, "stranger@example.com", None) is False


@pytest.mark.unit
def test_require_principal_missing():
    with pytest.raises(AuthError):
        require_principal({})


@pytest.mark.integration
def test_api_me_keys(sample_armored, sample_fingerprint):
    from basilisk.serve import create_app

    client = create_app().test_client()
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    r = client.get("/api/v1/me/keys")
    assert r.status_code == 401
    r2 = client.get("/api/v1/me/keys", headers=_principal_header("test@basilisk.local"))
    assert r2.status_code == 200
    payload = r2.get_json()
    assert payload["email"] == "test@basilisk.local"
    assert len(payload["keys"]) == 1


@pytest.mark.integration
def test_static_search_page():
    from pathlib import Path

    from basilisk.serve import create_app

    client = create_app().test_client()
    for path in ("/", "/search"):
        r = client.get(path)
        assert r.status_code == 200
        body = r.get_data(as_text=True)
        assert 'id="search-form"' in body
        assert 'id="auth-widget"' in body

    web_root = Path(__file__).resolve().parents[2] / "web"
    dist_index = web_root / "dist" / "index.html"
    src_index = web_root / "index.html"
    assert dist_index.is_file() or src_index.is_file()
    if dist_index.is_file():
        html = dist_index.read_text(encoding="utf-8")
        assert "/assets/" in html
        assert "integrity=" in html
    else:
        html = src_index.read_text(encoding="utf-8")
        assert "/src/pages/index.js" in html


@pytest.mark.integration
def test_api_key_detail(sample_armored, sample_fingerprint):
    from basilisk.serve import create_app

    client = create_app().test_client()
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    r = client.get(f"/api/v1/key/{sample_fingerprint}")
    assert r.status_code == 200
    payload = r.get_json()
    assert payload["fingerprint"] == sample_fingerprint.upper()
    assert "key_expiration" in payload
    assert payload["approval_state"] == "pending"
    assert payload["revoked"] is False
    assert "claimer_email" not in payload
    assert "pending_uids" not in payload


@pytest.mark.integration
def test_api_search(sample_armored, sample_fingerprint):
    from basilisk.serve import create_app

    client = create_app().test_client()
    store = get_store()
    ingest_keytext(store, get_blob_store(), sample_armored)
    approve_cert(store, sample_fingerprint, ["test@basilisk.local"])
    r = client.get("/api/v1/search", query_string={"q": "test@basilisk.local"})
    assert r.status_code == 200
    payload = r.get_json()
    assert len(payload["results"]) == 1
    hit = payload["results"][0]
    assert hit["fingerprint"] == sample_fingerprint
    assert "key_expiration" in hit
    assert hit["revoked"] is False
    assert "label" in hit
