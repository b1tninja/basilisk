import pytest
from basilisk.serve import create_app


@pytest.mark.integration
def test_health():
    client = create_app().test_client()
    r = client.get("/health")
    assert r.status_code == 200


@pytest.mark.integration
def test_hkp_roundtrip(sample_armored, sample_fingerprint):
    client = create_app().test_client()
    r = client.post("/pks/add", data={"keytext": sample_armored})
    assert r.status_code == 200
    r2 = client.get("/pks/lookup", query_string={"op": "get", "search": f"0x{sample_fingerprint}"})
    assert r2.status_code == 200
    client.post("/api/v1/dev/approve", json={"fingerprint": sample_fingerprint, "approved_uids": ["test@basilisk.local"]})
    r3 = client.get("/pks/lookup", query_string={"op": "get", "search": "test@basilisk.local"})
    assert r3.status_code == 200


@pytest.mark.integration
def test_hkp_lookup_accepts_options_mr(sample_armored, sample_fingerprint):
    """Wire parity with browser / GnuPG clients that send options=mr."""
    client = create_app().test_client()
    client.post("/pks/add", data={"keytext": sample_armored})
    client.post(
        "/api/v1/dev/approve",
        json={"fingerprint": sample_fingerprint, "approved_uids": ["test@basilisk.local"]},
    )
    r_get = client.get(
        "/pks/lookup",
        query_string={
            "op": "get",
            "options": "mr",
            "search": f"0x{sample_fingerprint}",
        },
    )
    assert r_get.status_code == 200
    assert b"BEGIN PGP" in r_get.data
    r_index = client.get(
        "/pks/lookup",
        query_string={
            "op": "index",
            "options": "mr",
            "search": "test@basilisk.local",
        },
    )
    assert r_index.status_code == 200
    assert b"pub:" in r_index.data
