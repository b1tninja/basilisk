"""HKP v2 API conformance (draft-gallagher-openpgp-hkp-10).

Each test names the normative statement it pins.
"""

from __future__ import annotations

import json

import pytest

from basilisk.hkp_v2.tokens import issue_token
from basilisk.openpgp.keyinfo import parse_cert_info
from basilisk.openpgp.packets import dearmor
from basilisk.serve import create_app

ACAO = "Access-Control-Allow-Origin"
V2_MEDIA_TYPE = "application/pgp-keys;armor=no"
IDENTITY = "test@basilisk.local"


@pytest.fixture
def client():
    return create_app().test_client()


@pytest.fixture
def published(client, sample_armored):
    """Submit and approve the sample certificate over the v2 API."""
    binary = dearmor(sample_armored.encode())
    token = issue_token(IDENTITY)
    r = client.put(
        f"/pks/v2/canonical/{IDENTITY}",
        data=binary,
        content_type=V2_MEDIA_TYPE,
        headers={"Authentication": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.get_data(as_text=True)
    info = parse_cert_info(binary)
    return {"binary": binary, "info": info, "fingerprint": info.primary.fingerprint}


# --------------------------------------------------------------------------
# §7.1 v2 output format
# --------------------------------------------------------------------------


@pytest.mark.integration
def test_lookup_returns_non_armored_bundle(client, published):
    """§7.1: a keyserver "MUST return non-armored (binary) certificate bundles
    in response to lookup requests" and "MUST set Content-Type:
    application/pgp-keys;armor=no"."""
    r = client.get(f"/pks/v2/certs/by-identity/{IDENTITY}")
    assert r.status_code == 200
    body = r.get_data()
    assert b"-----BEGIN PGP" not in body
    assert body == published["binary"]
    assert r.headers["Content-Type"].replace(" ", "").startswith(V2_MEDIA_TYPE)


@pytest.mark.integration
@pytest.mark.parametrize(
    "path",
    [
        f"/pks/v2/certs/by-identity/{IDENTITY}",
        f"/pks/v2/canonical/{IDENTITY}",
        f"/pks/v2/index/{IDENTITY}",
        "/pks/v2/certs/by-identity/nobody@example.invalid",
        "/pks/v2/index/nobody@example.invalid",
        "/pks/v2/prefixlog/2025-12-31",
        "/pks/v2/certs/by-keyid/DEADBEEFDECAFBAD",
    ],
)
def test_every_v2_response_sets_acao(client, published, path):
    """§7.1: in response to a v2 request a keyserver "MUST set the HTTP header
    Access-Control-Allow-Origin: *"."""
    assert client.get(path).headers.get(ACAO) == "*"


@pytest.mark.integration
def test_v2_submission_responses_set_acao(client, sample_armored):
    """§7.1's ACAO MUST is not scoped to lookups; it covers submissions too."""
    r = client.post(
        "/pks/v2/certs",
        data=dearmor(sample_armored.encode()),
        content_type=V2_MEDIA_TYPE,
    )
    assert r.headers.get(ACAO) == "*"
    assert client.open("/pks/v2/certs", method="OPTIONS").headers.get(ACAO) == "*"


@pytest.mark.integration
def test_index_sets_json_content_type(client, published):
    """§7.1: "MUST set Content-Type: application/json for JSON responses"."""
    r = client.get(f"/pks/v2/index/{IDENTITY}")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("application/json")


# --------------------------------------------------------------------------
# §5.1.5 / §7.1.1 v2 indexes
# --------------------------------------------------------------------------


@pytest.mark.integration
def test_index_shape(client, published):
    """§7.1.1: "The only required fields are the version and fingerprint of any
    key material, and the uidString of any User IDs.\""""
    r = client.get(f"/pks/v2/index/{IDENTITY}")
    certs = json.loads(r.get_data())
    assert isinstance(certs, list) and certs
    cert = certs[0]

    assert cert["version"] == 4
    assert cert["fingerprint"] == published["fingerprint"]
    # §7.1.1: "Fingerprints are given in hexadecimal notation, without any
    # '0x' prefix."
    assert not cert["fingerprint"].startswith("0x")
    assert cert["fingerprint"] == cert["fingerprint"].lower()

    assert cert["algorithm"]["code"] == 1
    assert cert["algorithm"]["name"] == "RSA (Encrypt or Sign)"
    assert cert["algorithm"]["bitLength"] == 2048

    uids = cert["userIDs"]
    assert [u["uidString"] for u in uids] == [IDENTITY]
    assert uids[0]["confidence"] >= 120  # §8: 120+ is "complete confidence"
    assert uids[0]["isRevoked"] is False

    for subkey in cert.get("subkeys", []):
        assert "version" in subkey and "fingerprint" in subkey


@pytest.mark.integration
def test_index_timestamps_are_rfc3339_utc(client, published):
    """§7.1.1: "Timestamps are given in UTC as per Section 5.6 of [RFC3339]"."""
    cert = json.loads(client.get(f"/pks/v2/index/{IDENTITY}").get_data())[0]
    for value in (cert["creation"], cert["expiration"]):
        assert value.endswith("Z")
        assert len(value) == 20
        assert value[4] == "-" and value[7] == "-" and value[10] == "T"


@pytest.mark.integration
def test_index_no_results_is_404(client, published):
    """§5.1.5: "If no certificates match the request, the keyserver SHOULD
    return an appropriate HTTP error code such as 404"."""
    assert client.get("/pks/v2/index/nobody@example.invalid").status_code == 404


# --------------------------------------------------------------------------
# §5.1.2 certs/by-vfingerprint
# --------------------------------------------------------------------------


@pytest.mark.integration
def test_by_vfingerprint_uses_versioned_fingerprint(client, published):
    """§5.1.2: "A versioned fingerprint consists of one octet of fingerprint
    version number and N octets of fingerprint"."""
    fpr = published["fingerprint"]
    r = client.get(f"/pks/v2/certs/by-vfingerprint/04{fpr}")
    assert r.status_code == 200
    assert r.get_data() == published["binary"]
    assert r.headers["Content-Type"].replace(" ", "").startswith(V2_MEDIA_TYPE)


@pytest.mark.integration
def test_by_vfingerprint_hex_is_case_insensitive(client, published):
    """§5.1.2: "The hexadecimal digits are not case sensitive.\""""
    fpr = published["fingerprint"]
    assert client.get(f"/pks/v2/certs/by-vfingerprint/04{fpr.upper()}").status_code == 200


@pytest.mark.integration
def test_by_vfingerprint_rejects_bare_fingerprint(client, published):
    """A bare v4 fingerprint is not a versioned fingerprint: the leading octet
    is mandatory (§5.1.2), so a 40-hex identifier must not resolve."""
    assert client.get(f"/pks/v2/certs/by-vfingerprint/{published['fingerprint']}").status_code == 404


@pytest.mark.integration
def test_by_vfingerprint_rejects_wrong_version_octet(client, published):
    """The version octet is part of the identifier; a v6 prefix must not match
    a v4 certificate."""
    assert client.get(f"/pks/v2/certs/by-vfingerprint/06{published['fingerprint']}").status_code == 404


@pytest.mark.integration
def test_by_vfingerprint_rejects_0x_prefix(client, published):
    """§5.1.2: "provided in the 'identifier' path component in hexadecimal
    encoding, without a preceding '0x'"."""
    assert client.get(f"/pks/v2/certs/by-vfingerprint/0x04{published['fingerprint']}").status_code == 404


@pytest.mark.integration
def test_old_by_fingerprint_path_is_gone(client, published):
    """The pre-spec ``certs/by-fingerprint`` path is not a v2 category."""
    r = client.get(f"/pks/v2/certs/by-fingerprint/{published['fingerprint']}")
    assert r.status_code == 501


# --------------------------------------------------------------------------
# §5.1.3 certs/by-keyid
# --------------------------------------------------------------------------


@pytest.mark.integration
def test_by_keyid_returns_v4_certificate(client, published):
    """§5.1.3: the Key ID is "16 hexadecimal digits, without a preceding 0x"."""
    keyid = published["fingerprint"][-16:]
    r = client.get(f"/pks/v2/certs/by-keyid/{keyid}")
    assert r.status_code == 200
    assert r.get_data() == published["binary"]


@pytest.mark.integration
def test_by_keyid_rejects_non_16_hex(client, published):
    fpr = published["fingerprint"]
    assert client.get(f"/pks/v2/certs/by-keyid/0x{fpr[-16:]}").status_code == 404
    assert client.get(f"/pks/v2/certs/by-keyid/{fpr}").status_code == 404


@pytest.mark.integration
def test_by_keyid_must_not_return_v6_certificates(client):
    """§5.1.3: "certificates with versions greater than 4 MUST NOT be returned
    in response to a certs/by-keyid request"."""
    pytest.importorskip("pysequoia")
    from pysequoia import Cert, Profile

    cert = Cert.generate(user_ids=["V6 <v6@basilisk.local>"], profile=Profile.RFC9580)
    binary = dearmor(str(cert).encode())
    info = parse_cert_info(binary)
    assert info.primary.version == 6

    token = issue_token("v6@basilisk.local")
    put = client.put(
        "/pks/v2/canonical/v6@basilisk.local",
        data=binary,
        content_type=V2_MEDIA_TYPE,
        headers={"Authentication": f"Bearer {token}"},
    )
    assert put.status_code == 200, put.get_data(as_text=True)

    fpr = info.primary.fingerprint
    # Reachable by versioned fingerprint...
    assert client.get(f"/pks/v2/certs/by-vfingerprint/06{fpr}").status_code == 200
    # ...but never by Key ID, under either truncation of the v6 fingerprint.
    assert client.get(f"/pks/v2/certs/by-keyid/{fpr[-16:]}").status_code == 404
    assert client.get(f"/pks/v2/certs/by-keyid/{fpr[:16]}").status_code == 404


# --------------------------------------------------------------------------
# §5.1.9 v2 identity lookups
# --------------------------------------------------------------------------


@pytest.mark.integration
def test_identity_lookup_requires_exact_match(client, published):
    """§5.1.9: v2 identity lookups "MUST only return results if the
    'identifier' path component exactly matches" the angle-bracket email or
    the full non-email User ID text."""
    for partial in ("test", "basilisk.local", "test@basilisk.loca"):
        assert client.get(f"/pks/v2/certs/by-identity/{partial}").status_code == 404
        assert client.get(f"/pks/v2/index/{partial}").status_code == 404


@pytest.mark.integration
def test_identity_lookup_is_case_insensitive(client, published):
    """§5.1.9: "Text lookups SHOULD NOT be case sensitive.\""""
    assert client.get(f"/pks/v2/certs/by-identity/{IDENTITY.upper()}").status_code == 200


@pytest.mark.integration
def test_bundle_concatenates_every_matching_certificate(client, published):
    """§9: a certificate bundle is "a sequence of one or more OpenPGP
    certificates ... concatenated directly"."""
    pytest.importorskip("pysequoia")
    from pysequoia import Cert

    second = Cert.generate(user_ids=[f"Second <{IDENTITY}>"])
    second_binary = dearmor(str(second).encode())
    r = client.put(
        f"/pks/v2/canonical/{IDENTITY}",
        data=second_binary,
        content_type=V2_MEDIA_TYPE,
        headers={"Authentication": f"Bearer {issue_token(IDENTITY)}"},
    )
    assert r.status_code == 200, r.get_data(as_text=True)

    body = client.get(f"/pks/v2/certs/by-identity/{IDENTITY}").get_data()
    assert published["binary"] in body
    assert second_binary in body
    assert len(body) == len(published["binary"]) + len(second_binary)

    certs = json.loads(client.get(f"/pks/v2/index/{IDENTITY}").get_data())
    assert {c["fingerprint"] for c in certs} == {
        published["fingerprint"],
        parse_cert_info(second_binary).primary.fingerprint,
    }


@pytest.mark.integration
def test_canonical_lookup_returns_bundle_or_404(client, published):
    """§5.1.4: "A keyserver MUST return either the canonical bundle of the
    identity being searched for, or a 404 Not Found error.\""""
    assert client.get(f"/pks/v2/canonical/{IDENTITY}").status_code == 200
    assert client.get("/pks/v2/canonical/nobody@example.invalid").status_code == 404


# --------------------------------------------------------------------------
# §5.1.7 / §5.2.6 OPTIONS feature detection
# --------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.parametrize(
    "category",
    ["certs/by-identity", "certs/by-vfingerprint", "certs/by-keyid", "index"],
)
def test_options_on_lookup_category(client, category):
    """§5.1.7: a keyserver supporting the category responds with 200 and "an
    Allow: response header that includes the value GET"."""
    r = client.open(f"/pks/v2/{category}", method="OPTIONS")
    assert r.status_code == 200
    assert "GET" in r.headers.get("Allow", "")


@pytest.mark.integration
def test_options_on_certs_submission_category(client):
    """§5.2.6: 200, an ``Allow:`` including POST, and one or more ``Accept:``."""
    r = client.open("/pks/v2/certs", method="OPTIONS")
    assert r.status_code == 200
    assert "POST" in r.headers.get("Allow", "")
    accepts = r.headers.getlist("Accept")
    assert "application/pgp-keys" in accepts
    assert "application/pgp-keys;proof=tokens" in accepts


@pytest.mark.integration
def test_options_on_canonical_category_allows_put(client):
    """§5.2.6: ``Allow:`` includes "POST" or "PUT" as appropriate; canonical is
    a PUT category (Table 3) and a GET category (Table 2)."""
    r = client.open("/pks/v2/canonical", method="OPTIONS")
    assert r.status_code == 200
    allow = r.headers.get("Allow", "")
    assert "PUT" in allow and "GET" in allow
    assert r.headers.getlist("Accept")


@pytest.mark.integration
def test_options_on_unsupported_category_is_501(client):
    """§5.1.7: otherwise a keyserver "SHOULD respond with an error code such as
    501 Not Implemented"."""
    assert client.open("/pks/v2/prefixlog", method="OPTIONS").status_code == 501
    assert client.open("/pks/v2/not-a-category", method="OPTIONS").status_code == 501


@pytest.mark.integration
@pytest.mark.parametrize(
    "category", ["certs/by-identity", "certs/by-vfingerprint", "certs/by-keyid", "index", "canonical"]
)
def test_get_without_identifier_is_403(client, category):
    """§5.1.7: "A keyserver SHOULD return an error code such as 403 Forbidden"
    to a GET without both path components."""
    assert client.get(f"/pks/v2/{category}").status_code == 403


@pytest.mark.integration
def test_head_lookup_matches_get_headers(client, published):
    """§5.1.8: a keyserver "SHOULD respond with the same header fields that it
    would have responded with if a GET request had been made"."""
    path = f"/pks/v2/certs/by-identity/{IDENTITY}"
    head = client.head(path)
    get = client.get(path)
    assert head.status_code == get.status_code
    assert head.headers["Content-Type"] == get.headers["Content-Type"]
    assert head.headers[ACAO] == get.headers[ACAO]


# --------------------------------------------------------------------------
# §5.1.6 prefixlog
# --------------------------------------------------------------------------


@pytest.mark.integration
def test_prefixlog_is_501(client):
    """§5.1.6 is a MAY; the category reports itself unimplemented (§4.2)."""
    r = client.get("/pks/v2/prefixlog/2025-12-31")
    assert r.status_code == 501
    assert r.headers.get(ACAO) == "*"


# --------------------------------------------------------------------------
# §5.2 submissions
# --------------------------------------------------------------------------


@pytest.mark.integration
def test_certs_post_accepts_binary_bundle(client, sample_armored):
    """§5.2.4: "The body of the POST or PUT request contains a certificate
    bundle as specified in Section 9, which MUST NOT be ASCII-armored.\""""
    binary = dearmor(sample_armored.encode())
    r = client.post("/pks/v2/certs", data=binary, content_type=V2_MEDIA_TYPE)
    assert r.status_code == 200
    body = r.get_json()
    assert [c["fingerprint"] for c in body["inserted"]] == [
        parse_cert_info(binary).primary.fingerprint
    ]


@pytest.mark.integration
def test_certs_post_accepts_multipart_keytext(client, sample_armored):
    """§5.2.5: advanced submission "MUST be named 'keytext'"."""
    import io

    binary = dearmor(sample_armored.encode())
    r = client.post(
        "/pks/v2/certs",
        data={"keytext": (io.BytesIO(binary), "cert.pgp", V2_MEDIA_TYPE)},
        content_type="multipart/form-data",
    )
    assert r.status_code == 200
    assert r.get_json()["inserted"]


@pytest.mark.integration
def test_multipart_without_keytext_is_422(client, sample_armored):
    import io

    r = client.post(
        "/pks/v2/certs",
        data={"other": (io.BytesIO(b"x"), "x.pgp")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 422


@pytest.mark.integration
def test_submission_response_shape(client, sample_armored):
    """§7.2 Table 12 arrays, and "Each certificate object MUST contain
    'version' and 'fingerprint' fields"."""
    binary = dearmor(sample_armored.encode())
    r = client.post("/pks/v2/certs", data=binary, content_type=V2_MEDIA_TYPE)
    body = r.get_json()
    assert set(body) == {"inserted", "updated", "deleted", "ignored", "invalid"}
    for name, entries in body.items():
        for entry in entries:
            assert isinstance(entry["version"], int)
            assert isinstance(entry["fingerprint"], str)
            if name not in ("ignored", "invalid"):
                assert "comment" not in entry

    # A resubmission carries no new information (§7.2 "ignored").
    again = client.post("/pks/v2/certs", data=binary, content_type=V2_MEDIA_TYPE).get_json()
    assert again["ignored"] and not again["inserted"]
    assert "comment" in again["ignored"][0]


@pytest.mark.integration
def test_malformed_submission_is_422(client):
    """§4.2: "422 Unprocessable content — Submission was not well formed"."""
    r = client.post("/pks/v2/certs", data=b"\x00not a cert", content_type=V2_MEDIA_TYPE)
    assert r.status_code == 422
    assert r.headers.get(ACAO) == "*"


@pytest.mark.integration
def test_empty_submission_is_422(client):
    assert client.post("/pks/v2/certs", data=b"", content_type=V2_MEDIA_TYPE).status_code == 422


@pytest.mark.integration
def test_canonical_put_accepts_authorization_header_spelling(client, sample_armored):
    """§5.2.4.1 spells the header ``Authentication:``; real clients send
    ``Authorization:``. Both are accepted."""
    binary = dearmor(sample_armored.encode())
    for header in ("Authentication", "Authorization"):
        c = create_app().test_client()
        r = c.put(
            f"/pks/v2/canonical/{IDENTITY}",
            data=binary,
            content_type=V2_MEDIA_TYPE,
            headers={header: f"Bearer {issue_token(IDENTITY)}"},
        )
        assert r.status_code == 200, header


# --------------------------------------------------------------------------
# Legacy API must keep working alongside v2 (§6)
# --------------------------------------------------------------------------


@pytest.mark.integration
def test_armor_headers_are_accepted_on_both_apis(client, sample_armored):
    """RFC 9580 §6.2 armor headers are optional but common — Sequoia always
    emits ``Comment:``. Ingest used to feed them to the base64 decoder and
    reject the upload as a malformed packet stream.
    """
    body = sample_armored.split("-----\n", 1)[1]
    with_headers = (
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
        "Version: GnuPG v2\n"
        "Comment: https://example.test\n"
        "\n" + body
    )
    legacy = client.post("/pks/add", data={"keytext": with_headers})
    assert legacy.status_code == 200

    v2 = client.post("/pks/v2/certs", data=with_headers.encode(), content_type=V2_MEDIA_TYPE)
    assert v2.status_code == 200
    body = v2.get_json()
    assert not body["invalid"]
    accepted = [c for name in ("inserted", "updated", "ignored") for c in body[name]]
    assert [c["fingerprint"] for c in accepted] == [
        parse_cert_info(dearmor(with_headers.encode())).primary.fingerprint
    ]


@pytest.mark.integration
def test_legacy_lookup_still_returns_armored(client, published):
    """§7.3: Legacy machine-readable output "MUST return ASCII-armored
    certificate bundles" — the v2 change must not leak into /pks/lookup."""
    r = client.get("/pks/lookup", query_string={"op": "get", "search": IDENTITY})
    assert r.status_code == 200
    assert b"-----BEGIN PGP PUBLIC KEY BLOCK-----" in r.get_data()
    assert r.headers["Content-Type"].startswith("application/pgp-keys")
