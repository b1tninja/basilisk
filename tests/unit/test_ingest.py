import pytest

from basilisk.openpgp.ingest import normalize_fingerprint, parse_search


@pytest.mark.unit
def test_short_keyid_allowed():
    kind, ident = parse_search("0xdeadbeef")
    assert kind == "short_keyid"
    assert ident == "deadbeef"
    kind, ident = parse_search("AABBCCDD")
    assert kind == "short_keyid"
    assert ident == "aabbccdd"


@pytest.mark.unit
def test_fingerprint_search():
    kind, ident = parse_search("0x" + "AB" * 20)
    assert kind == "fingerprint"
    assert len(ident) == 40


@pytest.mark.unit
def test_fingerprint_search_with_spaces():
    spaced = "AABB CCDD EEFF 0011 2233 4455 6677 8899 AABB CCDD"
    kind, ident = parse_search(spaced)
    assert kind == "fingerprint"
    assert ident == "AABBCCDDEEFF00112233445566778899AABBCCDD"


@pytest.mark.unit
def test_fingerprint_search_0x_with_spaces():
    kind, ident = parse_search("0x AABB CCDD EEFF 0011 2233 4455 6677 8899 AABB CCDD")
    assert kind == "fingerprint"
    assert len(ident) == 40


@pytest.mark.unit
def test_v6_fingerprint_search():
    fpr64 = "AB" * 32
    kind, ident = parse_search(fpr64)
    assert kind == "fingerprint"
    assert len(ident) == 64


@pytest.mark.unit
def test_partial_fingerprint_half_v4_only():
    # 32 hex = half of a v4 fingerprint → partial substring search
    half = "AB" * 16
    kind, ident = parse_search(half)
    assert kind == "fingerprint_partial"
    assert ident == half.upper()

    spaced = "AABB CCDD EEFF 0011 2233 4455 6677 8899"
    kind, ident = parse_search(spaced)
    assert kind == "fingerprint_partial"
    assert len(ident) == 32

    # Non-standard lengths are not fingerprint material
    kind, ident = parse_search("FDBA0D5445AA")  # 12 hex
    assert kind == "name"
    kind, ident = parse_search("0x" + "AB" * 10)  # 20 hex
    assert kind == "name"


@pytest.mark.unit
def test_short_hex_names_still_name_search():
    # All-hex tokens outside the common-length set stay names (Ada, Cafe, …)
    kind, ident = parse_search("Ada")
    assert kind == "name"
    assert ident == "ada"
    kind, ident = parse_search("Cafe")
    assert kind == "name"


@pytest.mark.unit
def test_name_and_email_unchanged():
    kind, ident = parse_search("Alice Example")
    assert kind == "name"
    assert ident == "alice example"
    kind, ident = parse_search("alice@example.com")
    assert kind == "email"
    assert ident == "alice@example.com"


@pytest.mark.unit
def test_normalize_fingerprint_strips_spaces():
    assert normalize_fingerprint("aa bb cc") == "AABBCC"
    assert normalize_fingerprint("0xDEAD BEEF") == "DEADBEEF"
