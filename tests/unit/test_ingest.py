import pytest

from basilisk.openpgp.ingest import IngestError, normalize_fingerprint, parse_search


@pytest.mark.unit
def test_reject_short_keyid():
    with pytest.raises(IngestError) as exc:
        parse_search("0xdeadbeef")
    assert exc.value.status == 400


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
def test_normalize_fingerprint_strips_spaces():
    assert normalize_fingerprint("aa bb cc") == "AABBCC"
    assert normalize_fingerprint("0xDEAD BEEF") == "DEADBEEF"
