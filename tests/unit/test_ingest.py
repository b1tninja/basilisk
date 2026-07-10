import pytest

from basilisk.openpgp.ingest import IngestError, parse_search


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
