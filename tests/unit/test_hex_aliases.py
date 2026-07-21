import pytest

from basilisk.db.hex_aliases import (
    hex_aliases,
    id_types_for_needle,
    normalize_hex_needle,
)


@pytest.mark.unit
def test_hex_aliases_include_short_and_fpr32():
    fpr = "AABBCCDDEEFF00112233445566778899AABBCCDD"
    aliases = dict(hex_aliases(fpr, fpr[-16:]))
    assert aliases[fpr] == "fingerprint"
    assert aliases[fpr[-16:].lower()] == "keyid"
    assert aliases[fpr[-8:].lower()] == "short_keyid"
    assert aliases[fpr[:32].lower()] == "fpr32_prefix"
    assert aliases[fpr[-32:].lower()] == "fpr32_suffix"


@pytest.mark.unit
def test_id_types_for_needle():
    assert id_types_for_needle("aabbccdd") == ("short_keyid",)
    assert id_types_for_needle("a" * 32) == ("fpr32_prefix", "fpr32_suffix")
    assert id_types_for_needle("a" * 16) == ()
    assert id_types_for_needle("a" * 12) == ()


@pytest.mark.unit
def test_normalize_hex_needle():
    assert normalize_hex_needle("0x AA BB CC DD") == "aabbccdd"
    assert normalize_hex_needle("aabb'or") == ""
    assert normalize_hex_needle("'; DROP") == ""
