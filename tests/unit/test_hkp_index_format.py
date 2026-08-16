"""The `op=index` body, read as an HKP client reads it.

The one test that covered this surface before asserted ``"pub:" in r.text``,
which every shape the route has ever emitted satisfies -- including the one
where a revoked key and a live key were byte-identical apart from the
fingerprint. These tests split the line on ``:`` and look at the columns,
because that is what the consumer does.

`draft-shaw-openpgp-hkp-00` §5.2:

    pub:<keyid>:<algo>:<keylen>:<created>:<expires>:<flags>
    uid:<url-encoded uid>:<created>:<expires>:<flags>
"""
from __future__ import annotations

import urllib.parse
from datetime import datetime, timedelta, timezone

import pytest

from basilisk.hkp.handlers import get_blob_store, get_store, ingest_keytext
from basilisk.hkp.lookup import lookup_index
from basilisk.openpgp.approve import approve_cert

UID = "test@basilisk.local"


def _seed(sample_armored: str, sample_fingerprint: str, **refresh):
    """Approve the sample key, optionally forcing expiration/revocation onto it."""
    store = get_store()
    blobs = get_blob_store()
    ingest_keytext(store, blobs, sample_armored)
    approve_cert(store, sample_fingerprint, [UID])
    if refresh:
        record = store.get_by_fingerprint(sample_fingerprint)
        store.refresh_approved(
            sample_fingerprint,
            record.blob_uri,
            record.sha256,
            record.key_id,
            **refresh,
        )
    return store


def _lines(store, fingerprint: str) -> list[str]:
    response = lookup_index(f"0x{fingerprint}", store=store)
    assert response.status == 200
    return response.body.strip().split("\n")


def _pub(store, fingerprint: str) -> list[str]:
    return _lines(store, fingerprint)[1].split(":")


def _past(days: int = 2) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _future(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


@pytest.mark.unit
def test_pub_line_has_the_draft_s_columns(sample_armored, sample_fingerprint):
    store = _seed(sample_armored, sample_fingerprint)
    lines = _lines(store, sample_fingerprint)
    assert lines[0] == "info:1:1"

    pub = lines[1].split(":")
    # Seven fields, identifier first, flags last -- not the ten-field form with
    # the fingerprint on the end that no HKP client could read.
    assert len(pub) == 7
    assert pub[0] == "pub"
    assert pub[1] == sample_fingerprint.lower()
    # Algorithm, key length and creation are not on the record, so they are
    # empty rather than the literal `255:0` the old form invented.
    assert pub[2:5] == ["", "", ""]


@pytest.mark.unit
def test_uid_line_url_encodes_so_a_colon_cannot_shift_the_columns(
    sample_armored, sample_fingerprint
):
    store = _seed(sample_armored, sample_fingerprint)
    approve_cert(store, sample_fingerprint, ["Olga: Example <olga@corp.test>"])

    uid_line = _lines(store, sample_fingerprint)[2]
    fields = uid_line.split(":")
    # Five fields even though the user id itself contains a colon: the count is
    # a property of the format, not of the name someone chose.
    assert len(fields) == 5
    assert fields[0] == "uid"
    assert urllib.parse.unquote(fields[1]) == "Olga: Example <olga@corp.test>"
    assert ":" not in fields[1]


@pytest.mark.unit
def test_revoked_key_is_flagged_r_and_a_live_one_is_not(
    sample_armored, sample_fingerprint
):
    # One store per test, so the live line is read *before* the same record is
    # revoked underneath it -- these are two states of one key, which is the
    # only way a directory ever holds a revoked key (`/pks/add` refuses one
    # outright).
    store = _seed(sample_armored, sample_fingerprint)
    live = _lines(store, sample_fingerprint)[1]
    assert live.split(":")[6] == ""

    _seed(sample_armored, sample_fingerprint, revoked=True)
    revoked = _lines(store, sample_fingerprint)[1]
    assert revoked.split(":")[6] == "r"
    # The point of the flag: the two are no longer the same bytes. Before this,
    # a revoked record differed from a live one only in its fingerprint, so
    # there was nothing on the line for a client to read.
    assert revoked != live


@pytest.mark.unit
def test_past_expiration_is_flagged_e_and_a_future_one_is_not(
    sample_armored, sample_fingerprint
):
    # A key that expires later is dated but not flagged -- `e` means expired,
    # not "expires". The fixture key's own expiration is in the future, which
    # is what makes this half worth asserting rather than assuming.
    store = _seed(sample_armored, sample_fingerprint, expiration=_future())
    live = _pub(store, sample_fingerprint)
    assert live[6] == ""
    assert int(live[5]) > int(datetime.now(timezone.utc).timestamp())

    _seed(sample_armored, sample_fingerprint, expiration=_past())
    pub = _pub(store, sample_fingerprint)
    assert pub[6] == "e"
    # The expiry itself rides in its own column, as seconds since the epoch.
    assert int(pub[5]) < int(datetime.now(timezone.utc).timestamp())


@pytest.mark.unit
def test_a_key_both_revoked_and_expired_carries_both_flags(
    sample_armored, sample_fingerprint
):
    store = _seed(sample_armored, sample_fingerprint, expiration=_past(), revoked=True)
    assert _pub(store, sample_fingerprint)[6] == "re"


@pytest.mark.unit
def test_a_record_with_no_expiration_leaves_the_column_empty(
    sample_armored, sample_fingerprint
):
    # `refresh_approved(expiration=None)` clears it, which is the state of every
    # key that simply does not expire. Empty, not `0` -- a zero epoch would read
    # as "expired in 1970" to anything doing arithmetic on the column.
    store = _seed(sample_armored, sample_fingerprint, expiration=None)
    pub = _pub(store, sample_fingerprint)
    assert pub[5] == ""
    assert pub[6] == ""
