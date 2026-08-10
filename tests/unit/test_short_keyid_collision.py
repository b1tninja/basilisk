"""A short key ID is not an identifier, and the lookup fails closed when two keys share one.

Short key IDs are 32 bits. Evil32 (https://evil32.com/) generated a colliding
key ID for **every key in the Web of Trust strong set**, at roughly four seconds
per collision on a GPU; in June 2016 a key sharing Linus Torvalds' short ID
0041 1886 was uploaded to the public keyservers. So a collision is not a remote
contingency to be defended against in theory -- it is something an attacker
arranges deliberately, cheaply, and against a target of their choosing.

`hex_aliases.py` already knows: `short_keyid` sits in `MULTI_ID_TYPES`, commented
"collisions expected". `lookup_get` requires exactly one match and 404s
otherwise. Nothing exercised that branch, because manufacturing keys whose
fingerprints collide is expensive.

It does not need to be. The branch returns before any blob is read, so what it
actually depends on is two *store records* sharing a short key ID -- which the
store will hold whether or not the key material behind them collides. Seeding
the store directly reaches the branch by the same route a real collision would.

The property under test is that it **fails closed**: an ambiguous needle
resolves to nothing rather than to a guess. Answering with either key would be
the impersonation, and picking the first row would make the attack depend on
insertion order.
"""

from __future__ import annotations

import pytest

from basilisk.db.blob_store import LocalBlobStore
from basilisk.db.sqlite_store import SqliteCertStore, sha256_hex
from basilisk.hkp.lookup import lookup_get, lookup_index
from basilisk.openpgp.ingest import parse_armored_keytext


def _seed(store, blobs, armored, *, fingerprint, key_id, uids):
    """Write one cert record under a chosen fingerprint and key id.

    The armor is real so the approved path can serve it; the identifiers are
    supplied rather than parsed, which is the whole point -- it puts two records
    in the index under one short key ID without the cost of colliding the
    underlying keys.
    """
    digest = sha256_hex(armored)
    uri = blobs.write_cert(fingerprint, digest, armored)
    store.upsert_pending(fingerprint, uri, digest, key_id, uids)
    store.approve(fingerprint, uids)


@pytest.fixture
def colliding_store(tmp_path, sample_armored):
    store = SqliteCertStore(str(tmp_path / "certs.db"))
    blobs = LocalBlobStore(str(tmp_path / "blobs"))
    parsed = parse_armored_keytext(sample_armored, path="v1")

    # Two key ids ending in the same 8 hex — the short key ID an attacker forges.
    # 0041 1886 is the one used against Linus Torvalds' key in June 2016.
    shared_short = "00411886"
    alice_kid = "11112222" + shared_short
    chuck_kid = "99998888" + shared_short

    # 40 hex: a v4 fingerprint. The length matters — `parse_search` classifies by
    # it, and a fingerprint of some other width is not recognised as one at all.
    # The last 16 hex are the long key id, which is where the collision lives.
    alice_fpr = "A" * 24 + alice_kid.upper()
    chuck_fpr = "C" * 24 + chuck_kid.upper()

    _seed(
        store,
        blobs,
        parsed.armored,
        fingerprint=alice_fpr,
        key_id=alice_kid,
        uids=parsed.uids,
    )
    return {
        "store": store,
        "blobs": blobs,
        "armored": parsed.armored,
        "uids": parsed.uids,
        "short": shared_short,
        "alice_fpr": alice_fpr,
        "alice_kid": alice_kid,
        "chuck_fpr": chuck_fpr,
        "chuck_kid": chuck_kid,
    }


@pytest.mark.unit
def test_a_unique_short_key_id_resolves(colliding_store):
    """Baseline: with one holder, the short id is a usable handle."""
    c = colliding_store
    resp = lookup_get(f"0x{c['short']}", store=c["store"], blobs=c["blobs"])
    assert resp.status == 200
    assert b"BEGIN PGP PUBLIC KEY BLOCK" in resp.body


@pytest.mark.unit
def test_a_colliding_short_key_id_resolves_to_nothing(colliding_store):
    """The same needle, once a second key claims it, answers 404 rather than guessing.

    This is the Evil32 attack shape: Chuck arranges a key whose short id matches
    Alice's and publishes it. Bob asks for the short id he was given.
    """
    c = colliding_store
    _seed(
        c["store"],
        c["blobs"],
        c["armored"],
        fingerprint=c["chuck_fpr"],
        key_id=c["chuck_kid"],
        uids=c["uids"],
    )

    # Both records really are indexed under the one short id.
    matches = c["store"].list_by_fingerprint_substring(c["short"])
    assert {m.fingerprint for m in matches} == {c["alice_fpr"], c["chuck_fpr"]}

    resp = lookup_get(f"0x{c['short']}", store=c["store"], blobs=c["blobs"])
    assert resp.status == 404, (
        "an ambiguous short key id must resolve to nothing; answering with "
        "either key is the impersonation the collision was arranged to achieve"
    )


@pytest.mark.unit
def test_the_full_fingerprint_still_resolves_both(colliding_store):
    """The collision costs the short id, not the keys.

    Both remain reachable by full fingerprint, which is why the advice is to
    exchange fingerprints rather than short ids -- and why 404 here is a
    usability cost rather than a denial of service.
    """
    c = colliding_store
    _seed(
        c["store"],
        c["blobs"],
        c["armored"],
        fingerprint=c["chuck_fpr"],
        key_id=c["chuck_kid"],
        uids=c["uids"],
    )
    for fpr in (c["alice_fpr"], c["chuck_fpr"]):
        resp = lookup_get(f"0x{fpr}", store=c["store"], blobs=c["blobs"])
        assert resp.status == 200, f"{fpr} should still resolve in full"


@pytest.mark.unit
def test_index_fails_closed_on_the_same_collision(colliding_store):
    """`op=index` carries its own copy of the rule, and needs its own test.

    Two guards, two call sites: `lookup_get` at lookup.py:113 and `lookup_index`
    at :164. They are near-identical but not shared, so a fix or a regression in
    one does not reach the other. `op=index` is what `gpg --search-keys` drives,
    which makes it the surface a person actually reads before choosing a key.

    Its filter is also stricter — `approval_state == "approved"`, where
    `lookup_get` admits `pending` too — so the two can disagree about how many
    matches exist for one needle.
    """
    c = colliding_store
    assert lookup_index(f"0x{c['short']}", store=c["store"]).status == 200

    _seed(
        c["store"],
        c["blobs"],
        c["armored"],
        fingerprint=c["chuck_fpr"],
        key_id=c["chuck_kid"],
        uids=c["uids"],
    )
    assert lookup_index(f"0x{c['short']}", store=c["store"]).status == 404


@pytest.mark.unit
def test_insertion_order_does_not_decide(colliding_store, tmp_path, sample_armored):
    """Seeded in the other order, the answer is the same 404.

    Guarding against a `matches[0]` regression: that would pass a single-order
    test while handing the attacker control of the outcome through upload timing.
    """
    c = colliding_store
    store = SqliteCertStore(str(tmp_path / "reversed.db"))
    blobs = LocalBlobStore(str(tmp_path / "reversed-blobs"))
    for fpr, kid in ((c["chuck_fpr"], c["chuck_kid"]), (c["alice_fpr"], c["alice_kid"])):
        _seed(store, blobs, c["armored"], fingerprint=fpr, key_id=kid, uids=c["uids"])

    resp = lookup_get(f"0x{c['short']}", store=store, blobs=blobs)
    assert resp.status == 404
