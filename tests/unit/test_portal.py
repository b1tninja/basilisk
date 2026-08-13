import re
from pathlib import Path

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
    # The portal serves a single-page shell and the client router draws the rest.
    # This asserts only what the server is answerable for: both paths return the
    # same shell, carrying the mount point the bundle attaches to. It used to
    # assert id="search-form" and id="auth-widget" were in the served bytes --
    # true when the portal rendered server-side, false since those moved into
    # React (web/src/pages/index.tsx renders the form; auth-widget is a class
    # now, not an id). That assertion belongs in the browser suite, where a
    # rendered DOM exists to make it of.
    bodies = []
    for path in ("/", "/search"):
        r = client.get(path)
        assert r.status_code == 200
        assert "text/html" in r.headers.get("Content-Type", "")
        body = r.get_data(as_text=True)
        assert '<div id="app">' in body, "SPA mount point missing from the shell"
        bodies.append(body)
    # /search is an alias, not a page: it must serve the identical shell so a
    # deep link lands on the client router rather than a 404 or a stale build.
    assert bodies[0] == bodies[1]

    web_root = Path(__file__).resolve().parents[2] / "web"
    dist_index = web_root / "dist" / "index.html"
    src_index = web_root / "index.html"
    assert dist_index.is_file() or src_index.is_file()
    if dist_index.is_file():
        html = dist_index.read_text(encoding="utf-8")
        assert "/assets/" in html
        assert "integrity=" in html
        # Module-graph SRI must be an *external* importmap (CSP script-src 'self').
        assert 'type="importmap"' in html
        assert "<script type=\"importmap\">{" not in html
        assert "/importmaps/importmap-" in html
        maps = list((web_root / "dist" / "importmaps").glob("importmap-*.json"))
        assert maps, "expected externalized importmap JSON under dist/importmaps/"
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


@pytest.mark.unit
@pytest.mark.parametrize(
    ("path", "destination"),
    [
        ("/encrypt", "/toolkit#encrypt"),
        ("/decrypt", "/toolkit#decrypt"),
        ("/quorum", "/toolkit"),
        ("/my-keys", "/published"),
    ],
)
def test_a_retired_page_moves_rather_than_disappears(path, destination):
    """Every path the toolkit absorbed still answers, and says where it went.

    The rule the retirement was run under: nothing is deleted before its
    replacement is reachable, and no route ever becomes a 404. These four are in
    bookmarks, in chat logs, and in every link this project has handed out — a
    404 would say the feature is gone, and it is not, it moved.

    No build is needed to assert this: the redirect is decided before any
    document is read, which is also why a missing ``dist/`` cannot break it.
    """
    from basilisk.serve import create_app

    response = create_app().test_client().get(path)
    assert response.status_code == 301
    assert response.headers["Location"] == destination


@pytest.mark.unit
def test_a_page_and_a_redirect_are_never_the_same_name():
    """A path that is both would resolve by lookup order, which is not a decision."""
    from basilisk.portal.static import _RETIRED_PAGES, _STATIC_PAGES

    assert set(_STATIC_PAGES) & set(_RETIRED_PAGES) == set()


def _retired_pages_from_dev_server(repo_root):
    """`RETIRED_PAGES` as written in web/scripts/basilisk-dev-server.js."""
    text = (repo_root / "web" / "scripts" / "basilisk-dev-server.js").read_text(
        encoding="utf-8"
    )
    block = re.search(r"const RETIRED_PAGES = \{(.*?)\n\};", text, re.S)
    assert block, "RETIRED_PAGES literal not found in basilisk-dev-server.js"
    return {
        (m.group(1) or m.group(2)): m.group(3)
        for m in re.finditer(
            r'(?:"([^"]+)"|([A-Za-z_$][\w$]*))\s*:\s*"([^"]+)"', block.group(1)
        )
    }


def _retired_pages_from_terraform(repo_root):
    """`local.retired_pages` as written in terraform/modules/basilisk/frontdoor.tf.

    Rebuilt into the same shape the other two use: Front Door splits a
    destination across ``destination_path`` and ``destination_fragment`` (a `#`
    in the path would be sent as a literal ``%23``), and it matches the request
    path with no leading slash, so both are put back here.
    """
    text = (
        repo_root / "terraform" / "modules" / "basilisk" / "frontdoor.tf"
    ).read_text(encoding="utf-8")
    entries = re.findall(
        r'match_paths\s*=\s*\[([^\]]*)\]\s*'
        r'destination_path\s*=\s*"([^"]*)"\s*'
        r'destination_fragment\s*=\s*"([^"]*)"',
        text,
    )
    pages = {}
    for raw_paths, destination, fragment in entries:
        paths = re.findall(r'"([^"]*)"', raw_paths)
        # A bookmarked `/encrypt/` reaches blob storage, which 404s it, where
        # Flask's router would have folded the trailing slash away first.
        assert paths == [paths[0], f"{paths[0]}/"], (
            f"{paths[0]}: expected the bare path and its trailing-slash variant, got {paths}"
        )
        pages[paths[0]] = destination + (f"#{fragment}" if fragment else "")
    return pages


@pytest.mark.unit
def test_a_retired_redirect_says_the_same_thing_in_all_three_places():
    """One fact, stated three times, so this asserts the three still agree.

    A retired path has to redirect wherever the request lands, and requests land
    in three different places. Flask's ``_RETIRED_PAGES`` answers for ``docker
    compose``, ``basilisk serve`` and the test client. The Vite plugin answers
    for ``npm run dev``. Front Door answers for the deployed site, and it is the
    one that matters most and is checked least: ``static-route`` sends ``/*`` to
    the storage account's ``$web`` container, so Flask never sees these paths on
    keys.b1tninja.com and its table cannot cover them there.

    Collapsing all three into one shared file would mean the Terraform module
    reaching outside itself for repo content, so they stay three declarations
    and this test is what makes them move together. It reads the files as text
    rather than importing them, because two of the three are not Python.
    """
    from basilisk.portal.static import _RETIRED_PAGES

    repo_root = Path(__file__).resolve().parents[2]
    dev_server = _retired_pages_from_dev_server(repo_root)
    front_door = _retired_pages_from_terraform(repo_root)

    assert len(front_door) == len(_RETIRED_PAGES), (
        "frontdoor.tf's local.retired_pages did not parse into the expected "
        f"number of rules (got {sorted(front_door)}); if its field order or "
        "naming changed, this parser has to change with it"
    )
    assert dev_server == _RETIRED_PAGES
    assert front_door == _RETIRED_PAGES
