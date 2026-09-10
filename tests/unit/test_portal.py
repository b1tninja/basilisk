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
# ── The whole built portal is served, now that only Flask serves it ──────────
#
# Front Door used to route `/*` to the storage account's `$web` container and
# only `/api/*`, `/pks/*`, `/claim/*`, `/.auth/*` and `/health` to the Function
# App, so most of `web/dist` reached readers without passing through any Python
# at all. The profile is gone, `scripts/package-function.sh` ships `web/dist`
# inside the function zip, and `register_static_portal` is the only thing
# serving the portal — which turned every file it had no route for into a 404
# on the live site.

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DIST = _REPO_ROOT / "web" / "dist"


def _dist_or_skip():
    """The built portal, or a skip. Tests that read served bytes need one."""
    if not (_DIST / "index.html").is_file():
        pytest.skip("web/dist not built: run `npm ci && npm run build` in web/")
    return _DIST


def _rollup_inputs(repo_root):
    """The HTML filenames named as Rollup inputs in `web/vite.config.js`.

    Read as text rather than executed: the config is a JavaScript module that
    imports Vite plugins, and standing up node to ask it a question is a much
    larger dependency than a brace scan over one object literal.
    """
    text = (repo_root / "web" / "vite.config.js").read_text(encoding="utf-8")
    start = text.index("input: {") + len("input: {")
    depth = 1
    i = start
    while depth:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    block = text[start : i - 1]
    inputs = re.findall(r'resolve\(__dirname,\s*"([^"]+\.html)"\)', block)
    assert inputs, "no Rollup inputs parsed out of vite.config.js"
    return inputs


@pytest.mark.unit
def test_every_rollup_input_has_a_route():
    """A page the build produces that no route serves is a 404 on the live site.

    This is the guard standing in for deriving ``_STATIC_PAGES`` from the build
    config, and it exists because the drift it watches for has already
    happened. ``toolkitWidgets`` was added to ``vite.config.js``,
    ``toolkit-widgets.html`` was built and shipped, and ``_STATIC_PAGES`` was
    never given a matching entry. Under Front Door that cost nothing — the
    document sat in ``$web`` and answered for itself. With Flask serving the
    portal it is a 404, and because ``scripts/smoke-test.sh`` walks every
    Rollup input, it is a failed deploy rather than a quiet gap.

    Deriving the dict instead was declined for the reasons written above
    ``_STATIC_PAGES``: the source of truth is JavaScript, and the ``/search``
    alias onto ``index.html`` is not recoverable from it. So the two lists stay
    two lists and this is what makes them move together. It needs no build to
    say so — it compares a config file against a Python dict, which is exactly
    the comparison nobody had made.
    """
    from basilisk.portal.static import _STATIC_PAGES

    inputs = _rollup_inputs(_REPO_ROOT)
    # index.html is not a `/<page>` name: it is `/`, plus the `/search` alias.
    pages = {Path(name).stem: name for name in inputs if name != "index.html"}

    unrouted = {
        page: filename
        for page, filename in pages.items()
        if _STATIC_PAGES.get(page) != filename
    }
    assert not unrouted, (
        f"Rollup builds {sorted(unrouted)} and _STATIC_PAGES does not serve "
        "them; add an entry in basilisk/portal/static.py"
    )

    # And the other direction: an entry naming a document no build produces is
    # a route that fails on the file read rather than 404ing honestly.
    assert set(_STATIC_PAGES) == set(pages) | {"search"}
    assert _STATIC_PAGES["search"] == "index.html"


@pytest.mark.integration
def test_toolkit_widgets_serves_its_own_document():
    """`/toolkit-widgets` answers, and answers with the widgets page.

    Asserting a 200 alone would pass if the route were wired to any document at
    all, and the neighbouring `toolkit.html` is exactly the wrong answer a
    status code cannot see. So this pins the mount point the widgets bundle
    attaches to, `toolkit-widgets-root`, which `/toolkit` does not have.
    """
    from basilisk.serve import create_app

    dist = _dist_or_skip()
    response = create_app().test_client().get("/toolkit-widgets")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("Content-Type", "")
    body = response.get_data(as_text=True)
    assert 'id="toolkit-widgets-root"' in body
    assert "<title>Toolkit widgets" in body
    assert 'id="toolkit-widgets-root"' not in (
        create_app().test_client().get("/toolkit").get_data(as_text=True)
    )

    staged = (dist / "toolkit-widgets.html").read_text(encoding="utf-8")
    # The served bytes may differ from the staged ones by the connect-src merge
    # `_send_html` applies, and by nothing else. The SRI set is what
    # `scripts/smoke-test.sh` compares after a deploy; compare it here, before.
    assert re.findall(r'integrity="[^"]*"', body) == re.findall(
        r'integrity="[^"]*"', staged
    )


@pytest.mark.integration
def test_the_merkle_pin_document_is_reachable():
    """`/integrity/module-roots.json` is served, verbatim, as JSON.

    Two segments, so the single-segment `/<page>` route could never have
    matched it: from the moment Front Door stopped sending `/*` to the blob
    container, the one file on the site whose job is to be an independent
    statement about the others was not on the site. `docs/THREAT-MODEL.md`
    tells a reader to fetch this path by hand; every visitor's power-on
    self-test compares its live module root against it and degrades to
    "unreachable" without it; and `scripts/smoke-test.sh` fails a deploy on a
    non-2xx here.

    Byte equality with the staged file, for the reason smoke-test.sh gives for
    the same comparison: `builtAt` included, a difference this tolerated would
    be a difference nobody notices.
    """
    import json

    from basilisk.serve import create_app

    dist = _dist_or_skip()
    staged = dist / "integrity" / "module-roots.json"
    assert staged.is_file(), "the build produced no Merkle pin document"

    response = create_app().test_client().get("/integrity/module-roots.json")
    assert response.status_code == 200
    assert "application/json" in response.headers.get("Content-Type", "")
    assert response.get_data() == staged.read_bytes()
    # Parsed, not merely fetched: an HTML error page served with a JSON
    # content-type would satisfy every assertion above.
    assert isinstance(json.loads(response.get_data(as_text=True)), dict)


@pytest.mark.integration
def test_the_content_hashed_pin_is_reachable_too():
    """The pin document's hashed sibling is under the same route.

    `/integrity/<path:filename>` serves the directory rather than one filename,
    so the per-deploy `module-roots-<hash>.json` that `deploy-static.sh`
    uploads beside the stable name is reachable with no second route to keep.
    """
    from basilisk.serve import create_app

    dist = _dist_or_skip()
    hashed = sorted((dist / "integrity").glob("module-roots-*.json"))
    if not hashed:
        pytest.skip("this build staged no content-hashed pin")
    client = create_app().test_client()
    for pin in hashed:
        response = client.get(f"/integrity/{pin.name}")
        assert response.status_code == 200, pin.name
        assert response.get_data() == pin.read_bytes(), pin.name


@pytest.mark.integration
def test_the_root_images_the_pages_reference_are_served():
    """Every file Vite copies out of `web/public` answers at its root path.

    The HTML references these absolutely — `/favicon.png`, `/logo.png` and the
    rest — so under Flask-only serving each one was a broken image and a 404 in
    every visitor's console. One route serves them rather than six, because a
    six-route list is the same hand-maintained table that lost
    `/toolkit-widgets`; this walks `web/public` so a seventh file added there
    is covered without anyone remembering to come back here.
    """
    from basilisk.serve import create_app

    _dist_or_skip()
    public = _REPO_ROOT / "web" / "public"
    staged = [p for p in sorted(public.iterdir()) if p.is_file()]
    assert staged, "web/public is empty; this test would be asserting nothing"

    client = create_app().test_client()
    for asset in staged:
        response = client.get(f"/{asset.name}")
        assert response.status_code == 200, asset.name
        assert response.get_data() == asset.read_bytes(), asset.name
        assert response.headers.get("Cache-Control"), asset.name


@pytest.mark.integration
def test_a_root_file_never_shadows_a_page_or_a_redirect():
    """The three answers `/<page>` can give, in a fixed order.

    A route serving whatever exists at the top of `dist` is one file away from
    changing what a URL means — drop an extensionless `toolkit` or `quorum`
    into `web/public` and the page, or the 301, stops being what the path
    resolves to. The order is decided inside the view rather than by route
    registration so that it is stated once and testable; this is the test.
    """
    from basilisk.serve import create_app

    _dist_or_skip()
    client = create_app().test_client()

    # Real files, with the two names that would collide, put where the
    # root-file route looks and taken away again. Asserting the order without
    # them would assert nothing: `dist` contains no `toolkit` or `quorum` at
    # the top level today, so every ordering passes on an empty collision.
    planted = [_DIST / "toolkit", _DIST / "quorum", _DIST / "shadow-probe"]
    # `send_from_directory` streams from an open handle, and on Windows an open
    # handle is an undeletable file. The app closes it when the request context
    # tears down; the test client hands the response back still open, so every
    # response is closed before the cleanup runs — including the ones a failing
    # assertion skipped past, or the `unlink` below raises a PermissionError
    # that replaces the assertion someone needs to read.
    opened = []

    def fetch(path):
        response = client.get(path)
        opened.append(response)
        return response

    try:
        for path in planted:
            path.write_bytes(b"planted by test_a_root_file_never_shadows")

        page = fetch("/toolkit")
        assert page.status_code == 200
        assert "text/html" in page.headers.get("Content-Type", "")
        assert "<title>Toolkit" in page.get_data(as_text=True)
        assert b"planted by" not in page.get_data()

        retired = fetch("/quorum")
        assert retired.status_code == 301, (
            "a file at the top of dist took the path a retired page redirects "
            "from; the root-file route must be tried last"
        )
        assert retired.headers["Location"] == "/toolkit"

        # And the same route does serve a root file whose name collides with
        # nothing — so the two assertions above are about precedence, not about
        # the mechanism being switched off.
        probe = fetch("/shadow-probe")
        assert probe.status_code == 200
        assert probe.get_data() == b"planted by test_a_root_file_never_shadows"
    finally:
        for response in opened:
            response.close()
        for path in planted:
            path.unlink(missing_ok=True)

    assert client.get("/definitely-not-a-page").status_code == 404
    assert client.get("/shadow-probe").status_code == 404


@pytest.mark.integration
def test_a_portal_page_cannot_be_fetched_around_the_connect_src_merge():
    """`.html` is refused at the root, so a page keeps exactly one URL.

    `_send_html` rewrites `connect-src` into the document before serving it.
    Serving `dist/toolkit.html` byte-for-byte through the root-file route would
    hand out the same page at a second URL with the merge skipped — a page
    whose meta names a narrower policy than the header on its own response,
    which is precisely the intersection failure `portal/static.py` documents.
    """
    from basilisk.serve import create_app

    _dist_or_skip()
    client = create_app().test_client()
    for path in ("/index.html", "/toolkit.html", "/toolkit-widgets.html"):
        assert client.get(path).status_code == 404, path


@pytest.mark.integration
def test_the_root_file_route_cannot_reach_outside_dist():
    """No path traversal: the route serves `dist`, and only `dist`.

    `send_from_directory` is what enforces this — it resolves against the
    directory and refuses anything that leaves it — so the point of this test
    is that no hand-rolled join ever replaces it. One level up from `dist` is
    `web/`, and two is a repository root holding `pytest.ini`,
    `pyproject.toml` and, on a developer's machine, `.env`.
    """
    from basilisk.serve import create_app

    _dist_or_skip()
    client = create_app().test_client()
    for path in (
        "/../pytest.ini",
        "/%2e%2e/pytest.ini",
        "/..%2fpytest.ini",
        "/....//pytest.ini",
        "/%2e%2e%2fpyproject.toml",
        "/../../.env",
        "/../vite.config.js",
    ):
        response = client.get(path)
        assert response.status_code != 200, f"{path} -> 200"
        assert b"[pytest]" not in response.get_data(), path


@pytest.mark.integration
def test_the_security_headers_reach_the_paths_that_had_none():
    """Flask's `after_request` is now the only thing adding these.

    Blob storage cannot add a response header and the Front Door rule set that
    used to add them went away with the profile, so the portal carries these
    headers only because its responses come out of `serve.py`. That makes every
    path added here a path where their absence would be a regression rather
    than a continuation — the two non-HTML ones included.
    """
    from basilisk.serve import create_app

    _dist_or_skip()
    client = create_app().test_client()
    for path in (
        "/toolkit-widgets",
        "/integrity/module-roots.json",
        "/favicon.png",
        "/logo.png",
    ):
        response = client.get(path)
        assert response.status_code == 200, path
        assert response.headers.get("Content-Security-Policy"), path
        assert response.headers["X-Content-Type-Options"] == "nosniff", path
        assert response.headers["X-Frame-Options"] == "DENY", path
        assert response.headers["Strict-Transport-Security"], path


@pytest.mark.integration
def test_every_built_page_smoke_test_asks_for_is_served():
    """The paths `scripts/smoke-test.sh` walks, against the app, before a deploy.

    Section 4 of that script iterates `web/dist/*.html` and fetches `/` for
    `index` and `/<name>` for the rest; section 5 iterates the Rollup inputs
    and does the same. A built page with no route fails the deploy there, on a
    live Function App, minutes after an upload. This asks the same question in
    the test suite, where the answer is cheap.
    """
    from basilisk.serve import create_app

    dist = _dist_or_skip()
    client = create_app().test_client()
    built = sorted(dist.glob("*.html"))
    assert len(built) >= 8, f"expected the full portal in dist, found {built}"
    for html in built:
        path = "/" if html.stem == "index" else f"/{html.stem}"
        response = client.get(path)
        assert response.status_code == 200, f"{path} ({html.name})"
        assert "text/html" in response.headers.get("Content-Type", ""), path
        # The SRI set is what smoke-test.sh compares served-against-staged.
        assert re.findall(
            r'integrity="[^"]*"', response.get_data(as_text=True)
        ) == re.findall(
            r'integrity="[^"]*"', html.read_text(encoding="utf-8")
        ), path
