from __future__ import annotations

from pathlib import Path

from flask import Flask, Response, redirect, send_from_directory
from werkzeug.exceptions import NotFound

from basilisk.config import get_settings

# Re-exported: `merge_connect_src` moved to a flask-free module so the packaging
# step can apply the same rewrite to the artifact it uploads. Importing it from
# here still works, which keeps every existing caller and test pointing at one
# implementation rather than acquiring a second.
from basilisk.security.csp import merge_connect_src  # noqa: F401

# Prefer Vite build output; fall back to legacy web/static during local transition.
_WEB_ROOT = Path(__file__).resolve().parents[2] / "web"
_DIST = _WEB_ROOT / "dist"
_LEGACY = _WEB_ROOT / "static"

# One entry per Rollup input in `web/vite.config.js`, plus the `/search` alias.
#
# This dict is hand-maintained and the build's input list is not, which is the
# drift that took `/toolkit-widgets` off the site: the entry was added to
# `vite.config.js`, `toolkit-widgets.html` was built, and nothing here routed
# it. While Front Door sent `/*` to the blob container that cost nothing — the
# document was in `$web` and answered on its own. Flask is the only thing
# serving the portal now, so an unrouted input is a 404, and
# `scripts/smoke-test.sh` walks every input, so it is a failed deploy.
#
# Deriving the mapping instead — reading `vite.config.js` at import time, or
# globbing `dist/*.html` — was considered and declined. The config is
# JavaScript, so runtime derivation means a regex parser for a program, and the
# glob makes the route table a property of whatever happens to be on disk: a
# half-written `dist/` would silently change which URLs exist, and `/search`
# (an alias onto `index.html`, not a page of its own) is not recoverable from
# either source. The guard is a test instead —
# `test_every_rollup_input_has_a_route` in `tests/unit/test_portal.py` fails
# when an input has no entry here, without needing a build to do it.
_STATIC_PAGES = {
    "published": "published.html",
    "key": "key.html",
    "stats": "stats.html",
    "search": "index.html",
    "verify": "verify.html",
    "toolkit": "toolkit.html",
    "toolkit-widgets": "toolkit-widgets.html",
    "preferences": "preferences.html",
}

# Pages that were retired into the toolkit, and where each one's errand went.
#
# A permanent redirect rather than a deletion, because every one of these paths
# is in somebody's bookmarks, in a chat log, and in the two years of links this
# project has handed out. A 404 tells a reader the feature is gone; it is not,
# it moved, and the destination is the fragment that opens exactly what the old
# page did.
#
# `/quorum` is the one that does not point at a fragment. The room it opened is
# the toolkit's session sheet, which a link cannot address without an audience
# to derive a room from — an invite is `/toolkit#j=<fingerprints>` and nobody
# arriving at `/quorum` has one. So it lands on the toolkit itself, which is
# where creating a session now starts.
#
# 301 and not 308: these are GET-only documents, no method is being preserved,
# and 301 is the status every cache and crawler already implements.
_RETIRED_PAGES = {
    "encrypt": "/toolkit#encrypt",
    "decrypt": "/toolkit#decrypt",
    "quorum": "/toolkit",
    "my-keys": "/published",
}

# HTML pins SRI hashes for that deploy. Content-hashed /assets/* and
# /importmaps/* mean a cached HTML document stays self-consistent (old pin →
# old chunks), so a day of HTML staleness is a day of a coherent older site
# rather than a mismatch. There is no edge cache in front of this any more —
# Front Door is gone and with it the purge that used to make a deploy visible
# immediately — so this max-age is now the whole freshness story for a
# browser that already has the page.
_HTML_CACHE_CONTROL = "public, max-age=86400"
# Hashed assets under /assets/ and /importmaps/ are immutable: cache hard.
_ASSET_CACHE_CONTROL = "public, max-age=604800, immutable"
# Root-level images (favicon.png, logo.png, …) are copied from `web/public`
# verbatim, so their names are stable across deploys and carry no content hash.
# A day, like the HTML: long enough to be worth caching, short enough that a
# replaced logo is not immortal.
_ROOT_ASSET_CACHE_CONTROL = "public, max-age=86400"
# The Merkle pin document is the one file whose job is to be a current
# statement about the others, and `fetchIntegrityPins` (web/src/lib/
# module-integrity.js) asks for it with `cache: "no-store"` for exactly that
# reason. Mirrors the header `scripts/deploy-static.sh` put on the blob, so a
# storage-account deploy and a Flask one say the same thing.
_INTEGRITY_CACHE_CONTROL = "public, max-age=60, must-revalidate"


def _static_root() -> Path:
    if (_DIST / "index.html").exists():
        return _DIST
    import os

    # Local/dev convenience only — production and CI must serve Vite dist/.
    allow_legacy = os.environ.get("BASILISK_DEV_APPROVE", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    if allow_legacy and (_LEGACY / "index.html").exists():
        return _LEGACY
    raise RuntimeError(
        "Vite build missing: run `npm ci && npm run build` in web/ "
        "(legacy web/static/ is deprecated)."
    )


def _send_html(filename: str) -> Response:
    """Serve a portal page, merging the deployment's signalling origin into it.

    **This is now the route the deployed site takes for these documents.** It
    used not to be, and that was the defect the paragraph here used to
    describe: Front Door sent ``/*`` to the storage account's ``$web``
    container and only ``/api/*``, ``/pks/*``, ``/claim/*``, ``/.auth/*`` and
    ``/health`` reached the Function App, so on ``keys.b1tninja.com`` the
    portal HTML never passed through this function, the merge below never ran
    on it, Front Door's header carried ``wss://…`` while the blob's meta did
    not, and the intersection the browser enforces left signalling with no
    reachable origin.

    Front Door has been removed from the deployment. ``web/dist`` now ships
    inside the function zip (``scripts/package-function.sh``) and every request
    for a portal document lands here, on every deployment there is: the Azure
    Function App, ``docker compose``, ``basilisk serve``, ``BASILISK_DEV_APPROVE``
    runs, and the test client. So the merge below is not a fallback for the
    deployments without a packaging step — it is the only thing that does it
    for the live site, and the same is true of the security headers
    ``serve.py``'s ``after_request`` adds, which blob storage could not have
    added and the Front Door rule set no longer exists to add.

    **This is not a second implementation.** It calls the same
    :func:`~basilisk.security.csp.merge_connect_src` that
    ``scripts/package-static.sh`` calls when it stages an artifact for a
    storage account, and doing it in both places stays safe because the merge
    is idempotent; a document that already carries the origin is returned
    unchanged.
    """
    ws_origin = get_settings().signaling_ws_origin()
    if ws_origin:
        # Read rather than stream: the bytes have to change, and a
        # ``send_from_directory`` response is in passthrough mode with a
        # validator computed from the file — both of which would be wrong for a
        # document this deployment rewrote.
        path = _static_root() / filename
        html = merge_connect_src(path.read_text(encoding="utf-8"), (ws_origin,))
        resp = Response(html, mimetype="text/html")
    else:
        resp = send_from_directory(_static_root(), filename)
    resp.headers["Cache-Control"] = _HTML_CACHE_CONTROL
    return resp


def _send_root_asset(page: str) -> Response | None:
    """Serve a file sitting at the top level of ``dist``, or return None.

    These are the six images Vite copies out of ``web/public`` —
    ``favicon.png``, ``favicon-32.png``, ``apple-touch-icon.png``, ``logo.png``,
    ``logo-alt.png``, ``logo-dark.png`` — referenced from the HTML by absolute
    root paths. One mechanism rather than six routes, because the set is
    decided by ``web/public`` and a six-route list is the same hand-maintained
    table that lost ``/toolkit-widgets``.

    Two things this must not become:

    * **A path-traversal hole.** ``send_from_directory`` does the resolution
      and refuses anything that escapes the directory, so no path joining is
      done here beyond an ``is_file`` probe used to decide 404-vs-serve, and
      the probe's answer is never what opens the file. The route this is
      called from is ``/<page>``, whose converter already excludes ``/``.
    * **A way to get a page without the connect-src merge.** ``.html`` is
      refused outright. Serving ``dist/toolkit.html`` through
      ``send_from_directory`` would return the built bytes rather than the ones
      :func:`_send_html` rewrites, which is the shape of the signalling failure
      documented there — a second URL for the same document, with a narrower
      policy, that nothing tests.
    """
    if page.endswith(".html"):
        return None
    try:
        root = _static_root()
    except RuntimeError:
        # No build on disk. A missing dist is a 404 for an asset, not a 500,
        # and never a 500 on a path that would otherwise have been a redirect.
        return None
    if not (root / page).is_file():
        return None
    try:
        resp = send_from_directory(root, page)
    except NotFound:
        return None
    resp.headers["Cache-Control"] = _ROOT_ASSET_CACHE_CONTROL
    return resp


def register_static_portal(app: Flask) -> None:
    @app.get("/")
    def index() -> Response:
        return _send_html("index.html")

    @app.get("/search")
    def search_alias() -> Response:
        return _send_html("index.html")

    # Registered before /<page> so "importmaps" is not treated as a page name.
    @app.get("/importmaps/<path:filename>")
    def static_importmaps(filename: str) -> Response:
        resp = send_from_directory(_static_root() / "importmaps", filename)
        # Content-hashed filenames — same caching posture as /assets/*.
        resp.headers["Cache-Control"] = _ASSET_CACHE_CONTROL
        resp.headers["Content-Type"] = "application/importmap+json"
        return resp

    @app.get("/assets/<path:filename>")
    def static_assets(filename: str) -> Response:
        resp = send_from_directory(_static_root() / "assets", filename)
        resp.headers["Cache-Control"] = _ASSET_CACHE_CONTROL
        return resp

    # Also registered before /<page>: "integrity" is two segments deep, so
    # /<page> could never have matched it and the pin document was simply not
    # on the site once Front Door stopped sending /* to the blob container.
    # `docs/THREAT-MODEL.md` tells readers to fetch this by hand, and every
    # visitor's power-on self-test compares its live module root against it.
    @app.get("/integrity/<path:filename>")
    def static_integrity(filename: str) -> Response:
        resp = send_from_directory(_static_root() / "integrity", filename)
        resp.headers["Cache-Control"] = _INTEGRITY_CACHE_CONTROL
        return resp

    @app.get("/<page>")
    def static_page(page: str) -> Response:
        filename = _STATIC_PAGES.get(page)
        if filename:
            return _send_html(filename)
        # Checked after the pages, so a name can never be both. A retired path
        # must not 404: see `_RETIRED_PAGES`.
        moved = _RETIRED_PAGES.get(page)
        if moved:
            return redirect(moved, code=301)
        # Last, so a root-level file in dist can never shadow a page or a
        # retired redirect. Ordering is decided here rather than by route
        # registration precisely so that a new file appearing in `web/public`
        # cannot change which URLs mean what.
        asset = _send_root_asset(page)
        if asset is not None:
            return asset
        return Response("Not found", status=404)
