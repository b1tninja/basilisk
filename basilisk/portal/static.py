from __future__ import annotations

from pathlib import Path

from flask import Flask, Response, redirect, send_from_directory

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

_STATIC_PAGES = {
    "published": "published.html",
    "key": "key.html",
    "stats": "stats.html",
    "search": "index.html",
    "verify": "verify.html",
    "toolkit": "toolkit.html",
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
# old chunks). Freshness after deploy is the Front Door purge in
# deploy-static.sh — not a tiny Cache-Control max-age.
# Hashed assets under /assets/ are immutable and safe to cache aggressively.
_HTML_CACHE_CONTROL = "public, max-age=86400"
_ASSET_CACHE_CONTROL = "public, max-age=604800, immutable"


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

    **This is not the route the deployed site takes for these documents, and
    relying on it was the defect.** Front Door sends ``/*`` to the storage
    account's ``$web`` container; only ``/api/*``, ``/pks/*``, ``/claim/*``,
    ``/.auth/*`` and ``/health`` reach the Function App. So on
    ``keys.b1tninja.com`` the portal HTML never passed through here, the merge
    below never ran on it, Front Door's header carried ``wss://…`` while the
    blob's meta did not, and the intersection the browser enforces left
    signalling with no reachable origin. Shared sessions could not start at all.

    The merge that covers the Azure artifact is now done at packaging time —
    ``scripts/package-static.sh``, against the bytes that are actually uploaded.

    **This is not dead code, and it is not a second implementation.** It calls
    the same :func:`~basilisk.security.csp.merge_connect_src`, and it covers the
    deployments where Flask really does serve the HTML: ``docker compose`` and
    any container fronting the app directly, ``basilisk serve`` for local work,
    ``BASILISK_DEV_APPROVE`` runs, and the test client. Those have no packaging
    step to do it for them. Doing it in both places is safe because the merge is
    idempotent; a document that already carries the origin is returned
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
        return Response("Not found", status=404)
