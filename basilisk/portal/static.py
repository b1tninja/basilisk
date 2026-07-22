from __future__ import annotations

from pathlib import Path

from flask import Flask, Response, send_from_directory

# Prefer Vite build output; fall back to legacy web/static during local transition.
_WEB_ROOT = Path(__file__).resolve().parents[2] / "web"
_DIST = _WEB_ROOT / "dist"
_LEGACY = _WEB_ROOT / "static"

_STATIC_PAGES = {
    "my-keys": "my-keys.html",
    "key": "key.html",
    "stats": "stats.html",
    "search": "index.html",
    "encrypt": "encrypt.html",
    "decrypt": "decrypt.html",
    "verify": "verify.html",
    "toolkit": "toolkit.html",
    "quorum": "quorum.html",
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
        return Response("Not found", status=404)
