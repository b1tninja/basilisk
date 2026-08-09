from __future__ import annotations

import re
from pathlib import Path

from flask import Flask, Response, send_from_directory

from basilisk.config import get_settings

_CONNECT_SRC_RE = re.compile(r"(connect-src\s+)([^;\"]+)")

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
    "preferences": "preferences.html",
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


def merge_connect_src(html: str, extra_sources: tuple[str, ...]) -> str:
    """Add per-deployment sources to the page's own ``connect-src``.

    The `<meta>` CSP and the response header intersect in the browser, so a
    source the header allows is still blocked unless the meta allows it too.
    Most of the policy is a build-time constant and stays in the HTML; the
    quorum signalling host is not — it comes out of a connection string that
    differs per deployment — so it is merged in on the way out rather than
    hardcoded into ten static pages. Sources already present are left alone,
    which keeps ``quorum.html``'s ``stun:`` entries intact.
    """
    if not extra_sources:
        return html

    def add(match: re.Match[str]) -> str:
        prefix, existing = match.group(1), match.group(2)
        parts = existing.split()
        for source in extra_sources:
            if source not in parts:
                parts.append(source)
        return f"{prefix}{' '.join(parts)}"

    return _CONNECT_SRC_RE.sub(add, html, count=1)


def _send_html(filename: str) -> Response:
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
        return Response("Not found", status=404)
