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


def register_static_portal(app: Flask) -> None:
    @app.get("/")
    def index() -> Response:
        return send_from_directory(_static_root(), "index.html")

    @app.get("/search")
    def search_alias() -> Response:
        return send_from_directory(_static_root(), "index.html")

    @app.get("/<page>")
    def static_page(page: str) -> Response:
        filename = _STATIC_PAGES.get(page)
        if filename:
            return send_from_directory(_static_root(), filename)
        return Response("Not found", status=404)

    @app.get("/assets/<path:filename>")
    def static_assets(filename: str) -> Response:
        return send_from_directory(_static_root() / "assets", filename)
