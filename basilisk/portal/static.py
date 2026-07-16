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
}


def _static_root() -> Path:
    return _DIST if (_DIST / "index.html").exists() else _LEGACY


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
        root = _static_root()
        return send_from_directory(root / "assets", filename)

    # Legacy paths kept for older caches / local static fallback
    @app.get("/css/<path:filename>")
    def static_css(filename: str) -> Response:
        root = _static_root()
        css_root = root / "css" if (root / "css").exists() else _LEGACY / "css"
        return send_from_directory(css_root, filename)

    @app.get("/js/<path:filename>")
    def static_js(filename: str) -> Response:
        root = _static_root()
        js_root = root / "js" if (root / "js").exists() else _LEGACY / "js"
        return send_from_directory(js_root, filename)
