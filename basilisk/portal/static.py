from __future__ import annotations

from pathlib import Path

from flask import Flask, Response, send_from_directory

STATIC_ROOT = Path(__file__).resolve().parents[2] / "web" / "static"

# Clean URL -> static HTML file (served locally; deploy uploads blobs without .html suffix)
_STATIC_PAGES = {
    "search": "search.html",
    "my-keys": "my-keys.html",
    "key": "key.html",
}


def register_static_portal(app: Flask) -> None:
    @app.get("/")
    def index() -> Response:
        return send_from_directory(STATIC_ROOT, "index.html")

    @app.get("/<page>")
    def static_page(page: str) -> Response:
        filename = _STATIC_PAGES.get(page)
        if filename:
            return send_from_directory(STATIC_ROOT, filename)
        return Response("Not found", status=404)

    @app.get("/css/<path:filename>")
    def static_css(filename: str) -> Response:
        return send_from_directory(STATIC_ROOT / "css", filename)

    @app.get("/js/<path:filename>")
    def static_js(filename: str) -> Response:
        return send_from_directory(STATIC_ROOT / "js", filename)

    @app.get("/assets/<path:filename>")
    def static_assets(filename: str) -> Response:
        return send_from_directory(STATIC_ROOT / "assets", filename)
