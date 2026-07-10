from __future__ import annotations

import json

from flask import Flask, Response, request

from basilisk.auth.azure import require_principal
from basilisk.auth.errors import AuthError
from basilisk.config import get_settings
from basilisk.hkp.handlers import get_store
from basilisk.portal.me import my_keys
from basilisk.portal.search import search_keys
from basilisk.security.rate_limit import RateLimitError, check_lookup_rate, client_ip


def register_portal_api(app: Flask) -> None:
    settings = get_settings()

    @app.get("/api/v1/search")
    def api_search() -> Response:
        query = request.args.get("q", "").strip()
        ip = client_ip(dict(request.headers), request.remote_addr)
        try:
            check_lookup_rate(ip)
        except RateLimitError as exc:
            return Response(str(exc), status=exc.status, mimetype="text/plain")
        payload = search_keys(query, get_store(), settings)
        return Response(json.dumps(payload), mimetype="application/json")

    @app.get("/api/v1/me/keys")
    def api_me_keys() -> Response:
        try:
            principal = require_principal(dict(request.headers))
        except AuthError as exc:
            return Response(str(exc), status=exc.status, mimetype="application/json")
        payload = {"email": principal["email"], "keys": my_keys(principal, get_store(), settings)}
        return Response(json.dumps(payload), mimetype="application/json")
