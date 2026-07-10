from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from flask import Flask, Response, request

from basilisk.auth.claim import submit_claim
from basilisk.config import get_settings
from basilisk.hkp.handlers import (
    HttpResponse,
    get_blob_store,
    get_store,
    ingest_keytext,
    lookup_get,
    lookup_index,
    lookup_stats,
    parse_add_form,
)
from basilisk.observability.metrics import inc
from basilisk.openpgp.approve import approve_cert
from basilisk.openpgp.errors import IngestError
from basilisk.security.proof import ProofError, issue_challenge, verify_proof
from basilisk.security.rate_limit import (
    RateLimitError,
    check_lookup_rate,
    check_sendtoken_rate,
    check_upload_rate,
    client_ip,
)


def _to_flask(resp: HttpResponse) -> Response:
    body = resp.body if isinstance(resp.body, (bytes, bytearray)) else str(resp.body).encode("utf-8")
    if resp.status == 304:
        return Response(status=304, headers=resp.headers)
    r = Response(body, status=resp.status, headers=resp.headers)
    if resp.mimetype:
        r.mimetype = resp.mimetype
    return r


def create_app() -> Flask:
    app = Flask(__name__)
    settings = get_settings()

    @app.get("/health")
    def health() -> Response:
        return Response("ok", status=200, mimetype="text/plain")

    @app.get("/pks/lookup")
    def hkp_lookup() -> Response:
        op = request.args.get("op", "get")
        search = request.args.get("search", "")
        if op == "stats":
            return _to_flask(lookup_stats())
        ip = client_ip(dict(request.headers), request.remote_addr)
        try:
            check_lookup_rate(ip)
        except RateLimitError as exc:
            inc("rate_limited")
            return Response(str(exc), status=exc.status, mimetype="text/plain")
        if op == "index":
            return _to_flask(lookup_index(search))
        if op == "get":
            etag = request.headers.get("If-None-Match")
            return _to_flask(lookup_get(search, if_none_match=etag))
        return _to_flask(HttpResponse(501, "Unsupported operation", {}, "text/plain"))

    @app.post("/pks/add")
    def hkp_add() -> Response:
        store = get_store()
        blobs = get_blob_store()
        ip = client_ip(dict(request.headers), request.remote_addr)
        try:
            check_upload_rate(ip)
            keytext = parse_add_form(request.get_data(), request.content_type)
            fpr, _kid, dup = ingest_keytext(store, blobs, keytext, path="v1")
            if dup:
                inc("duplicate_uploads")
            claim = f"{settings.base_url}/claim/{fpr}"
            return Response(f"Ok\nClaim: {claim}\n", status=200, mimetype="text/plain")
        except RateLimitError as exc:
            inc("rate_limited")
            return Response(str(exc), status=exc.status, mimetype="text/plain")
        except IngestError as exc:
            inc("rejected_uploads")
            return Response(str(exc), status=exc.status, mimetype="text/plain")

    @app.post("/api/v1/dev/approve")
    def dev_approve() -> Response:
        if not settings.dev_approve:
            return Response("Forbidden", status=403)
        payload: dict[str, Any] = request.get_json(force=True, silent=True) or {}
        fpr = payload.get("fingerprint", "")
        uids = payload.get("approved_uids")
        store = get_store()
        record = store.get_by_fingerprint(fpr)
        if not record:
            return Response("Not found", status=404)
        if not uids:
            from pysequoia import Cert

            cert = Cert.from_bytes(get_blob_store().read(record.blob_uri))
            from basilisk.openpgp.ingest import uid_string

            uids = [uid_string(u) for u in cert.user_ids]
        approve_cert(store, fpr, uids)
        return Response(json.dumps({"status": "approved", "fingerprint": fpr.upper()}), mimetype="application/json")

    @app.get("/claim/<fingerprint>")
    @app.post("/claim/<fingerprint>")
    def claim_page(fingerprint: str) -> Response:
        store = get_store()
        record = store.get_by_fingerprint(fingerprint)
        if not record:
            return Response("Not found", status=404)
        if request.method == "POST":
            from pysequoia import Cert

            cert = Cert.from_bytes(get_blob_store().read(record.blob_uri))
            from basilisk.openpgp.ingest import uid_string

            pending_uids = [uid_string(u) for u in cert.user_ids]
            ok, msg = submit_claim(fingerprint, dict(request.headers), pending_uids)
            return Response(msg, status=200 if ok else 403)
        html_path = Path(__file__).resolve().parent / "web" / "templates" / "claim.html"
        html = html_path.read_text(encoding="utf-8").replace("{{ fingerprint }}", fingerprint.upper())
        return Response(html, mimetype="text/html")

    from basilisk.hkp_v2.routes import register_v2

    register_v2(app)

    from basilisk.portal.routes import register_portal_api
    from basilisk.portal.static import register_static_portal

    register_portal_api(app)
    register_static_portal(app)
    return app


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Basilisk dev HTTP server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    create_app().run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
