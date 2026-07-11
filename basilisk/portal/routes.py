from __future__ import annotations

import json

from flask import Flask, Response, request

from basilisk.auth.azure import require_principal
from basilisk.auth.errors import AuthError
from basilisk.config import get_settings
from basilisk.hkp.handlers import get_store
from basilisk.portal.me import my_keys
from basilisk.portal.search import search_keys
from basilisk.portal.serializers import key_summary
from basilisk.security.rate_limit import RateLimitError, check_lookup_rate, client_ip


def register_portal_api(app: Flask) -> None:
    settings = get_settings()

    # ------------------------------------------------------------------
    # Public endpoints
    # ------------------------------------------------------------------

    @app.get("/api/v1/auth/config")
    def api_auth_config() -> Response:
        return Response(
            json.dumps({"providers": list(settings.auth_providers)}),
            mimetype="application/json",
        )

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

    # ------------------------------------------------------------------
    # Auth status (lightweight — no DB)
    # ------------------------------------------------------------------

    @app.get("/api/v1/me")
    def api_me() -> Response:
        try:
            principal = require_principal(dict(request.headers))
        except AuthError:
            return Response(
                json.dumps({"authenticated": False}),
                status=401,
                mimetype="application/json",
            )
        return Response(
            json.dumps({
                "authenticated": True,
                "email": principal["email"],
                "name": principal.get("name", ""),
                "oid": principal.get("oid", ""),
            }),
            mimetype="application/json",
        )

    # ------------------------------------------------------------------
    # Authenticated: list keys
    # ------------------------------------------------------------------

    @app.get("/api/v1/me/keys")
    def api_me_keys() -> Response:
        try:
            principal = require_principal(dict(request.headers))
        except AuthError as exc:
            return Response(str(exc), status=exc.status, mimetype="application/json")
        payload = {
            "email": principal["email"],
            "keys": my_keys(principal, get_store(), settings),
        }
        return Response(json.dumps(payload), mimetype="application/json")

    # ------------------------------------------------------------------
    # Authenticated: submit a public key + auto-claim
    # ------------------------------------------------------------------

    @app.post("/api/v1/me/keys")
    def api_submit_key() -> Response:
        try:
            principal = require_principal(dict(request.headers))
        except AuthError as exc:
            return Response(
                json.dumps({"error": str(exc)}), status=exc.status, mimetype="application/json"
            )

        body = request.get_json(silent=True) or {}
        keytext = body.get("key", "").strip() if isinstance(body, dict) else ""
        if not keytext:
            return Response(
                json.dumps({"error": "No key provided. Send JSON {\"key\": \"<armored>\"}"}),
                status=400,
                mimetype="application/json",
            )

        from basilisk.hkp.handlers import get_blob_store, ingest_keytext
        from basilisk.openpgp.errors import IngestError

        try:
            store = get_store(settings)
            blob_store = get_blob_store(settings)
            fpr, _, dup = ingest_keytext(store, blob_store, keytext, path="web")
        except IngestError as exc:
            return Response(
                json.dumps({"error": str(exc)}),
                status=getattr(exc, "status", 400),
                mimetype="application/json",
            )

        # Attempt auto-claim so the key is associated with the signed-in identity.
        claimed = False
        claim_message = ""
        try:
            from basilisk.auth.claim import submit_claim
            from basilisk.openpgp.ingest import uid_string
            from pysequoia import Cert

            record = store.get_by_fingerprint(fpr)
            cert = Cert.from_bytes(blob_store.read(record.blob_uri))
            pending_uids = [uid_string(u) for u in cert.user_ids]
            claimed, claim_message = submit_claim(fpr, dict(request.headers), pending_uids)
        except Exception:
            pass  # Claim failure is non-fatal; user can claim manually.

        record = store.get_by_fingerprint(fpr)
        result = key_summary(record, settings, include_uids=True)
        result["duplicate"] = dup
        result["claimed"] = claimed
        result["claim_message"] = claim_message

        return Response(json.dumps(result), status=200, mimetype="application/json")
