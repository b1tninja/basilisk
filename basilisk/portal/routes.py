from __future__ import annotations

import json
import logging

from flask import Flask, Response, request

from basilisk.auth.azure import require_principal
from basilisk.auth.errors import AuthError
from basilisk.config import get_settings
from basilisk.hkp.handlers import get_store
from basilisk.openpgp.canonical import emails_from_uids
from basilisk.portal.me import my_keys
from basilisk.portal.search import search_keys
from basilisk.portal.serializers import key_summary
from basilisk.security.rate_limit import (
    RateLimitError,
    check_lookup_rate,
    check_upload_rate,
    client_ip,
)

logger = logging.getLogger(__name__)


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

    @app.get("/api/v1/key/<fingerprint>")
    def api_key_detail(fingerprint: str) -> Response:
        record = get_store(settings).get_by_fingerprint(fingerprint)
        if not record:
            return Response(
                json.dumps({"error": "Not found"}),
                status=404,
                mimetype="application/json",
            )

        payload = {
            "fingerprint": record.fingerprint,
            "key_id": record.key_id,
            "approval_state": record.approval_state,
            "revoked": record.revoked,
            "key_expiration": record.key_expiration,
            "approved_uids": record.approved_uids if record.approval_state == "approved" else [],
            "sha256": record.sha256,
        }

        # Pending UIDs / claimer email only for the authenticated claimant.
        try:
            principal = require_principal(dict(request.headers))
        except AuthError:
            principal = None

        is_claimer = bool(
            principal
            and record.claimer_email
            and principal["email"].lower() == record.claimer_email.lower()
        )
        if is_claimer or (principal and record.approval_state == "pending"):
            # Claimants (or signed-in users inspecting a pending key they may claim)
            # can see pending UIDs; claimer_email only if they are the claimer.
            if record.approval_state == "pending":
                payload["pending_uids"] = record.pending_uids or []
            if is_claimer:
                payload["claimer_email"] = record.claimer_email
        elif record.approval_state == "approved":
            payload["pending_uids"] = []

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
        from basilisk.openpgp.ingest import parse_armored_keytext

        ip = client_ip(dict(request.headers), request.remote_addr)
        try:
            parsed_pre = parse_armored_keytext(keytext, path="v1")
            check_upload_rate(ip, parsed_pre.fingerprint)
        except RateLimitError as exc:
            return Response(
                json.dumps({"error": str(exc)}), status=exc.status, mimetype="application/json"
            )
        except IngestError as exc:
            return Response(
                json.dumps({"error": str(exc)}),
                status=getattr(exc, "status", 400),
                mimetype="application/json",
            )

        uid_emails = emails_from_uids(parsed_pre.uids)
        if principal["email"].lower() not in uid_emails:
            return Response(
                json.dumps(
                    {
                        "error": (
                            f"None of the key's UIDs match your signed-in email "
                            f"({principal['email']}). Use /pks/add for anonymous upload."
                        )
                    }
                ),
                status=422,
                mimetype="application/json",
            )

        try:
            store = get_store(settings)
            blob_store = get_blob_store(settings)
            fpr, _, dup = ingest_keytext(store, blob_store, keytext, path="v1")
        except IngestError as exc:
            return Response(
                json.dumps({"error": str(exc)}),
                status=getattr(exc, "status", 400),
                mimetype="application/json",
            )

        claimed = False
        claim_message = ""
        try:
            from basilisk.auth.claim import submit_claim

            claimed, claim_message = submit_claim(
                fpr, dict(request.headers), parsed_pre.uids
            )
        except Exception:
            logger.warning("Auto-claim failed for %s; user can claim manually", fpr, exc_info=True)

        record = store.get_by_fingerprint(fpr)
        result = key_summary(record, settings, include_uids=True)
        result["duplicate"] = dup
        result["claimed"] = claimed
        result["claim_message"] = claim_message

        return Response(json.dumps(result), status=200, mimetype="application/json")

    # ------------------------------------------------------------------
    # Authenticated: delete / unpublish own key
    # ------------------------------------------------------------------

    @app.delete("/api/v1/me/keys/<fingerprint>")
    def api_delete_key(fingerprint: str) -> Response:
        try:
            principal = require_principal(dict(request.headers))
        except AuthError as exc:
            return Response(
                json.dumps({"error": str(exc)}), status=exc.status, mimetype="application/json"
            )
        store = get_store(settings)
        record = store.get_by_fingerprint(fingerprint)
        if not record:
            return Response(json.dumps({"error": "Not found"}), status=404, mimetype="application/json")
        claimer = (record.claimer_email or "").lower()
        if claimer != principal["email"].lower():
            return Response(
                json.dumps({"error": "Only the claimer can delete this key"}),
                status=403,
                mimetype="application/json",
            )
        store.reject(fingerprint)
        return Response(
            json.dumps({"status": "deleted", "fingerprint": record.fingerprint}),
            mimetype="application/json",
        )
