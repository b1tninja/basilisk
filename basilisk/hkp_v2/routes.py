from __future__ import annotations

import json

from flask import Flask, Response, request

from basilisk.hkp.lookup import lookup_get
from basilisk.hkp_v2.submit import canonical_put, certs_post, sendtoken_response
from basilisk.observability.metrics import inc
from basilisk.openpgp.errors import IngestError
from basilisk.openpgp.ingest import normalize_fingerprint
from basilisk.security.proof import ProofError, issue_challenge, verify_proof
from basilisk.security.rate_limit import (
    RateLimitError,
    check_lookup_rate,
    check_sendtoken_rate,
    check_upload_rate,
    client_ip,
)
from basilisk.serve import _to_flask


def _lookup_with_rate_limit(search: str) -> Response:
    ip = client_ip(dict(request.headers), request.remote_addr)
    try:
        check_lookup_rate(ip)
        return _to_flask(lookup_get(search))
    except RateLimitError as exc:
        inc("rate_limited")
        return Response(str(exc), status=exc.status)


def register_v2(app: Flask) -> None:
    @app.route("/pks/v2/certs", methods=["OPTIONS"])
    def v2_certs_options() -> Response:
        headers = {
            "Allow": "POST",
            "Accept": "application/pgp-keys, application/pgp-keys;proof=tokens",
        }
        return Response("", status=200, headers=headers)

    @app.get("/pks/v2/challenge")
    def v2_challenge() -> Response:
        return Response(json.dumps(issue_challenge()), mimetype="application/json")

    @app.post("/pks/v2/sendtoken")
    def v2_sendtoken() -> Response:
        ip = client_ip(dict(request.headers), request.remote_addr)
        email = request.args.get("email") or (request.get_json(silent=True) or {}).get("email", "")
        try:
            verify_proof(request.headers.get("X-Basilisk-Proof"))
            check_sendtoken_rate(ip, email)
            body, status = sendtoken_response(email)
            if status != 200:
                return Response(body.get("error", "Invalid"), status=status)
            return Response(json.dumps(body), mimetype="application/json")
        except (ProofError, RateLimitError) as exc:
            inc("rate_limited")
            return Response(str(exc), status=exc.status)

    @app.put("/pks/v2/canonical/<path:identity>")
    def v2_canonical_put(identity: str) -> Response:
        ip = client_ip(dict(request.headers), request.remote_addr)
        auth = request.headers.get("Authorization", "")
        if not auth.lower().startswith("bearer "):
            return Response("Unauthorized", status=401)
        token = auth.split(" ", 1)[1]
        try:
            verify_proof(request.headers.get("X-Basilisk-Proof"))
            check_upload_rate(ip)
            body, status = canonical_put(identity, token, request.get_data(as_text=True))
            if isinstance(body, str):
                if status >= 400:
                    inc("rejected_uploads")
                return Response(body, status=status)
            return Response(json.dumps(body), mimetype="application/json", status=status)
        except (ProofError, RateLimitError) as exc:
            inc("rate_limited")
            return Response(str(exc), status=exc.status)
        except IngestError as exc:
            inc("rejected_uploads")
            return Response(str(exc), status=exc.status)

    @app.get("/pks/v2/canonical/<path:identity>")
    def v2_canonical_get(identity: str) -> Response:
        return _lookup_with_rate_limit(identity)

    @app.get("/pks/v2/certs/by-fingerprint/<fingerprint>")
    def v2_by_fpr(fingerprint: str) -> Response:
        return _lookup_with_rate_limit(f"0x{normalize_fingerprint(fingerprint)}")

    @app.get("/pks/v2/certs/by-keyid/<keyid>")
    def v2_by_kid(keyid: str) -> Response:
        return _lookup_with_rate_limit(f"0x{keyid.lower().removeprefix('0x')}")

    @app.get("/pks/v2/certs/by-identity/<path:email>")
    def v2_by_email(email: str) -> Response:
        return _lookup_with_rate_limit(email)

    @app.post("/pks/v2/certs")
    def v2_certs_post() -> Response:
        ip = client_ip(dict(request.headers), request.remote_addr)
        try:
            verify_proof(request.headers.get("X-Basilisk-Proof"))
            check_upload_rate(ip)
            body, status = certs_post(request.get_data(as_text=True))
            if isinstance(body, str):
                if status >= 400:
                    inc("rejected_uploads")
                return Response(body, status=status)
            return Response(json.dumps(body), mimetype="application/json", status=status)
        except (ProofError, RateLimitError) as exc:
            inc("rate_limited")
            return Response(str(exc), status=exc.status)
