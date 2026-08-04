"""HKP v2 routes (draft-gallagher-openpgp-hkp-10 §5).

Every response carries ``Access-Control-Allow-Origin: *`` — §7.1 makes that a
MUST for the v2 API, including the submission paths. That is safe here only
because Basilisk carries no ambient credentials: there is no cookie or session
anywhere in the server, and the only authenticated v2 operation
(``PUT /pks/v2/canonical``) is gated on a Bearer token that a cross-origin
attacker cannot obtain. See ``docs/CRYPTOGRAPHY.md``.
"""

from __future__ import annotations

import json

from flask import Flask, Response, request

from basilisk.hkp.cors import cors_get_headers, flask_cors
from basilisk.hkp_v2.index import index_for_identity
from basilisk.hkp_v2.lookup import (
    canonical_bundle,
    certs_by_identity,
    certs_by_keyid,
    certs_by_vfingerprint,
)
from basilisk.hkp_v2.submit import (
    ACCEPT_BASIC,
    ACCEPT_TOKEN_PROOF,
    canonical_put,
    certs_post,
    sendtoken_response,
)
from basilisk.observability.metrics import inc
from basilisk.openpgp.errors import IngestError
from basilisk.security.proof import ProofError, issue_challenge, verify_proof
from basilisk.security.rate_limit import (
    RateLimitError,
    check_lookup_rate,
    check_sendtoken_rate,
    check_upload_rate,
    client_ip,
)
from basilisk.serve import _to_flask

# Headers a browser client must be allowed to send on a v2 submission preflight.
_ALLOWED_REQUEST_HEADERS = "Authorization, Authentication, Content-Type, X-Basilisk-Proof"

# Coarse guard applied before dearmoring; the real per-certificate budget is
# ``settings.max_upload_bytes``, enforced against the armored form in ingest.
MAX_SUBMISSION_BYTES = 1024 * 1024


def _options(allow: str, accept: tuple[str, ...] = ()) -> Response:
    """§5.1.7 / §5.2.6 feature detection: 200 with ``Allow:`` and, for
    submissions, ``Accept:``."""
    headers = cors_get_headers(
        {
            "Allow": allow,
            "Access-Control-Allow-Methods": allow,
            "Access-Control-Allow-Headers": _ALLOWED_REQUEST_HEADERS,
        }
    )
    response = Response("", status=200, headers=headers)
    for media_type in accept:
        response.headers.add("Accept", media_type)
    return response


def _bearer_token() -> str | None:
    """§5.2.4.1 spells the header ``Authentication: Bearer <token>``.

    Real-world clients and proxies send ``Authorization``, so both are read.
    """
    for name in ("Authentication", "Authorization"):
        value = request.headers.get(name, "")
        if value.lower().startswith("bearer "):
            return value.split(" ", 1)[1].strip()
    return None


def _submission_body() -> bytes:
    """Basic (§5.2.4) or advanced (§5.2.5) submission payload."""
    content_type = request.content_type or ""
    if content_type.startswith("multipart/form-data"):
        part = request.files.get("keytext")
        if part is not None:
            return part.read()
        form_value = request.form.get("keytext")
        if form_value is not None:
            return form_value.encode("utf-8")
        raise IngestError("multipart submission requires a 'keytext' part", 422)
    return request.get_data()


def _submission_result(body: dict | str, status: int) -> Response:
    if status >= 400:
        inc("rejected_uploads")
    if isinstance(body, str):
        return flask_cors(status, body)
    return flask_cors(status, json.dumps(body), mimetype="application/json")


def register_v2(app: Flask) -> None:
    def _rate_limited_lookup(fn, identifier: str) -> Response:
        ip = client_ip(dict(request.headers), request.remote_addr)
        try:
            check_lookup_rate(ip)
        except RateLimitError as exc:
            inc("rate_limited")
            return flask_cors(exc.status, str(exc))
        return _to_flask(fn(identifier))

    # ---- Feature detection (§5.1.7, §5.2.6) -------------------------------
    # The category path component is present, the identifier is absent.

    @app.route("/pks/v2/certs/by-identity", methods=["OPTIONS"])
    @app.route("/pks/v2/certs/by-vfingerprint", methods=["OPTIONS"])
    @app.route("/pks/v2/certs/by-keyid", methods=["OPTIONS"])
    @app.route("/pks/v2/index", methods=["OPTIONS"])
    def v2_lookup_options() -> Response:
        return _options("GET, HEAD, OPTIONS")

    @app.route("/pks/v2/certs", methods=["OPTIONS"])
    def v2_certs_options() -> Response:
        return _options("POST, OPTIONS", (ACCEPT_BASIC, ACCEPT_TOKEN_PROOF))

    @app.route("/pks/v2/canonical", methods=["OPTIONS"])
    def v2_canonical_options() -> Response:
        return _options("GET, HEAD, PUT, OPTIONS", (ACCEPT_BASIC, ACCEPT_TOKEN_PROOF))

    @app.route("/pks/v2/sendtoken", methods=["OPTIONS"])
    def v2_sendtoken_options() -> Response:
        return _options("POST, OPTIONS", ("text/plain",))

    @app.route("/pks/v2/prefixlog", methods=["OPTIONS"])
    @app.route("/pks/v2/prefixlog/<identifier>", methods=["GET", "OPTIONS"])
    def v2_prefixlog(identifier: str | None = None) -> Response:
        # §5.1.6 is a MAY. Serving it needs a modification log the cert store
        # does not index yet, so the category reports itself unsupported.
        return flask_cors(501, "prefixlog is not supported")

    # ---- Lookups (§5.1) ---------------------------------------------------

    @app.get("/pks/v2/certs/by-identity/<path:identity>")
    def v2_certs_by_identity(identity: str) -> Response:
        return _rate_limited_lookup(certs_by_identity, identity)

    @app.get("/pks/v2/certs/by-vfingerprint/<vfingerprint>")
    def v2_certs_by_vfingerprint(vfingerprint: str) -> Response:
        return _rate_limited_lookup(certs_by_vfingerprint, vfingerprint)

    @app.get("/pks/v2/certs/by-keyid/<keyid>")
    def v2_certs_by_keyid(keyid: str) -> Response:
        return _rate_limited_lookup(certs_by_keyid, keyid)

    @app.get("/pks/v2/index/<path:identity>")
    def v2_index(identity: str) -> Response:
        return _rate_limited_lookup(index_for_identity, identity)

    @app.get("/pks/v2/canonical/<path:identity>")
    def v2_canonical_get(identity: str) -> Response:
        return _rate_limited_lookup(canonical_bundle, identity)

    # §5.1.7: "A keyserver SHOULD return an error code such as 403 Forbidden"
    # to a GET without both category and identifier.
    @app.get("/pks/v2/certs/by-identity")
    @app.get("/pks/v2/certs/by-vfingerprint")
    @app.get("/pks/v2/certs/by-keyid")
    @app.get("/pks/v2/index")
    @app.get("/pks/v2/canonical")
    def v2_lookup_without_identifier() -> Response:
        return flask_cors(403, "An identifier path component is required")

    @app.get("/pks/v2/challenge")
    def v2_challenge() -> Response:
        return flask_cors(200, json.dumps(issue_challenge()), mimetype="application/json")

    # ---- Submissions (§5.2) ----------------------------------------------

    @app.post("/pks/v2/sendtoken")
    def v2_sendtoken() -> Response:
        # §5.2.2: "The body of the POST request is a single email address."
        ip = client_ip(dict(request.headers), request.remote_addr)
        raw = request.get_data(as_text=True).strip()
        email = raw if ("@" in raw and len(raw.split()) == 1 and "{" not in raw) else ""
        if not email:
            # Tolerate the pre-spec query/JSON callers still in the wild.
            email = request.args.get("email") or (
                request.get_json(silent=True) or {}
            ).get("email", "")
        try:
            verify_proof(request.headers.get("X-Basilisk-Proof"))
            check_sendtoken_rate(ip, email)
            body, status = sendtoken_response(email)
            # §5.2.2: "The keyserver SHOULD respond with an empty document."
            return flask_cors(status, body)
        except (ProofError, RateLimitError) as exc:
            inc("rate_limited")
            return flask_cors(exc.status, str(exc))

    @app.post("/pks/v2/certs")
    def v2_certs_post() -> Response:
        ip = client_ip(dict(request.headers), request.remote_addr)
        try:
            verify_proof(request.headers.get("X-Basilisk-Proof"))
            check_upload_rate(ip)
            payload = _submission_body()
            if len(payload) > MAX_SUBMISSION_BYTES:
                raise IngestError("Payload too large", 413)
            return _submission_result(*certs_post(payload))
        except (ProofError, RateLimitError) as exc:
            inc("rate_limited")
            return flask_cors(exc.status, str(exc))
        except IngestError as exc:
            inc("rejected_uploads")
            return flask_cors(exc.status, str(exc))

    @app.put("/pks/v2/canonical/<path:identity>")
    def v2_canonical_put(identity: str) -> Response:
        ip = client_ip(dict(request.headers), request.remote_addr)
        token = _bearer_token()
        if token is None:
            return flask_cors(401, "Unauthorized")
        try:
            verify_proof(request.headers.get("X-Basilisk-Proof"))
            check_upload_rate(ip)
            payload = _submission_body()
            if len(payload) > MAX_SUBMISSION_BYTES:
                raise IngestError("Payload too large", 413)
            return _submission_result(*canonical_put(identity, token, payload))
        except (ProofError, RateLimitError) as exc:
            inc("rate_limited")
            return flask_cors(exc.status, str(exc))
        except IngestError as exc:
            inc("rejected_uploads")
            return flask_cors(exc.status, str(exc))

    # §4.2: "501 Not implemented — The requested category/operation is not
    # supported." Catch-all for v2 categories this server does not implement.
    @app.route(
        "/pks/v2/<path:unsupported>",
        methods=["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"],
    )
    def v2_unsupported(unsupported: str) -> Response:
        return flask_cors(501, "Unsupported v2 category or operation")
