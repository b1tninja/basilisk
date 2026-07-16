from __future__ import annotations

import json
import logging
from typing import Any

import azure.functions as func

from basilisk.config import get_settings
from basilisk.hkp.handlers import (
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
from basilisk.security.rate_limit import RateLimitError, check_lookup_rate, check_upload_rate, client_ip
from basilisk.serve import create_app

logger = logging.getLogger(__name__)

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

_flask = create_app()


def _flask_response(req: func.HttpRequest):
    with _flask.test_request_context(
        path=req.url.split("?", 1)[0].split("/", 3)[-1] if req.url else "/",
        method=req.method,
        data=req.get_body(),
        headers=dict(req.headers),
        query_string=req.url.split("?", 1)[1] if req.url and "?" in req.url else "",
    ):
        return _flask.full_dispatch_request()


@app.route(route="health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse("ok", status_code=200)


@app.route(route="pks/lookup", methods=["GET"])
def hkp_lookup(req: func.HttpRequest) -> func.HttpResponse:
    op = req.params.get("op", "get")
    search = req.params.get("search", "")
    if op == "stats":
        r = lookup_stats()
    else:
        ip = client_ip(dict(req.headers))
        try:
            check_lookup_rate(ip)
        except RateLimitError as exc:
            inc("rate_limited")
            return func.HttpResponse(str(exc), status_code=exc.status)
        if op == "index":
            r = lookup_index(search)
        elif op == "get":
            r = lookup_get(search, if_none_match=req.headers.get("If-None-Match"))
        else:
            return func.HttpResponse("Unsupported operation", status_code=501)
    body = r.body if isinstance(r.body, bytes) else str(r.body).encode()
    return func.HttpResponse(body=body, status_code=r.status, headers=r.headers, mimetype=r.mimetype)


@app.route(route="pks/add", methods=["POST"])
def hkp_add(req: func.HttpRequest) -> func.HttpResponse:
    settings = get_settings()
    ip = client_ip(dict(req.headers))
    try:
        check_upload_rate(ip)
        keytext = parse_add_form(req.get_body(), req.headers.get("Content-Type"))
        fpr, _, dup = ingest_keytext(get_store(), get_blob_store(), keytext, path="v1")
        if dup:
            inc("duplicate_uploads")
        claim = f"{settings.base_url}/claim/{fpr}"
        return func.HttpResponse(f"Ok\nClaim: {claim}\n", status_code=200, mimetype="text/plain")
    except RateLimitError as exc:
        inc("rate_limited")
        return func.HttpResponse(str(exc), status_code=exc.status)
    except IngestError as exc:
        inc("rejected_uploads")
        return func.HttpResponse(str(exc), status_code=exc.status)


@app.route(route="api/v1/dev/approve", methods=["POST"])
def dev_approve(req: func.HttpRequest) -> func.HttpResponse:
    settings = get_settings()
    if not settings.dev_approve:
        return func.HttpResponse("Forbidden", status_code=403)
    try:
        payload: dict[str, Any] = json.loads(req.get_body().decode() or "{}")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return func.HttpResponse(f"Invalid JSON body: {exc}", status_code=400)
    if not isinstance(payload, dict):
        return func.HttpResponse("JSON body must be an object", status_code=400)
    fpr = payload.get("fingerprint", "")
    uids = payload.get("approved_uids")
    store = get_store()
    record = store.get_by_fingerprint(fpr)
    if not record:
        return func.HttpResponse("Not found", status_code=404)
    if not uids:
        from pysequoia import Cert

        from basilisk.openpgp.ingest import uid_string

        try:
            cert = Cert.from_bytes(get_blob_store().read(record.blob_uri))
        except Exception as exc:
            logger.exception("Failed to read cert blob for %s", fpr)
            return func.HttpResponse(f"Failed to read certificate: {exc}", status_code=500)
        uids = [uid_string(u) for u in cert.user_ids]
    approve_cert(store, fpr, uids)
    return func.HttpResponse(json.dumps({"status": "approved"}), mimetype="application/json")


@app.service_bus_queue_trigger(
    arg_name="msg",
    queue_name="key-approved",
    connection="ServiceBusConnection",
)
def approve_fn(msg: func.ServiceBusMessage) -> None:
    body = json.loads(msg.get_body().decode())
    if body.get("event") != "key.approved":
        return
    fpr = body["fingerprint"]
    uids = body.get("approved_uids", [])
    approve_cert(get_store(), fpr, uids)
    logger.info("Approved %s", fpr)


@app.route(route="pks/v2/{*path}", methods=["GET", "POST", "PUT", "OPTIONS"])
def hkp_v2(req: func.HttpRequest) -> func.HttpResponse:
    resp = _flask_response(req)
    return func.HttpResponse(
        body=resp.get_data(),
        status_code=resp.status_code,
        headers=dict(resp.headers),
        mimetype=resp.mimetype,
    )


@app.route(route="api/v1/{*path}", methods=["GET", "POST"])
def portal_api(req: func.HttpRequest) -> func.HttpResponse:
    resp = _flask_response(req)
    return func.HttpResponse(
        body=resp.get_data(),
        status_code=resp.status_code,
        headers=dict(resp.headers),
        mimetype=resp.mimetype,
    )


@app.route(route="claim/{fingerprint}", methods=["GET", "POST"])
def claim(req: func.HttpRequest) -> func.HttpResponse:
    resp = _flask_response(req)
    return func.HttpResponse(
        body=resp.get_data(),
        status_code=resp.status_code,
        headers=dict(resp.headers),
        mimetype=resp.mimetype,
    )
