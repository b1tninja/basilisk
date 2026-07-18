from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import azure.functions as func

from basilisk.config import get_settings
from basilisk.hkp.handlers import get_store
from basilisk.openpgp.approve import approve_cert
from basilisk.serve import create_app

logger = logging.getLogger(__name__)

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

_flask = create_app()


def _path_and_query(req: func.HttpRequest) -> tuple[str, str]:
    """Reconstruct Flask path + query from an Azure Functions request."""
    parsed = urlparse(req.url or "/")
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    return path, parsed.query or ""


def _flask_response(req: func.HttpRequest) -> func.HttpResponse:
    path, query = _path_and_query(req)
    with _flask.test_request_context(
        path=path,
        method=req.method,
        data=req.get_body(),
        headers=dict(req.headers),
        query_string=query,
    ):
        resp = _flask.full_dispatch_request()
    return func.HttpResponse(
        body=resp.get_data(),
        status_code=resp.status_code,
        headers=dict(resp.headers),
        mimetype=resp.mimetype,
    )


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


@app.schedule(schedule="0 0 */6 * * *", arg_name="timer", run_on_startup=False)
def expire_pending_keys(timer: func.TimerRequest) -> None:
    """Reject unclaimed pending keys and hide/delete OpenPGP-expired approved keys.

    - Unclaimed pending older than BASILISK_PENDING_TTL_DAYS → rejected
    - Approved keys past key_expiration → approval_state=expired (hidden from search)
    - Expired keys past BASILISK_EXPIRED_GRACE_DAYS after key_expiration → delete blob+record
    """
    from basilisk.db.factory import get_blob_store

    settings = get_settings()
    store = get_store()
    now = datetime.now(timezone.utc)

    if settings.pending_ttl_days > 0:
        cutoff = now - timedelta(days=settings.pending_ttl_days)
        for record in store.list_pending_older_than(cutoff.isoformat()):
            # Only expire unclaimed keys.
            if record.claimer_email:
                continue
            store.reject(record.fingerprint)
            logger.info("Expired pending key %s", record.fingerprint)

    # Hide approved keys whose embedded OpenPGP expiration has passed.
    for record in store.list_approved_past_expiration(now.isoformat()):
        store.mark_expired(record.fingerprint)
        logger.info("Marked approved key expired (hidden) %s", record.fingerprint)

    # After grace period, delete blob + record.
    grace = max(0, settings.expired_grace_days)
    grace_cutoff = now - timedelta(days=grace)
    blobs = get_blob_store(settings)
    for record in store.list_expired_past_grace(grace_cutoff.isoformat()):
        if record.blob_uri:
            try:
                blobs.delete(record.blob_uri)
            except Exception:
                logger.warning(
                    "Blob delete failed for %s (%s)",
                    record.fingerprint,
                    record.blob_uri,
                    exc_info=True,
                )
        store.delete_cert(record.fingerprint)
        logger.info("Deleted expired key past grace %s", record.fingerprint)


@app.route(
    route="{*path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
    auth_level=func.AuthLevel.ANONYMOUS,
)
def http_proxy(req: func.HttpRequest) -> func.HttpResponse:
    """Single HTTP entrypoint — all routes handled by Flask create_app()."""
    return _flask_response(req)
