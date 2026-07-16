from __future__ import annotations

from flask import Flask, Response, request

from basilisk.hkp.handlers import get_blob_store, get_store
from basilisk.openpgp.canonical import emails_from_uids
from basilisk.openpgp.wkd import parse_email, wkd_local_hash


def _serve_wkd(domain: str, hu: str) -> Response:
    """Return the binary OpenPGP key for an approved email matching domain+hash."""
    store = get_store()
    # Scan approved keys — email index is the source of truth.
    # We look up by iterating emails table via list isn't ideal; try common approach:
    # clients also send ?l=<local> on advanced method.
    local = (request.args.get("l") or "").strip().lower()
    if local:
        email = f"{local}@{domain.lower()}"
        record = store.get_by_email(email)
        if not record or record.approval_state != "approved":
            return Response("Not found", status=404)
        if wkd_local_hash(local) != hu:
            return Response("Not found", status=404)
        data = get_blob_store().read(record.blob_uri)
        return Response(
            data,
            status=200,
            mimetype="application/octet-stream",
            headers={"Access-Control-Allow-Origin": "*"},
        )

    # Without ?l=, find any approved email on this domain with matching hash.
    # Table/sqlite: use list from emails — get_by_email needs exact address.
    # Fall back: scan stats-sized stores via fingerprint search is too heavy;
    # require ?l= for advanced method when hash-only (direct method includes domain).
    return Response("Not found", status=404)


def register_wkd(app: Flask) -> None:
    @app.get("/.well-known/openpgpkey/policy")
    @app.get("/.well-known/openpgpkey/<domain>/policy")
    def wkd_policy(domain: str | None = None) -> Response:
        return Response(
            "protocol-version: 1\n",
            status=200,
            mimetype="text/plain",
            headers={"Access-Control-Allow-Origin": "*"},
        )

    # Advanced method: /.well-known/openpgpkey/hu/<hash>?l=<local>
    @app.get("/.well-known/openpgpkey/hu/<hu>")
    def wkd_advanced(hu: str) -> Response:
        local = (request.args.get("l") or "").strip().lower()
        if not local:
            return Response("Not found", status=404)
        # Domain comes from Host header for advanced method.
        host = (request.host or "").split(":")[0].lower()
        # Strip openpgpkey. prefix if present (advanced WKD subdomain).
        domain = host.removeprefix("openpgpkey.")
        return _serve_wkd(domain, hu)

    # Direct method: /.well-known/openpgpkey/<domain>/hu/<hash>
    @app.get("/.well-known/openpgpkey/<domain>/hu/<hu>")
    def wkd_direct(domain: str, hu: str) -> Response:
        return _serve_wkd(domain, hu)
