from __future__ import annotations

from flask import Flask, Response, request

from basilisk.hkp.cors import flask_cors, options_get_only
from basilisk.hkp.handlers import get_blob_store, get_store
from basilisk.openpgp.wkd import wkd_local_hash


def _serve_wkd(domain: str, hu: str) -> Response:
    """Return the binary OpenPGP key for an approved email matching domain+hash."""
    store = get_store()
    local = (request.args.get("l") or "").strip().lower()
    if local:
        email = f"{local}@{domain.lower()}"
        record = store.get_by_email(email)
        if not record or record.approval_state != "approved":
            return flask_cors(404, "Not found")
        if wkd_local_hash(local) != hu:
            return flask_cors(404, "Not found")
        data = get_blob_store().read(record.blob_uri)
        return flask_cors(
            200,
            data,
            mimetype="application/octet-stream",
        )

    # Without ?l=, find any approved email on this domain with matching hash.
    # Require ?l= for advanced method when hash-only.
    return flask_cors(404, "Not found")


def register_wkd(app: Flask) -> None:
    @app.route("/.well-known/openpgpkey/policy", methods=["OPTIONS"])
    @app.route("/.well-known/openpgpkey/<domain>/policy", methods=["OPTIONS"])
    @app.route("/.well-known/openpgpkey/hu/<hu>", methods=["OPTIONS"])
    @app.route("/.well-known/openpgpkey/<domain>/hu/<hu>", methods=["OPTIONS"])
    def wkd_options(domain: str | None = None, hu: str | None = None) -> Response:
        return options_get_only()

    @app.get("/.well-known/openpgpkey/policy")
    @app.get("/.well-known/openpgpkey/<domain>/policy")
    def wkd_policy(domain: str | None = None) -> Response:
        return flask_cors(
            200,
            "protocol-version: 1\n",
            mimetype="text/plain",
        )

    # Advanced method: /.well-known/openpgpkey/hu/<hash>?l=<local>
    @app.get("/.well-known/openpgpkey/hu/<hu>")
    def wkd_advanced(hu: str) -> Response:
        local = (request.args.get("l") or "").strip().lower()
        if not local:
            return flask_cors(404, "Not found")
        # Domain comes from Host header for advanced method.
        host = (request.host or "").split(":")[0].lower()
        # Strip openpgpkey. prefix if present (advanced WKD subdomain).
        domain = host.removeprefix("openpgpkey.")
        return _serve_wkd(domain, hu)

    # Direct method: /.well-known/openpgpkey/<domain>/hu/<hash>
    @app.get("/.well-known/openpgpkey/<domain>/hu/<hu>")
    def wkd_direct(domain: str, hu: str) -> Response:
        return _serve_wkd(domain, hu)
