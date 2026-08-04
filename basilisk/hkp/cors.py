"""GET-only CORS for public key fetch endpoints (HKP / WKD / key JSON).

Public key material is intentionally world-readable. Legacy mutating endpoints
(POST /pks/add, claim, /api/v1/me/*) must NOT use these helpers.

The one exception is the HKP v2 API: draft-gallagher-openpgp-hkp §7.1 makes
``Access-Control-Allow-Origin: *`` a MUST on every ``/pks/v2/*`` response,
submissions included, so ``basilisk/hkp_v2/routes.py`` uses ``flask_cors`` on
its write paths too. That is only defensible because this server holds no
ambient credential — no cookie, no session — so ``*`` grants a cross-origin
page nothing it could not obtain from its own backend. Note that
``CORS_GET_HEADERS`` still advertises GET-only *methods*; the v2 preflight
handler overrides ``Access-Control-Allow-Methods`` per category.

Never pair Access-Control-Allow-Origin: * with Allow-Credentials.
"""

from __future__ import annotations

from flask import Response

from basilisk.hkp.response import HttpResponse

# Exposed to browser clients (OpenPGP.js / Keyoxide / other portals).
CORS_GET_HEADERS: dict[str, str] = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Max-Age": "86400",
}


def cors_get_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Merge GET CORS headers with response-specific headers (extra wins on conflict)."""
    out = dict(CORS_GET_HEADERS)
    if extra:
        out.update(extra)
    return out


def http_cors(
    status: int,
    body: bytes | str,
    *,
    mimetype: str = "text/plain",
    extra: dict[str, str] | None = None,
) -> HttpResponse:
    return HttpResponse(status, body, cors_get_headers(extra), mimetype)


def flask_cors(
    status: int,
    body: bytes | str = "",
    *,
    mimetype: str | None = "text/plain",
    extra: dict[str, str] | None = None,
) -> Response:
    headers = cors_get_headers(extra)
    if status == 204:
        return Response(status=204, headers=headers)
    r = Response(body, status=status, headers=headers)
    if mimetype:
        r.mimetype = mimetype
    return r


def options_get_only(*, allow: str = "GET, HEAD, OPTIONS") -> Response:
    """Preflight for GET-only public key endpoints."""
    return flask_cors(
        204,
        "",
        mimetype=None,
        extra={"Allow": allow},
    )
