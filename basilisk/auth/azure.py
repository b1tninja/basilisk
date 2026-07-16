from __future__ import annotations

import os

from basilisk.auth.errors import AuthError


def _header_value(headers: dict[str, str], name: str) -> str | None:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def _dev_auth_bypass_enabled() -> bool:
    """Local/dev only: allow forged Easy Auth headers when explicitly enabled."""
    return os.environ.get("BASILISK_DEV_AUTH", "").strip().lower() in ("1", "true", "yes", "on")


def _has_trusted_edge_marker(headers: dict[str, str]) -> bool:
    """
    Easy Auth sets additional headers alongside X-MS-CLIENT-PRINCIPAL.
    Require at least one so clients cannot forge a principal alone.
    Production must also strip client-supplied copies at the edge (Front Door / Functions).
    """
    return bool(
        _header_value(headers, "X-MS-CLIENT-PRINCIPAL-ID")
        or _header_value(headers, "X-MS-CLIENT-PRINCIPAL-IDP")
        or _header_value(headers, "X-MS-CLIENT-PRINCIPAL-NAME")
    )


def parse_easy_auth_headers(headers: dict[str, str]) -> dict[str, str] | None:
    """Parse Azure Easy Auth client principal header (supports AAD and Google providers)."""
    import base64
    import json

    raw = _header_value(headers, "X-MS-CLIENT-PRINCIPAL")
    if not raw:
        return None

    if not _has_trusted_edge_marker(headers) and not _dev_auth_bypass_enabled():
        return None

    data = json.loads(base64.b64decode(raw))
    claims = {c["typ"]: c["val"] for c in data.get("claims", [])}

    # Email: AAD uses the long XML claim name; Google/OIDC uses shorter forms.
    email = (
        claims.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
        or claims.get("emails")
        or claims.get("preferred_username")
        or claims.get("email")
        or ""
    ).lower()

    # Stable subject: AAD OID or OIDC sub.
    oid = (
        claims.get("http://schemas.microsoft.com/identity/claims/objectidentifier")
        or claims.get("sub")
        or ""
    )

    name = claims.get("name") or (email.split("@")[0] if email else "")

    return {"email": email, "oid": oid, "name": name}


def require_principal(headers: dict[str, str]) -> dict[str, str]:
    principal = parse_easy_auth_headers(headers)
    if not principal or not principal.get("email"):
        raise AuthError()
    return principal
