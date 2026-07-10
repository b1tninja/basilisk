from __future__ import annotations


from basilisk.auth.errors import AuthError


def _header_value(headers: dict[str, str], name: str) -> str | None:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def parse_easy_auth_headers(headers: dict[str, str]) -> dict[str, str] | None:
    """Parse Azure Easy Auth client principal header."""
    import base64
    import json

    raw = _header_value(headers, "X-MS-CLIENT-PRINCIPAL")
    if not raw:
        return None
    data = json.loads(base64.b64decode(raw))
    claims = {c["typ"]: c["val"] for c in data.get("claims", [])}
    return {
        "email": claims.get(
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", ""
        ),
        "oid": claims.get("http://schemas.microsoft.com/identity/claims/objectidentifier", ""),
    }


def require_principal(headers: dict[str, str]) -> dict[str, str]:
    principal = parse_easy_auth_headers(headers)
    if not principal or not principal.get("email"):
        raise AuthError()
    return principal
