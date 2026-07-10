from __future__ import annotations


def parse_easy_auth_headers(headers: dict[str, str]) -> dict[str, str] | None:
    """Parse Azure Easy Auth client principal header."""
    import base64
    import json

    raw = headers.get("X-MS-CLIENT-PRINCIPAL") or headers.get("x-ms-client-principal")
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
