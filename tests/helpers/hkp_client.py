from __future__ import annotations

import httpx


def lookup_get(client: httpx.Client, search: str) -> httpx.Response:
    return client.get("/pks/lookup", params={"op": "get", "search": search})


def dev_approve(client: httpx.Client, fingerprint: str, uids: list[str]) -> httpx.Response:
    return client.post(
        "/api/v1/dev/approve",
        json={"fingerprint": fingerprint, "approved_uids": uids},
    )
