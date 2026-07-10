from __future__ import annotations

from dataclasses import dataclass


@dataclass
class HttpResponse:
    status: int
    body: bytes | str
    headers: dict[str, str]
    mimetype: str | None = None
