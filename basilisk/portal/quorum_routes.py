"""Quorum signaling mailbox API — opaque ciphertext relay only."""

from __future__ import annotations

import json
import logging
import re

from flask import Flask, Response, request

from basilisk.portal.quorum_store import (
    MAX_PAYLOAD_BYTES,
    ROOM_ID_RE,
    get_quorum_store,
)
from basilisk.security.rate_limit import (
    RateLimitError,
    check_upload_rate,
    client_ip,
    get_limiter,
)

logger = logging.getLogger(__name__)


def check_quorum_rate(ip: str, room_id: str) -> None:
    limiter = get_limiter()
    # ~1 post / 0.5s per IP; ~1 post / 0.25s per room
    if not limiter.allow(f"quorum:ip:{ip}", 0.5):
        raise RateLimitError("Quorum rate limit exceeded for this IP")
    if not limiter.allow(f"quorum:room:{room_id}", 0.25):
        raise RateLimitError("Quorum rate limit exceeded for this room")


def register_quorum_api(app: Flask) -> None:
    @app.post("/api/v1/quorum/room/<room_id>/messages")
    def quorum_post(room_id: str) -> Response:
        if not re.fullmatch(ROOM_ID_RE, room_id.strip().upper()):
            return Response(
                json.dumps({"error": "Invalid room id"}),
                status=400,
                mimetype="application/json",
            )
        ip = client_ip(dict(request.headers), request.remote_addr)
        try:
            check_upload_rate(ip)
            check_quorum_rate(ip, room_id.strip().upper())
        except RateLimitError as exc:
            return Response(
                json.dumps({"error": str(exc)}),
                status=exc.status,
                mimetype="application/json",
            )

        body = request.get_json(silent=True) or {}
        payload = body.get("payload") or body.get("message") or ""
        if not payload and request.data:
            text = request.get_data(as_text=True) or ""
            if "BEGIN PGP" in text or text.strip():
                payload = text
        if not isinstance(payload, str) or not payload.strip():
            return Response(
                json.dumps({"error": "Missing payload"}),
                status=400,
                mimetype="application/json",
            )
        if len(payload.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            return Response(
                json.dumps({"error": f"Payload exceeds {MAX_PAYLOAD_BYTES} bytes"}),
                status=413,
                mimetype="application/json",
            )
        try:
            result = get_quorum_store().post(room_id, payload.strip())
        except ValueError as exc:
            return Response(
                json.dumps({"error": str(exc)}),
                status=413,
                mimetype="application/json",
            )
        except RuntimeError as exc:
            return Response(
                json.dumps({"error": str(exc)}),
                status=429,
                mimetype="application/json",
            )
        return Response(json.dumps(result), mimetype="application/json")

    @app.get("/api/v1/quorum/room/<room_id>/messages")
    def quorum_poll(room_id: str) -> Response:
        if not re.fullmatch(ROOM_ID_RE, room_id.strip().upper()):
            return Response(
                json.dumps({"error": "Invalid room id"}),
                status=400,
                mimetype="application/json",
            )
        ip = client_ip(dict(request.headers), request.remote_addr)
        try:
            from basilisk.security.rate_limit import check_lookup_rate

            check_lookup_rate(ip)
        except RateLimitError as exc:
            return Response(
                json.dumps({"error": str(exc)}),
                status=exc.status,
                mimetype="application/json",
            )
        try:
            since = int(request.args.get("since") or "0")
        except ValueError:
            since = 0
        if since < 0:
            since = 0
        result = get_quorum_store().poll(room_id, since)
        return Response(json.dumps(result), mimetype="application/json")
