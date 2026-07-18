"""In-memory ephemeral signaling mailbox for Quorum WebRTC rooms."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


MAX_ROOMS = 256
MAX_MESSAGES_PER_ROOM = 200
MAX_PAYLOAD_BYTES = 32 * 1024
ROOM_TTL_SEC = 30 * 60
ROOM_ID_RE = r"^[A-Z2-7]{8,32}$"


@dataclass
class MailboxMessage:
    seq: int
    payload: str
    created_at: float


@dataclass
class RoomMailbox:
    room_id: str
    messages: list[MailboxMessage] = field(default_factory=list)
    next_seq: int = 1
    last_activity: float = field(default_factory=time.time)


class QuorumMailboxStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rooms: dict[str, RoomMailbox] = {}

    def _sweep_locked(self, now: float) -> None:
        stale = [
            rid
            for rid, room in self._rooms.items()
            if (now - room.last_activity) > ROOM_TTL_SEC
        ]
        for rid in stale:
            del self._rooms[rid]

    def post(self, room_id: str, payload: str) -> dict:
        rid = room_id.strip().upper()
        if len(payload.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError(f"Payload exceeds {MAX_PAYLOAD_BYTES} bytes")
        now = time.time()
        with self._lock:
            self._sweep_locked(now)
            room = self._rooms.get(rid)
            if room is None:
                if len(self._rooms) >= MAX_ROOMS:
                    raise RuntimeError("Too many active quorum rooms")
                room = RoomMailbox(room_id=rid)
                self._rooms[rid] = room
            if len(room.messages) >= MAX_MESSAGES_PER_ROOM:
                raise RuntimeError("Room message limit reached")
            msg = MailboxMessage(seq=room.next_seq, payload=payload, created_at=now)
            room.next_seq += 1
            room.messages.append(msg)
            room.last_activity = now
            return {"seq": msg.seq, "room_id": rid}

    def poll(self, room_id: str, since: int = 0) -> dict:
        rid = room_id.strip().upper()
        now = time.time()
        with self._lock:
            self._sweep_locked(now)
            room = self._rooms.get(rid)
            if room is None:
                return {"room_id": rid, "messages": [], "next_since": since}
            room.last_activity = now
            msgs = [
                {"seq": m.seq, "payload": m.payload}
                for m in room.messages
                if m.seq > since
            ]
            next_since = msgs[-1]["seq"] if msgs else since
            return {"room_id": rid, "messages": msgs, "next_since": next_since}

    def room_count(self) -> int:
        with self._lock:
            return len(self._rooms)


_store = QuorumMailboxStore()


def get_quorum_store() -> QuorumMailboxStore:
    return _store


def reset_quorum_store() -> None:
    global _store
    _store = QuorumMailboxStore()
