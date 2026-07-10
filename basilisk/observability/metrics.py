from __future__ import annotations

import threading

_lock = threading.Lock()
_counters: dict[str, int] = {
    "rejected_uploads": 0,
    "rate_limited": 0,
    "duplicate_uploads": 0,
}


def inc(name: str, n: int = 1) -> None:
    with _lock:
        _counters[name] = _counters.get(name, 0) + n


def snapshot() -> dict[str, int]:
    with _lock:
        return dict(_counters)


def reset() -> None:
    with _lock:
        for key in _counters:
            _counters[key] = 0
