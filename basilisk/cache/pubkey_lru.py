from __future__ import annotations

from collections import OrderedDict
from threading import Lock


class PubkeyLRU:
    def __init__(self, max_size: int = 1000) -> None:
        self._max = max(0, max_size)
        self._data: OrderedDict[str, bytes] = OrderedDict()
        self._lock = Lock()

    def get(self, sha256: str) -> bytes | None:
        if self._max == 0:
            return None
        with self._lock:
            if sha256 in self._data:
                self._data.move_to_end(sha256)
                return self._data[sha256]
        return None

    def put(self, sha256: str, data: bytes) -> None:
        if self._max == 0:
            return
        with self._lock:
            self._data[sha256] = data
            self._data.move_to_end(sha256)
            while len(self._data) > self._max:
                self._data.popitem(last=False)
