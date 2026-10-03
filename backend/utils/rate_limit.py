"""Small in-memory sliding-window rate limiter.

It only counts within one process, the same as the ThreadPoolExecutor
used for scans. That's enough for one server instance. Running several
instances would need a shared store such as Redis.
"""

from __future__ import annotations

import threading
import time


class RateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            attempts = [t for t in self._attempts.get(key, []) if now - t < self.window_seconds]
            self._attempts[key] = attempts
            return len(attempts) < self.max_attempts

    def record_attempt(self, key: str) -> None:
        with self._lock:
            self._attempts.setdefault(key, []).append(time.monotonic())
