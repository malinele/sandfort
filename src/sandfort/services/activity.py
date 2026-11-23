"""In-process sandbox activity tracker for the idle scanner.

``touch`` records the last activity instant but writes at most once per ``DEBOUNCE_S`` per
sandbox, so hot toolbox loops cost one dict lookup. State lives in process memory only; a
sandbox with no recorded activity reports the baseline taken when the tracker was built, so a
restart never counts idle time it cannot know about. Safe to call from threads and tasks.
"""

import threading
from datetime import datetime, timedelta

from sandfort.clock import Clock

DEBOUNCE_S = 5.0


class ActivityTracker:
    def __init__(self, clock: Clock, debounce_s: float = DEBOUNCE_S) -> None:
        self._clock = clock
        self._debounce = timedelta(seconds=debounce_s)
        self._baseline = clock.now()
        self._last: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def touch(self, sandbox_id: str) -> bool:
        """Record activity now; False when the debounce window swallowed the write."""
        now = self._clock.now()
        with self._lock:
            previous = self._last.get(sandbox_id)
            if previous is not None and now - previous < self._debounce:
                return False
            self._last[sandbox_id] = now
            return True

    def last_activity(self, sandbox_id: str) -> datetime:
        with self._lock:
            return self._last.get(sandbox_id, self._baseline)

    def forget(self, sandbox_id: str) -> None:
        with self._lock:
            self._last.pop(sandbox_id, None)
