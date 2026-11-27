"""Rate-limited deny log line of the egress proxy.

A sandbox that loops on its connection cap (429) or on a denied host would write one warning per
attempt. ``DenyLog`` writes the first rejection per (sandbox, reason) and then at most one line
per key per ``interval_s``; that line ends with ``suppressed=<n>``, the number of rejections held
back since the previous line. The answer to the client is never throttled, only the log.

A reason is the http status plus the refusal detail with digits collapsed, so ``port 25 is not
allowed`` and ``port 26 is not allowed`` are one reason and a port scan stays one line per
interval. A deny under a different policy generation than the key's last written line is
logged at once, carrying the count held back under the old generation, so an operator checking
``gen=`` after a policy change sees the new generation without waiting out the interval. The
state is an LRU table of at most ``max_entries`` keys, so a flood of sandbox ids
cannot grow it; an evicted key logs again as a first rejection and loses its suppressed count.
``log`` has no await, so on the event loop each call is atomic and needs no lock.
"""

import logging
import re
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from sandfort.egress.relay import Deny

DENY_LOG_INTERVAL_S = 60.0
DENY_LOG_MAX_ENTRIES = 4096

_DIGITS = re.compile(r"\d+")

_log = logging.getLogger("sandfort.egress")

type Key = tuple[str, int, str]


@dataclass(slots=True)
class _Entry:
    last_logged: float
    gen: str
    suppressed: int = 0


def reason_of(deny: Deny) -> tuple[int, str]:
    """The throttle's notion of a reason: status and the detail up to a colon, digits collapsed."""
    head = deny.detail.partition(":")[0]
    return deny.status, _DIGITS.sub("#", head)


class DenyLog:
    def __init__(
        self,
        *,
        interval_s: float = DENY_LOG_INTERVAL_S,
        max_entries: int = DENY_LOG_MAX_ENTRIES,
        clock: Callable[[], float] = time.monotonic,
        logger: logging.Logger = _log,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self._interval_s = interval_s
        self._max_entries = max_entries
        self._clock = clock
        self._logger = logger
        self._entries: OrderedDict[Key, _Entry] = OrderedDict()

    @property
    def tracked(self) -> int:
        """Keys currently held (never more than ``max_entries``)."""
        return len(self._entries)

    def log(self, sandbox_id: str, deny: Deny, gen: str, host: Callable[[], str]) -> None:
        """Write the deny line unless this (sandbox, reason) logged one within the interval.

        ``host`` renders the logged host name and is only called for a line that is written.
        """
        suppressed = self._admit(sandbox_id, deny, gen)
        if suppressed is None:
            return
        tail = f" suppressed={suppressed}" if suppressed else ""
        self._logger.warning(
            "deny sandbox=%s host=%s status=%d reason=%s gen=%s%s",
            sandbox_id,
            host(),
            deny.status,
            deny.detail,
            gen,
            tail,
        )

    def _admit(self, sandbox_id: str, deny: Deny, gen: str) -> int | None:
        """``None`` to suppress, else how many rejections were held back before this one."""
        now = self._clock()
        key: Key = (sandbox_id, *reason_of(deny))
        entry = self._entries.get(key)
        if entry is None:
            self._entries[key] = _Entry(now, gen)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)
            return 0
        self._entries.move_to_end(key)
        if entry.gen == gen and now - entry.last_logged < self._interval_s:
            entry.suppressed += 1
            return None
        held_back = entry.suppressed
        entry.last_logged = now
        entry.gen = gen
        entry.suppressed = 0
        return held_back
