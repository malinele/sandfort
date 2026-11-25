"""Per-sandbox DNS pins: the vetted address set of a name, kept for a fixed window.

docs/egress-v2-design.md section 4.4. After a name has been resolved, vetted and reached, its
address set is pinned for the pair (sandbox, name) for ``window_s`` seconds. Inside the window
every CONNECT of that sandbox to that name uses the pinned set without a new query, so a
rebinding answer cannot alternate with a public one. Pins are per sandbox: one tenant cannot
tell from timing what another resolved. A sandbox holds at most ``MAX_PINS_PER_SANDBOX`` pins
and the proxy at most ``MAX_PINS_TOTAL``; both caps evict the least recently used pin.

A window of 0 turns pinning off (one resolution per CONNECT, the v1 behavior). Nothing here
logs: the queried names never reach a log line.

``recheck_sandbox`` has the signature of the policy client's change callback. It drops the pins
of names the sandbox's current policy no longer admits; it does not depend on the tunnel
registry, which ignores a sandbox with no open tunnel.
"""

import time
from collections import OrderedDict
from collections.abc import Callable
from typing import NamedTuple

from sandfort.egress.policy_client import PolicyEntry
from sandfort.egress.rules import EgressRules
from sandfort.webhooks.ssrf import IpAddress

MAX_PINS_PER_SANDBOX = 256
MAX_PINS_TOTAL = 65536

type PinKey = tuple[str, str]  # (sandbox id, name)


class _Pin(NamedTuple):
    expires_at: float
    addresses: tuple[IpAddress, ...]


def _fold(name: str) -> str:
    return name.lower().rstrip(".")


class PinStore:
    def __init__(
        self,
        window_s: float,
        clock: Callable[[], float] = time.monotonic,
        *,
        max_per_sandbox: int = MAX_PINS_PER_SANDBOX,
        max_total: int = MAX_PINS_TOTAL,
    ) -> None:
        self._window_s = window_s
        self._clock = clock
        self._max_per_sandbox = max_per_sandbox
        self._max_total = max_total
        self._pins: OrderedDict[PinKey, _Pin] = OrderedDict()  # least recently used first
        self._names: dict[str, OrderedDict[str, None]] = {}  # the same, per sandbox

    def __len__(self) -> int:
        return len(self._pins)

    def count(self, sandbox_id: str) -> int:
        return len(self._names.get(sandbox_id, ()))

    def get(self, sandbox_id: str, name: str) -> list[IpAddress] | None:
        """The live pinned set (a copy), or ``None``; an expired pin is forgotten here."""
        key = (sandbox_id, _fold(name))
        pin = self._pins.get(key)
        if pin is None:
            return None
        if self._clock() >= pin.expires_at:
            self._forget(key)
            return None
        self._pins.move_to_end(key)
        self._names[sandbox_id].move_to_end(key[1])
        return list(pin.addresses)

    def put(self, sandbox_id: str, name: str, addresses: list[IpAddress]) -> None:
        """Pin ``addresses`` for the window; a no-op when pinning is off or the set is empty."""
        if self._window_s <= 0 or not addresses:
            return
        key = (sandbox_id, _fold(name))
        self._forget(key)  # a replaced pin neither counts twice nor keeps its old position
        if self.count(sandbox_id) >= self._max_per_sandbox:
            self._forget((sandbox_id, next(iter(self._names[sandbox_id]))))
        if len(self._pins) >= self._max_total:
            self._forget(next(iter(self._pins)))
        self._pins[key] = _Pin(self._clock() + self._window_s, tuple(addresses))
        self._names.setdefault(sandbox_id, OrderedDict())[key[1]] = None

    def drop(self, sandbox_id: str, name: str) -> None:
        self._forget((sandbox_id, _fold(name)))

    def drop_sandbox(self, sandbox_id: str) -> None:
        for name in tuple(self._names.get(sandbox_id, ())):
            self._forget((sandbox_id, name))

    def recheck_sandbox(self, sandbox_id: str, entry: PolicyEntry) -> None:
        """Drop the pins of ``sandbox_id`` whose name ``entry`` no longer admits."""
        names = tuple(self._names.get(sandbox_id, ()))
        if not names:
            return
        if not entry.found:
            self.drop_sandbox(sandbox_id)
            return
        try:
            rules = EgressRules.from_entries(entry.rules)
        except ValueError:  # a policy that cannot be parsed admits nothing
            self.drop_sandbox(sandbox_id)
            return
        for name in names:
            if not rules.admits_name(name):
                self._forget((sandbox_id, name))

    def _forget(self, key: PinKey) -> None:
        if self._pins.pop(key, None) is None:
            return
        sandbox_id, name = key
        names = self._names[sandbox_id]
        del names[name]
        if not names:
            del self._names[sandbox_id]
