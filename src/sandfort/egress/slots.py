"""The connection slots of the egress proxy: global, per sandbox and pre-authentication.

Each client connection takes a global slot and a pre-authentication slot for its source address
when it arrives, trades the second for nothing once it has authenticated, takes a per-sandbox
slot when a tunnel is wanted, and gives back whatever it still holds on every exit path.
"""

import asyncio

from sandfort.egress.admission import Seen
from sandfort.egress.proxy_limits import SlotTable
from sandfort.egress.relay import Deny, source_of

ALL_CONNECTIONS = ""  # the single key of the global slot table


class ConnectionSlots:
    def __init__(
        self, per_sandbox: int | None, total: int | None, preauth_per_source: int | None
    ) -> None:
        self._per_sandbox = SlotTable(per_sandbox)
        self._total = SlotTable(total)
        self._preauth = SlotTable(preauth_per_source)

    @property
    def open_connections(self) -> int:
        """Client connections currently holding a global slot."""
        return self._total.total

    def unauthenticated_from(self, source: str) -> int:
        """Connections from ``source`` that have not authenticated yet."""
        return self._preauth.held(source)

    def enter(self, writer: asyncio.StreamWriter, seen: Seen) -> None:
        """Take a global slot and a pre-authentication slot for the source, or refuse."""
        if not self._total.try_acquire(ALL_CONNECTIONS):
            raise Deny(503, "Service Unavailable", "global connection ceiling reached")
        seen.admitted = True
        source = source_of(writer)
        if not self._preauth.try_acquire(source):
            raise Deny(429, "Too Many Requests", "too many unauthenticated connections")
        seen.preauth_source = source

    def end_preauth(self, seen: Seen) -> None:
        if seen.preauth_source is not None:
            self._preauth.release(seen.preauth_source)
            seen.preauth_source = None

    def take(self, sandbox_id: str) -> None:
        if not self._per_sandbox.try_acquire(sandbox_id):
            raise Deny(429, "Too Many Requests", "too many concurrent connections for sandbox")

    def leave(self, seen: Seen) -> None:
        """Release every slot ``seen`` still holds."""
        self.end_preauth(seen)
        if seen.slot_held:
            self._per_sandbox.release(seen.sandbox_id)
            seen.slot_held = False
        if seen.admitted:
            self._total.release(ALL_CONNECTIONS)
            seen.admitted = False
