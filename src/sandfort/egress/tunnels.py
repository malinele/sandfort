"""Registry of open egress tunnels and the sweep that closes the ones a policy no longer admits.

Every admitted tunnel is registered with the sandbox, the target form (name or IP literal), the
connected address, the policy generation it was admitted under, the token version and epoch,
and the task that handles the connection (docs/egress-v2-design.md section 5.4).
``recheck_sandbox`` runs when a policy entry changes and again for each sweep result: it
cancels the task of every tunnel the current entry no longer admits. The cancelled task's
``finally`` path in ``EgressProxy.handle`` releases the slots and closes both sides, so the
client sees a reset connection. The address vetting done at admission is not repeated: the
denied networks do not change while the process runs.

``sweep_once`` refreshes the policy of every sandbox that has tunnels (batch lookups through
the ``PolicyClient``, whose change callback runs the re-check) and then cancels every tunnel
of a sandbox whose last successful refresh is older than the client's ``max_stale_s``.
"""

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

from sandfort.egress.policy_client import PolicyClient, PolicyEntry
from sandfort.egress.rules import EgressRules, target_address
from sandfort.webhooks.ssrf import IpAddress

_log = logging.getLogger("sandfort.egress")


@dataclass(frozen=True, eq=False, slots=True)
class TunnelRecord:
    """One open tunnel. ``host`` keeps the target form; ``address`` is the connected address."""

    sandbox_id: str
    host: str
    address: IpAddress
    port: int
    generation: int
    token_version: int
    epoch: int | None
    task: asyncio.Task[None]


def _admitted(record: TunnelRecord, entry: PolicyEntry, rules: EgressRules) -> bool:
    if record.token_version == 2 and record.epoch != entry.epoch:
        return False
    if record.token_version == 1 and entry.generation >= 1:
        return False
    if target_address(record.host) is not None:  # an IP-literal target: CIDR rules only
        return rules.admits_address(record.address)
    return rules.admits_name(record.host)


class TunnelRegistry:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._by_sandbox: dict[str, list[TunnelRecord]] = {}

    def register(self, record: TunnelRecord) -> TunnelRecord:
        self._by_sandbox.setdefault(record.sandbox_id, []).append(record)
        return record

    def unregister(self, record: TunnelRecord) -> None:
        records = self._by_sandbox.get(record.sandbox_id)
        if records is None or record not in records:
            return
        records.remove(record)
        if not records:
            del self._by_sandbox[record.sandbox_id]

    def tunnels_of(self, sandbox_id: str) -> tuple[TunnelRecord, ...]:
        return tuple(self._by_sandbox.get(sandbox_id, ()))

    def sandbox_ids_with_tunnels(self) -> tuple[str, ...]:
        return tuple(self._by_sandbox)

    def has_tunnels(self, sandbox_id: str) -> bool:
        return sandbox_id in self._by_sandbox

    def recheck_sandbox(self, sandbox_id: str, entry: PolicyEntry) -> None:
        """Cancel every tunnel of ``sandbox_id`` that ``entry`` no longer admits."""
        records = self.tunnels_of(sandbox_id)
        if not records:
            return
        if not entry.found:
            self._cancel(records, "no policy for sandbox")
            return
        try:
            rules = EgressRules.from_entries(entry.rules)
        except ValueError:  # a policy that cannot be parsed admits nothing
            self._cancel(records, "unparsable policy")
            return
        self._cancel([r for r in records if not _admitted(r, entry, rules)], "policy changed")

    async def sweep_once(self, client: PolicyClient) -> None:
        """Refresh every sandbox with tunnels, then close those that stayed stale too long."""
        sandbox_ids = self.sandbox_ids_with_tunnels()
        if not sandbox_ids:
            return
        try:
            await client.refresh_many(sandbox_ids)
        finally:  # clause 4 holds even when the refresh itself raised
            now = self._clock()
            for sandbox_id in self.sandbox_ids_with_tunnels():
                last = client.last_success_at(sandbox_id)
                if last is None or now - last > client.max_stale_s:
                    self._cancel(self.tunnels_of(sandbox_id), "policy not refreshed")

    @staticmethod
    def _cancel(records: "list[TunnelRecord] | tuple[TunnelRecord, ...]", reason: str) -> None:
        for record in records:
            _log.info(
                "close sandbox=%s host=%r port=%d reason=%s",
                record.sandbox_id,
                record.host,
                record.port,
                reason,
            )
            record.task.cancel()


async def sweep_while_serving(
    registry: TunnelRegistry, client: PolicyClient, serving: Callable[[], bool]
) -> None:
    """Sweep every cache interval until ``serving`` turns false; a failed sweep is logged.

    The period is the cache interval measured start to start: a sweep's own duration is
    taken off the next sleep.
    """
    loop = asyncio.get_running_loop()
    wait = client.cache_s
    while serving():
        await asyncio.sleep(wait)
        if not serving():
            return
        started = loop.time()
        try:
            await registry.sweep_once(client)
        except Exception:
            _log.exception("egress sweep failed")
        wait = max(0.0, client.cache_s - (loop.time() - started))


async def stop_sweeper(sweeper: "asyncio.Task[None] | None", client: PolicyClient | None) -> None:
    """Teardown: cancel the sweeper task (if any), then close the policy client (if any)."""
    if sweeper is not None:
        sweeper.cancel()
        await asyncio.gather(sweeper, return_exceptions=True)
    if client is not None:
        await client.aclose()
