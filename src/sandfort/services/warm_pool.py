"""Warm pool of standby sandboxes (phase 8): repeated creates of one spec are claimed, not built.

Pooling is lazy and exact-match. A pool exists per org, snapshot and resource shape (the
``spec_hash``), and only for creates without custom env, volume mounts, an egress allowlist or a
standby marker. With ``Settings.warm_pool_size`` at zero (the default) ``try_claim`` returns at
once and nothing else in the system changes.

* ``try_claim`` is called by ``SandboxService.create`` for an eligible command. It runs one
  database-only unit of work: the atomic claim (``StandbyRepository.claim_standby``), an audit row
  naming the claim and the refill jobs that top the pool back up to the configured size. No
  driver call happens in that transaction.
* The ``warm_pool.refill`` job handler builds one standby through the ordinary service path
  (quota reservation, intent-then-act, driver outside any transaction) under an internal name.
  The handler re-counts first, so surplus jobs (several creates before a refill ran) do nothing.
* Standbys reserve quota like any sandbox, are hidden from user listings and carry
  ``auto_stop_minutes = -1`` so the idle scanner never stops them.

The claim goes through the undecorated sandbox repository: it changes no lifecycle state, so
the event and metering decorators (which only forward the lifecycle surface) are not involved.
"""

import hashlib
import json
import logging
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from sandfort.clock import Clock
from sandfort.config import Settings
from sandfort.db.repositories.ports import StandbyClaim, StandbyRepository, UnitOfWorkPort
from sandfort.domain.events import ActorType
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import NetworkPolicy, Sandbox
from sandfort.errors import CapacityExceeded, InternalError, QuotaExceeded
from sandfort.ids import new_sandbox_id
from sandfort.services.audit import AuditRecorder
from sandfort.services.sandboxes import CreateSandboxCommand
from sandfort.workers.handlers import JobContext, register
from sandfort.workers.jobs import DEFAULT_WAKEUP, enqueue_job

logger = logging.getLogger(__name__)

WARM_POOL_REFILL = "warm_pool.refill"
CLAIM_ACTION = "sandbox.claim"
STANDBY_NAME_PREFIX = "standby-"
NO_AUTO_TIMER = -1  # standbys are never auto-stopped or auto-deleted while they wait


class SandboxCreator(Protocol):
    """The part of ``SandboxService`` the refill builds standbys with."""

    async def create(
        self, org_id: str, actor_id: str, command: CreateSandboxCommand
    ) -> Sandbox: ...


def is_eligible(command: CreateSandboxCommand) -> bool:
    """Only a plain create (no env, mounts or egress allowlist, not a standby) can use the pool.

    A create with an allowlist, even an empty one, bypasses the pool entirely (no claim, no
    refill), the egress design's safest first step: a pooled sandbox built with other egress
    is never handed out, and the pool key needs no allowlist component.
    """
    return (
        not command.env
        and not command.volumes
        and not command.standby
        and command.egress_allowlist is None
    )


def compute_spec_hash(org_id: str, command: CreateSandboxCommand) -> str:
    """Pool key: org, snapshot, resource fields and the network block flag (64 hex chars).

    Everything a claim may still choose (name, labels, visibility, auto timers) and everything
    that makes a create ineligible (env, volumes, an egress allowlist) is deliberately left out.
    """
    material = {
        "org_id": org_id,
        "snapshot": command.snapshot,
        "cpu_millicores": command.resources.cpu_millicores,
        "memory_mib": command.resources.memory_mib,
        "disk_gib": command.resources.disk_gib,
        "block_all": command.network.block_all,
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _standby_repository(uow: UnitOfWorkPort) -> StandbyRepository:
    repository = uow.sandboxes
    if not isinstance(repository, StandbyRepository):
        raise InternalError("the warm pool needs the undecorated sandbox repository")
    return repository


def _standby_command(payload: Mapping[str, Any]) -> CreateSandboxCommand:
    snapshot = payload.get("snapshot")
    return CreateSandboxCommand(
        name=STANDBY_NAME_PREFIX + new_sandbox_id(),
        snapshot=None if snapshot is None else str(snapshot),
        resources=ResourceSpec.model_validate(payload["resources"]),
        network=NetworkPolicy(block_all=bool(payload["block_all"])),
        auto_stop_minutes=NO_AUTO_TIMER,
        auto_delete_minutes=NO_AUTO_TIMER,
        standby=True,
        spec_hash=str(payload["spec_hash"]),
    )


class WarmPool:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        settings: Settings,
        clock: Clock,
        audit: AuditRecorder | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._settings = settings
        self._clock = clock
        self._audit = audit or AuditRecorder(clock)
        self._creator: SandboxCreator | None = None

    @property
    def enabled(self) -> bool:
        return self._settings.warm_pool_size > 0

    def attach(self, creator: SandboxCreator) -> None:
        """Bind the service the refill builds with (it is built after the pool, which it holds)."""
        self._creator = creator

    async def try_claim(
        self, org_id: str, actor_id: str, command: CreateSandboxCommand
    ) -> Sandbox | None:
        """Claim a matching standby for ``command``; ``None`` means build it the normal way.

        Either way the pool is topped up afterwards by refill jobs enqueued in the same unit of
        work, so the first eligible create seeds the pool and every claim replaces its standby.
        """
        if not self.enabled or not is_eligible(command):
            return None
        key = compute_spec_hash(org_id, command)
        claim = StandbyClaim(
            name=command.name,
            labels=dict(command.labels),
            public=command.public,
            auto_stop_minutes=command.auto_stop_minutes,
            auto_delete_minutes=command.auto_delete_minutes,
            at=self._clock.now(),
        )
        async with self._uow_factory() as uow:
            repository = _standby_repository(uow)
            claimed = await repository.claim_standby(org_id, key, claim)
            if claimed is not None:
                await self._record_claim(uow, org_id, actor_id, claimed, key)
            missing = self._settings.warm_pool_size - await repository.count_standby(org_id, key)
            payload = self._refill_payload(org_id, actor_id, command, key)
            for _ in range(max(missing, 0)):
                await enqueue_job(uow, self._clock, org_id, WARM_POOL_REFILL, payload)
            await uow.commit()
        DEFAULT_WAKEUP.notify()
        return claimed

    async def refill_one(self, payload: Mapping[str, Any]) -> Sandbox | None:
        """Job body: build one standby unless the pool is already at its configured size."""
        if self._creator is None:
            raise InternalError("the warm pool has no sandbox service attached")
        org_id, key = str(payload["org_id"]), str(payload["spec_hash"])
        async with self._uow_factory() as uow:  # read-only; closed before any driver call
            present = await _standby_repository(uow).count_standby(org_id, key)
        if present >= self._settings.warm_pool_size:
            return None
        actor = payload.get("actor_id")
        try:
            return await self._creator.create(
                org_id, "" if actor is None else str(actor), _standby_command(payload)
            )
        except (QuotaExceeded, CapacityExceeded):  # no room: the pool stays smaller, no retry
            logger.info("warm pool refill skipped for org %s: no capacity", org_id)
            return None

    async def _record_claim(
        self, uow: UnitOfWorkPort, org_id: str, actor_id: str, sandbox: Sandbox, key: str
    ) -> None:
        await self._audit.record(
            uow,
            org_id=org_id,
            actor_type=ActorType.API_KEY,
            actor_id=actor_id,
            action=CLAIM_ACTION,
            target_type="sandbox",
            target_id=sandbox.id,
            details={"name": sandbox.name, "spec_hash": key},
        )

    @staticmethod
    def _refill_payload(
        org_id: str, actor_id: str, command: CreateSandboxCommand, key: str
    ) -> dict[str, Any]:
        return {
            "org_id": org_id,
            "actor_id": actor_id,
            "spec_hash": key,
            "snapshot": command.snapshot,
            "resources": command.resources.model_dump(mode="json"),
            "block_all": command.network.block_all,
        }


# The job runner calls handlers with a ``JobContext`` that carries neither settings nor the
# quota-aware service, so the wired pool is reached through this process-wide reference.
_ACTIVE: list[WarmPool] = []


def activate(pool: WarmPool) -> None:
    """Make ``pool`` the one the ``warm_pool.refill`` handler serves (the latest wins)."""
    _ACTIVE[:] = [pool]


@register(WARM_POOL_REFILL)
async def handle_refill(payload: Mapping[str, Any], context: JobContext) -> None:
    if not _ACTIVE:
        raise InternalError("no warm pool is active in this process")
    await _ACTIVE[0].refill_one(payload)
