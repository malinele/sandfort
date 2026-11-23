"""Interactive terminals: persisted pty session rows, live driver handles and connect tokens.

``create_pty`` guards the sandbox, audits and persists an ``open`` row in one short unit of
work, closes it, and only then asks the driver for a tty exec running the default shell (bash
when the image has it, else ``sh``). The live handle is kept in the process-wide
``PtyRegistry`` keyed by pty id, and a single-use connect token bound to (org, sandbox, pty)
authorizes exactly one websocket bridge. Teardown (explicit close, the bridge ending, or the
sandbox stopping) removes the handle, closes the driver terminal and marks the row ``closed``;
it is idempotent. Audit rows carry ids and sizes only, never terminal content.

Each org holds at most ``max_per_org`` live terminals per process. Create and connect first
reap the terminals no token can attach any more (expired, or spent on a refused connect).
"""

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Protocol, runtime_checkable

import anyio

from sandfort.auth.connect_tokens import (
    ConnectTokenInvalid,
    ConnectTokenStore,
    PendingConnectTokens,
)
from sandfort.auth.principal import Principal
from sandfort.clock import Clock
from sandfort.db.models.pty import PtySessionState
from sandfort.db.repositories.ports import (
    PtySessionRecord,
    PtySessionRepository,
    UnitOfWorkPort,
)
from sandfort.domain.events import ActorType
from sandfort.domain.sandbox import Sandbox, visible_stop_cause
from sandfort.drivers.base import PtySessionDriver, PtySessionHandle, SandboxDriver
from sandfort.drivers.errors import DriverUnsupported
from sandfort.errors import (
    CLOSED,
    DEFAULT_CAPACITY_RETRY_AFTER_S,
    CapacityExceeded,
    Conflict,
    NotFound,
    no_container_conflict,
)
from sandfort.ids import JOB, new_id
from sandfort.toolbox import process
from sandfort.toolbox.guards import load_started_sandbox

logger = logging.getLogger(__name__)

# A terminal slot frees only when a terminal closes, so a 5 s retry would just re-hit the cap.
TERMINAL_CAP_RETRY_AFTER_S = 30

PTY_PREFIX = "pty"
DEFAULT_SHELL_ARGV = (
    "/bin/sh",
    "-c",
    "if [ -x /bin/bash ]; then exec /bin/bash; fi; exec /bin/sh",
)
WEBSOCKET_PATH_TEMPLATE = "/v1/sandboxes/{sandbox_id}/toolbox/pty/{pty_id}/connect"


class PtyUnitOfWork(UnitOfWorkPort, Protocol):
    """The unit of work plus the pty session repository (``db.unit_of_work.UnitOfWork``)."""

    pty_sessions: PtySessionRepository


type PtyUowFactory = Callable[[], PtyUnitOfWork]


@runtime_checkable
class PtyExitCodeDriver(Protocol):
    """Optional driver capability: the exit code of the process a terminal ran."""

    async def pty_exit_code(self, handle: PtySessionHandle) -> int | None:
        """The exit code; ``None`` while the process still runs or when it is unknown."""
        ...


class AuditSink(Protocol):
    """The slice of ``services.audit.AuditRecorder`` used here (toolbox never imports services)."""

    async def record(
        self,
        uow: UnitOfWorkPort,
        *,
        org_id: str,
        actor_type: ActorType,
        actor_id: str | None,
        action: str,
        target_type: str | None = None,
        target_id: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> object: ...


def new_pty_id() -> str:
    """Time-sortable ``pty_`` id (the shared id module has no such prefix)."""
    return f"{PTY_PREFIX}_{new_id(JOB).partition('_')[2]}"


def websocket_path(sandbox_id: str, pty_id: str) -> str:
    return WEBSOCKET_PATH_TEMPLATE.format(sandbox_id=sandbox_id, pty_id=pty_id)


@dataclass(frozen=True, slots=True)
class LivePty:
    org_id: str
    sandbox_id: str
    pty_id: str
    handle: PtySessionHandle
    connected: bool = False  # a websocket bridge redeemed the token; never reaped


@dataclass(frozen=True, slots=True)
class PtyConnect:
    """A freshly created terminal and the single-use token that authorizes its websocket."""

    record: PtySessionRecord
    token: str
    websocket_path: str


class OrgSlots:
    """Per-org admission slots keyed by resource id; a cap of 0 admits any number."""

    def __init__(
        self,
        cap: int,
        resource: str,
        *,
        frees_when: str | None = None,
        retry_after_s: int = DEFAULT_CAPACITY_RETRY_AFTER_S,
    ) -> None:
        self._cap = cap
        self._resource = resource
        self._frees_when = frees_when  # said in the error: when a slot becomes free again
        self._retry_after_s = retry_after_s
        self._owners: dict[str, str] = {}  # resource id -> org id

    def hold(self, org_id: str, key: str) -> None:
        """Take a slot for ``key`` (idempotent); ``CapacityExceeded`` when the org is full."""
        held = sum(1 for owner in self._owners.values() if owner == org_id)
        if key not in self._owners and 0 < self._cap <= held:
            hint = f"; a slot frees when {self._frees_when}" if self._frees_when else ""
            raise CapacityExceeded(
                f"the org already has {self._cap} {self._resource}{hint}",
                retry_after_s=self._retry_after_s,
                details={"resource": self._resource, "limit": self._cap},
            )
        self._owners[key] = org_id

    def release(self, key: str) -> None:
        self._owners.pop(key, None)


class PtyRegistry:
    """Process-wide live terminals by pty id; each holds an org slot from reserve/add to pop."""

    def __init__(self, max_per_org: int = 0) -> None:
        self._live: dict[str, LivePty] = {}
        self._slots = OrgSlots(
            max_per_org,
            "live terminals",
            frees_when="a terminal closes",
            retry_after_s=TERMINAL_CAP_RETRY_AFTER_S,
        )

    def __len__(self) -> int:
        return len(self._live)

    def reserve(self, org_id: str, pty_id: str) -> None:
        self._slots.hold(org_id, pty_id)

    def add(self, live: LivePty) -> None:
        self._slots.hold(live.org_id, live.pty_id)
        self._live[live.pty_id] = live

    def get(self, pty_id: str) -> LivePty | None:
        return self._live.get(pty_id)

    def pop(self, pty_id: str) -> LivePty | None:
        self._slots.release(pty_id)
        return self._live.pop(pty_id, None)

    def mark_connected(self, live: LivePty) -> LivePty:
        connected = replace(live, connected=True)
        self._live[live.pty_id] = connected
        return connected

    def unconnected(self) -> list[LivePty]:
        return [live for live in self._live.values() if not live.connected]

    def for_sandbox(self, org_id: str, sandbox_id: str) -> list[LivePty]:
        return [
            live
            for live in self._live.values()
            if live.org_id == org_id and live.sandbox_id == sandbox_id
        ]


class PtyService:
    def __init__(
        self,
        uow_factory: PtyUowFactory,
        driver: SandboxDriver,
        recorder: AuditSink,
        clock: Clock,
        registry: PtyRegistry,
        tokens: ConnectTokenStore,
    ) -> None:
        self._uow_factory = uow_factory
        self._driver = driver
        self._recorder = recorder
        self._clock = clock
        self._registry = registry
        self._tokens = tokens

    # -- commands -----------------------------------------------------------------

    async def create_pty(
        self,
        principal: Principal,
        sandbox_id: str,
        *,
        rows: int,
        cols: int,
        argv: Sequence[str] | None = None,
        env: Mapping[str, str] | None = None,
    ) -> PtyConnect:
        environment = dict(env or {})
        process.validate_env(environment)
        driver = self._pty_driver()
        await self._reap_unconnected()  # stale terminals give their slots back first
        org_id, pty_id = principal.org_id, new_pty_id()
        self._registry.reserve(org_id, pty_id)  # at the cap: refused before any row or audit
        try:
            row, sandbox = await self._open_row(
                principal, sandbox_id, pty_id, rows, cols, environment
            )
            command = list(argv) if argv else list(DEFAULT_SHELL_ARGV)
            try:
                if sandbox.driver_ref is None:
                    raise no_container_conflict(sandbox.state.value, visible_stop_cause(sandbox))
                handle = await driver.create_pty(
                    sandbox.driver_ref, command, environment, rows, cols
                )
            except BaseException:
                with anyio.CancelScope(shield=True):
                    await self._close_row(org_id, pty_id)
                raise
        except BaseException:
            self._registry.pop(pty_id)  # give the reserved slot back
            raise
        try:  # minted before it is registered, so a reap never finds it without a token
            token = await self._tokens.mint(org_id, sandbox_id, pty_id)
        finally:  # registered even when minting fails: the next reap then tears it down
            self._registry.add(LivePty(org_id, sandbox_id, pty_id, handle))
        path = websocket_path(sandbox_id, pty_id)
        return PtyConnect(record=row, token=token, websocket_path=path)

    async def resize(
        self, principal: Principal, sandbox_id: str, pty_id: str, rows: int, cols: int
    ) -> PtySessionRecord:
        async with self._uow_factory() as uow:
            await load_started_sandbox(uow, principal.org_id, sandbox_id, self._clock)
            record = await self._pty_in(uow, principal.org_id, sandbox_id, pty_id)
            live = self._registry.get(pty_id)
            if record.state != PtySessionState.OPEN.value or live is None:
                raise Conflict(
                    "pty is closed",
                    reason=CLOSED,
                    details={"state": PtySessionState.CLOSED.value},
                )
            details = {"pty_id": pty_id, "rows": rows, "cols": cols}
            await self._audit(uow, principal, sandbox_id, "toolbox.pty.resize", details)
            await uow.commit()
        await self._pty_driver().resize_pty(live.handle, rows, cols)
        async with self._uow_factory() as uow:
            updated = await uow.pty_sessions.resize(principal.org_id, pty_id, rows, cols)
            await uow.commit()
        return updated or record

    async def close(self, principal: Principal, sandbox_id: str, pty_id: str) -> PtySessionRecord:
        async with self._uow_factory() as uow:
            if await uow.sandboxes.get(principal.org_id, sandbox_id) is None:
                raise NotFound(f"sandbox {sandbox_id} not found")
            record = await self._pty_in(uow, principal.org_id, sandbox_id, pty_id)
            await self._audit(uow, principal, sandbox_id, "toolbox.pty.close", {"pty_id": pty_id})
            await uow.commit()
        return await self._teardown(principal.org_id, pty_id) or record

    async def close_sandbox(self, org_id: str, sandbox_id: str) -> None:
        """Tear down the sandbox's live terminals and close rows left open (best effort)."""
        try:
            for live in self._registry.for_sandbox(org_id, sandbox_id):
                await self._teardown(org_id, live.pty_id)
            async with self._uow_factory() as uow:
                for record in await uow.pty_sessions.list_for_sandbox(org_id, sandbox_id):
                    if record.state == PtySessionState.OPEN.value:
                        await uow.pty_sessions.close(org_id, record.id, self._clock.now())
                await uow.commit()
        except Exception:
            logger.exception("could not close the terminals of sandbox %s", sandbox_id)

    # -- queries ------------------------------------------------------------------

    async def list_ptys(self, org_id: str, sandbox_id: str) -> list[PtySessionRecord]:
        async with self._uow_factory() as uow:
            if await uow.sandboxes.get(org_id, sandbox_id) is None:
                raise NotFound(f"sandbox {sandbox_id} not found")
            return list(await uow.pty_sessions.list_for_sandbox(org_id, sandbox_id))

    async def get_pty(self, org_id: str, sandbox_id: str, pty_id: str) -> PtySessionRecord:
        async with self._uow_factory() as uow:
            return await self._pty_in(uow, org_id, sandbox_id, pty_id)

    # -- websocket bridge ---------------------------------------------------------

    async def connect(self, token: str, sandbox_id: str, pty_id: str) -> LivePty:
        """Redeem ``token`` once for the live terminal it grants, else ``ConnectTokenInvalid``."""
        await self._reap_unconnected()
        grant = await self._tokens.redeem(token)
        live = self._registry.get(grant.pty_id)
        matches = (grant.sandbox_id, grant.pty_id) == (sandbox_id, pty_id)
        if not matches or live is None or live.org_id != grant.org_id:
            raise ConnectTokenInvalid("connect token does not grant a live terminal here")
        return self._registry.mark_connected(live)

    async def read(self, live: LivePty) -> bytes:
        return await self._pty_driver().read_pty(live.handle)

    async def write(self, live: LivePty, data: bytes) -> None:
        await self._pty_driver().write_pty(live.handle, data)

    @property
    def reports_exit_codes(self) -> bool:
        """Whether the driver can tell the exit code of a terminal's process."""
        return isinstance(self._driver, PtyExitCodeDriver)

    async def exit_code(self, live: LivePty) -> int | None:
        """The terminal process's exit code if the driver reports it, else ``None``.

        Read it before ``finish``: tearing the terminal down drops the driver's handle.
        """
        if not isinstance(self._driver, PtyExitCodeDriver):
            return None
        try:
            return await self._driver.pty_exit_code(live.handle)
        except Exception:
            logger.warning("could not read the exit code of pty %s", live.pty_id, exc_info=True)
            return None

    async def finish(self, live: LivePty) -> None:
        """The bridge ended (process exit or client gone): tear the terminal down."""
        await self._teardown(live.org_id, live.pty_id)

    # -- internals ----------------------------------------------------------------

    def _pty_driver(self) -> PtySessionDriver:
        if not isinstance(self._driver, PtySessionDriver):
            raise DriverUnsupported("the driver does not support interactive terminals")
        return self._driver

    async def _open_row(
        self,
        principal: Principal,
        sandbox_id: str,
        pty_id: str,
        rows: int,
        cols: int,
        environment: Mapping[str, str],
    ) -> tuple[PtySessionRecord, Sandbox]:
        """Guard the sandbox, audit and persist the ``open`` row; return it and the sandbox."""
        async with self._uow_factory() as uow:
            sandbox = await load_started_sandbox(uow, principal.org_id, sandbox_id, self._clock)
            details = {"pty_id": pty_id, "rows": rows, "cols": cols, "env": dict(environment)}
            await self._audit(uow, principal, sandbox_id, "toolbox.pty.create", details)
            record = PtySessionRecord(
                id=pty_id,
                org_id=principal.org_id,
                sandbox_id=sandbox_id,
                state=PtySessionState.OPEN.value,
                rows=rows,
                cols=cols,
                created_at=self._clock.now(),
                closed_at=None,
            )
            await uow.pty_sessions.add(record)
            await uow.commit()
        return record, sandbox

    async def _reap_unconnected(self) -> None:
        """Tear down terminals no token can attach any more, like a sandbox stop (best effort)."""
        if not isinstance(self._tokens, PendingConnectTokens):
            return
        try:  # listed before the pending read, so a later terminal never meets an older set
            candidates = self._registry.unconnected()
            pending = await self._tokens.pending_pty_ids()
            for stale in candidates:
                current = self._registry.get(stale.pty_id)
                if current is None or current.connected or stale.pty_id in pending:
                    continue
                logger.info("reaping pty %s: never connected, no live token", stale.pty_id)
                await self._teardown(stale.org_id, stale.pty_id)
        except Exception:
            logger.exception("could not reap unconnected terminals")

    async def _teardown(self, org_id: str, pty_id: str) -> PtySessionRecord | None:
        record: PtySessionRecord | None = None
        with anyio.CancelScope(shield=True):
            live = self._registry.pop(pty_id)
            if live is not None:
                try:
                    await self._pty_driver().close_pty(live.handle)
                except Exception:
                    logger.warning("could not close pty %s", pty_id, exc_info=True)
            record = await self._close_row(org_id, pty_id)
        return record

    async def _close_row(self, org_id: str, pty_id: str) -> PtySessionRecord | None:
        try:
            async with self._uow_factory() as uow:
                record = await uow.pty_sessions.close(org_id, pty_id, self._clock.now())
                await uow.commit()
        except Exception:
            logger.exception("could not mark pty %s closed", pty_id)
            return None
        return record

    async def _audit(
        self,
        uow: UnitOfWorkPort,
        principal: Principal,
        sandbox_id: str,
        action: str,
        details: Mapping[str, object],
    ) -> None:
        await self._recorder.record(
            uow,
            org_id=principal.org_id,
            actor_type=ActorType.API_KEY,
            actor_id=principal.key_id,
            action=action,
            target_type="sandbox",
            target_id=sandbox_id,
            details=details,
        )

    @staticmethod
    async def _pty_in(
        uow: PtyUnitOfWork, org_id: str, sandbox_id: str, pty_id: str
    ) -> PtySessionRecord:
        record = await uow.pty_sessions.get(org_id, pty_id)
        if record is None or record.sandbox_id != sandbox_id:
            raise NotFound(f"pty {pty_id} not found")
        return record
