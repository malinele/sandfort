"""Sandbox reset: a fresh container for the same sandbox (same id, name, labels and spec).

A reset removes the sandbox's container and creates a new one from the same image reference
(the row's ``image_ref``, i.e. its snapshot) and the same driver spec the sandbox was created
with: resources, env, network policy and egress marker, isolation tier and volume mounts (with
their read-only flag). An allowlisted sandbox's egress token is minted again first
(``Lifecycle.refresh_egress``, its own unit of work), so the new container gets a fresh token. The
row keeps its id, name, labels, auto timers and quota reservation. Everything written to the old
container is gone; named volumes are separate objects and are kept.

Allowed from ``started`` (the new container is started, the sandbox ends ``started``) and from
``stopped`` (the new container is created but not started, the sandbox ends ``stopped``; the next
start adopts it). Any other state answers 409 ``InvalidState``.

The lifecycle table has no ``started -> started`` move, so a reset does not change the state: the
state-keyed side effects (lifecycle events, usage intervals, quota release and re-reserve) do not
run, and the sandbox is metered as one continuous run. Intent first, then act (architecture D4):
the audit row ``sandbox.reset`` is committed with the intent in its own unit of work, the driver
is called with no transaction open, and a fresh unit of work records a changed container ref.

Jobs mode (``use_jobs``) is NOT supported: there is no reset job kind, and running the driver
calls inline there would bypass the node placement the job runner honours. A reset in jobs mode
is refused with 409 and a message that says so.

Concurrency and failure. The new ref is saved right after the container is created and before it
is started, so a failed start leaves the row pointing at the created container and delete removes
it. If the row is no longer in the state the intent saw when the ref is saved (a concurrent stop or
delete finished), the new container is destroyed and the caller gets 409 ``Conflict`` naming the
new state. ``refuse_if_busy`` runs again right before the old container is destroyed, so a snapshot
that began after the intent is not cut off. The intent's audit details carry ``state`` and
``previous_driver_ref`` (the container the reset is about to remove, null when the row had none).
The reconciler leaves a started row alone for ``RESET_SETTLE_S`` after the intent while the row
still points at ``previous_driver_ref``; once the row points at the new container, a drift or a
death on it is settled at once.

If the driver fails after the old container was removed (create or start), the failure is
recorded and the error reaches the caller: the row moves to ``error`` with the tenant-safe failure
reason (``failure_reason``; a registry refusal never carries the daemon text) as
``error_reason`` and ``error_code`` ``reset_failed`` (through ``Lifecycle.record_failure`` where
the transition table allows it; the table has no ``started`` or ``stopped`` to ``error`` edge, so
for those two states the move is written directly, guarded by the row version, like the
reconciler's drift repair), and an audit row ``sandbox.reset_failed`` carries the same reason. The
row then leads to ``destroying`` like every other failed sandbox: delete it. A failure while
recording the failure is logged and never hides the driver error.
"""

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.sandbox import ERROR_RESET_FAILED, Sandbox, SandboxState
from sandfort.drivers.base import SandboxDriver
from sandfort.drivers.errors import DriverError, DriverNotFound
from sandfort.errors import (
    CHANGED_DURING_RESET,
    CONCURRENT_UPDATE,
    UNSUPPORTED_MODE,
    Conflict,
    InvalidState,
)
from sandfort.services.sandbox_jobs import (
    MAX_ERROR_REASON_CHARS,
    AuditNote,
    Lifecycle,
    failure_reason,
)

logger = logging.getLogger(__name__)

SANDBOX_RESET = "sandbox.reset"
SANDBOX_RESET_FAILED = "sandbox.reset_failed"
RESET_TARGET = "reset"  # the "target" in the InvalidState message, beside real states
RECORD_REF_ATTEMPTS = 3  # tries to save the new ref against concurrent row writers

_S = SandboxState
_RESETTABLE = frozenset({_S.STARTED, _S.STOPPED})


class SandboxReset:
    def __init__(
        self,
        core: Lifecycle,
        uow_factory: Callable[[], UnitOfWorkPort],
        driver: SandboxDriver,
        clock: Clock,
        *,
        use_jobs: bool,
        refuse_if_busy: Callable[[str, str], Awaitable[None]],
        on_replaced: Callable[[str, str], Awaitable[None]] | None = None,
    ) -> None:
        """``refuse_if_busy(org_id, sandbox_id)`` raises while a snapshot commit needs the old
        container; ``on_replaced(org_id, sandbox_id)`` drops state bound to it (open PTYs)."""
        self._core = core
        self._uow_factory = uow_factory
        self._driver = driver
        self._clock = clock
        self._use_jobs = use_jobs
        self._refuse_if_busy = refuse_if_busy
        self._on_replaced = on_replaced

    async def reset(self, org_id: str, actor_id: str, sandbox_id: str) -> Sandbox:
        current = await self._core.load(org_id, sandbox_id)  # 404 first, scope included
        if self._use_jobs:
            raise Conflict(
                "sandbox reset is not supported when sandbox lifecycle runs as jobs; "
                "delete the sandbox and create a new one instead",
                reason=UNSUPPORTED_MODE,
            )
        self._require_resettable(current)
        await self._refuse_if_busy(org_id, sandbox_id)
        sandbox = await self._record_intent(org_id, actor_id, sandbox_id)
        sandbox = await self._with_fresh_egress_token(sandbox)
        await self._replace_container(actor_id, sandbox)
        if self._on_replaced is not None:
            await self._on_replaced(org_id, sandbox_id)
        return await self._core.load(org_id, sandbox_id)

    async def _with_fresh_egress_token(self, sandbox: Sandbox) -> Sandbox:
        """The intent row with the env ``Lifecycle.refresh_egress`` just stored.

        The new container is created from this env, so an allowlisted sandbox gets a newly
        minted egress token. Only the env (and the row version) are taken from the refreshed
        row: the state stays the one the intent saw.
        """
        refreshed = await self._core.refresh_egress(sandbox.org_id, sandbox.id)
        changes = {"env": refreshed.env, "version": refreshed.version}
        return sandbox.model_copy(update=changes)

    @staticmethod
    def _require_resettable(sandbox: Sandbox) -> None:
        if sandbox.state not in _RESETTABLE:
            raise InvalidState(
                f"illegal sandbox transition: {sandbox.state.value} -> {RESET_TARGET}",
                details={"state": sandbox.state.value, "target": RESET_TARGET},
            )

    async def _record_intent(self, org_id: str, actor_id: str, sandbox_id: str) -> Sandbox:
        """Audit the reset and bump the row's version, so a racing writer fails its own save."""
        async with self._uow_factory() as uow:
            current = await self._core.require(uow, org_id, sandbox_id)
            self._require_resettable(current)  # decided again on the row being written
            now = self._clock.now()
            changes: dict[str, Any] = {"updated_at": now}
            if current.state is _S.STARTED:  # a fresh run: keep the idle timer off the old one
                changes.update(started_at=now, last_activity_at=now)
            saved = await uow.sandboxes.update(
                org_id, current.model_copy(update=changes), expected_version=current.version
            )
            details = {"state": current.state.value, "previous_driver_ref": current.driver_ref}
            note = AuditNote(actor_id, SANDBOX_RESET, details)
            await self._core.record(uow, org_id, sandbox_id, note)
            await uow.commit()
        return saved

    async def _replace_container(self, actor_id: str, sandbox: Sandbox) -> None:
        """Remove the old container, create the new one (and start it when the sandbox runs).

        ``sandbox`` is the row the intent saved, so its state is the one the intent saw. The new
        ref is saved before the start; a driver failure past the removal is recorded, then raised.
        """
        await self._refuse_if_busy(sandbox.org_id, sandbox.id)  # a snapshot may have begun since
        created_ref: str | None = None
        try:
            if sandbox.driver_ref is not None:
                try:
                    await self._driver.destroy(sandbox.driver_ref)
                except DriverNotFound:
                    pass  # already gone; the outcome is the one we want
            created_ref = (await self._driver.create(self._core.spec(sandbox))).ref
            await self._record_ref(sandbox.org_id, sandbox.id, created_ref, sandbox.state)
            if sandbox.state is _S.STARTED:
                await self._driver.start(created_ref)
        except DriverError as exc:
            await self._record_failure(actor_id, sandbox, exc, created_ref)
            raise

    async def _record_ref(
        self, org_id: str, sandbox_id: str, ref: str, intent_state: SandboxState
    ) -> None:
        """Save the new ref on the row; destroy the new container and raise 409 if it can't be.

        The row must still be in ``intent_state``. A concurrent writer that only bumped the row
        version is read again, up to ``RECORD_REF_ATTEMPTS`` times.
        """
        failure = Conflict(
            f"sandbox {sandbox_id} was modified concurrently during the reset",
            reason=CONCURRENT_UPDATE,
        )
        for _ in range(RECORD_REF_ATTEMPTS):
            try:
                changed_to = await self._save_ref(org_id, sandbox_id, ref, intent_state)
            except Conflict:
                continue  # stale version: read the row again
            if changed_to is None:
                return
            failure = Conflict(
                f"sandbox {sandbox_id} changed during the reset: it is now {changed_to.value}, "
                f"not {intent_state.value}; the new container was removed",
                reason=CHANGED_DURING_RESET,
                details={"state": changed_to.value, "expected_state": intent_state.value},
            )
            break
        await self._discard(ref)
        raise failure

    async def _save_ref(
        self, org_id: str, sandbox_id: str, ref: str, intent_state: SandboxState
    ) -> SandboxState | None:
        """``None`` once the row holds ``ref``; the row's state when it left ``intent_state``."""
        async with self._uow_factory() as uow:
            current = await self._core.require(uow, org_id, sandbox_id)
            if current.state is not intent_state:
                return current.state
            if current.driver_ref == ref:
                return None
            changes = {"driver_ref": ref, "updated_at": self._clock.now()}
            await uow.sandboxes.update(
                org_id, current.model_copy(update=changes), expected_version=current.version
            )
            await uow.commit()
        return None

    async def _discard(self, ref: str) -> None:
        """Best-effort removal of a container no row points at."""
        try:
            await self._driver.destroy(ref)
        except DriverNotFound:
            pass  # already gone
        except DriverError:
            logger.exception("could not remove container %s left by a conflicted reset", ref)

    async def _record_failure(
        self, actor_id: str, sandbox: Sandbox, exc: DriverError, ref: str | None
    ) -> None:
        """Move the row to error and audit ``sandbox.reset_failed``; never raises.

        The stored ``error_reason`` and the audit ``error`` are the tenant-safe failure reason
        (``failure_reason``), the same text the create path records.
        """
        reason = failure_reason(exc)[:MAX_ERROR_REASON_CHARS]
        try:
            await self._core.record_failure(
                sandbox.org_id, sandbox.id, exc, driver_ref=ref, code=ERROR_RESET_FAILED
            )
            async with self._uow_factory() as uow:
                current = await self._core.require(uow, sandbox.org_id, sandbox.id)
                if current.state in _RESETTABLE:  # the frozen table has no edge to error here
                    changes: dict[str, Any] = {
                        "state": _S.ERROR,
                        "error_reason": reason,
                        "error_code": ERROR_RESET_FAILED,
                        "updated_at": self._clock.now(),
                    }
                    if ref is not None:
                        changes["driver_ref"] = ref
                    await uow.sandboxes.update(
                        sandbox.org_id,
                        current.model_copy(update=changes),
                        expected_version=current.version,
                    )
                details = {"error": reason}
                note = AuditNote(actor_id, SANDBOX_RESET_FAILED, details)
                await self._core.record(uow, sandbox.org_id, sandbox.id, note)
                await uow.commit()
        except Exception:  # the driver error is the one the caller must see
            logger.exception("could not record the failed reset of sandbox %s", sandbox.id)
