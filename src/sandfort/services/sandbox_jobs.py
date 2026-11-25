"""The sandbox drive-and-transition core, shared by the inline service path and the job handlers.

``Lifecycle`` holds the work the sandbox service has always done: commit a state move in its
own unit of work, call the driver with no transaction open (architecture D4), then commit the
outcome. Every ``drive_*`` method is idempotent: it inspects the stored state first, so a
retried job (or a second runner) never repeats a finished step, and it adopts what a previous
attempt left behind (deterministic container names make a retried create adopt the container).
The handlers at the bottom are registered for the four sandbox lifecycle job kinds.
With ``egress`` set, ``refresh_egress`` (called by a reset) re-mints the token of an allowlisted
sandbox and rewrites its stored environment. ``drive_start`` does not: a start reuses the
existing container, whose environment was fixed when it was created, so a rewritten stored
environment would never reach it. A new token reaches a sandbox only through a recreated
container (a reset). At startup ``sandfort.api.wiring.install_services`` calls
``sandfort.wiring.wire_egress``, which installs the settings the job handlers use.
"""

import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType, AuditOutcome
from sandfort.domain.isolation import ISOLATION_LABEL
from sandfort.domain.lifecycle import IllegalTransition, assert_transition, can_transition
from sandfort.domain.node import DEFAULT_NODE_ID
from sandfort.domain.sandbox import (
    ERROR_EGRESS_UNAVAILABLE,
    ERROR_IMAGE_ACCESS_DENIED,
    ERROR_IMAGE_NOT_FOUND,
    ERROR_INTERNAL,
    ERROR_INVALID_IMAGE_REFERENCE,
    ERROR_REGISTRY_TLS_ERROR,
    ERROR_REGISTRY_UNREACHABLE,
    ERROR_START_FAILED,
    ERROR_TIMEOUT,
    Sandbox,
    SandboxState,
    egress_spec_labels,
)
from sandfort.drivers.base import SandboxDriver, SandboxSpec
from sandfort.drivers.errors import (
    DriverAccessDenied,
    DriverError,
    DriverInvalidReference,
    DriverNotFound,
    DriverRegistryTlsError,
    DriverRegistryUnreachable,
    DriverTimeout,
)
from sandfort.egress.env import EgressReminting, reminted_proxy_env
from sandfort.errors import InvalidState, NotFound
from sandfort.services.audit import AuditRecorder
from sandfort.services.egress_provision import EgressUnavailable, provision_egress_env
from sandfort.services.node_registry import stamp_job
from sandfort.services.usage import MeteredUnitOfWorkFactory
from sandfort.services.volumes import user_labels
from sandfort.workers.handlers import JobContext, register
from sandfort.workers.jobs import (
    DEFAULT_WAKEUP,
    SANDBOX_CREATE,
    SANDBOX_DELETE,
    SANDBOX_START,
    SANDBOX_STOP,
    JobWakeup,
    SandboxJob,
    enqueue_job,
)

logger = logging.getLogger(__name__)

STOP_TIMEOUT_S = 10.0
MAX_ERROR_REASON_CHARS = 500
SANDBOX_FAILED = "sandbox.failed"
PHASE_CREATE = "create"
PHASE_START = "start"

_S = SandboxState
# Image failures whose code follows from the exception type alone (never the message).
_IMAGE_ERROR_CODES: tuple[tuple[type[DriverError], str], ...] = (
    (DriverRegistryUnreachable, ERROR_REGISTRY_UNREACHABLE),
    (DriverRegistryTlsError, ERROR_REGISTRY_TLS_ERROR),
    (DriverAccessDenied, ERROR_IMAGE_ACCESS_DENIED),
    (DriverInvalidReference, ERROR_INVALID_IMAGE_REFERENCE),
)


def driver_error_code(exc: DriverError, *, fallback: str, image: str | None = None) -> str:
    """The sandbox ``error_code`` for ``exc``, from its type and ref (never its message).

    A timeout is ``timeout``; an image registry failure is ``registry_unreachable`` (network,
    throttling or a registry server error), ``registry_tls_error`` (TLS validation failed),
    ``image_access_denied`` (the registry refused) or ``invalid_image_reference`` (unparsable
    reference); a not-found whose ref is ``image`` (the create's image or snapshot reference)
    is ``image_not_found``; anything else is ``fallback``.
    """
    for error_type, code in _IMAGE_ERROR_CODES:
        if isinstance(exc, error_type):
            return code
    if isinstance(exc, DriverTimeout):
        return ERROR_TIMEOUT
    if image is not None and isinstance(exc, DriverNotFound) and exc.ref == image:
        return ERROR_IMAGE_NOT_FOUND
    return fallback


def failure_reason(exc: DriverError) -> str:
    """The tenant-visible ``error_reason`` for ``exc`` (before the length cap): its message.

    Invariant: every driver error message is tenant safe, so none is rewritten here. The Docker
    driver gives a registry refusal, an unparsable reference and an unclassified pull failure a
    fixed message built from the image reference, and any other unclassified daemon failure a
    fixed sentence (``drivers/docker/client.py``); the daemon text only reaches the server log.
    The logs and firecracker agent drivers follow the same rule.
    """
    return exc.message


@dataclass(frozen=True, slots=True)
class AuditNote:
    actor_id: str | None
    action: str
    details: Mapping[str, Any] = field(default_factory=dict)


class Lifecycle:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        driver: SandboxDriver,
        clock: Clock,
        audit: AuditRecorder | None = None,
        on_stopped: Callable[[str, str], Awaitable[None]] | None = None,  # (org_id, sandbox_id)
        wakeup: JobWakeup = DEFAULT_WAKEUP,
        node_id: str = DEFAULT_NODE_ID,
        egress: EgressReminting | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        # Metered factories built with a driver also take a final disk sample at stop/delete.
        self._final_disk = (
            uow_factory.final_disk if isinstance(uow_factory, MeteredUnitOfWorkFactory) else None
        )
        self._egress = egress
        self._driver = driver
        self._clock = clock
        self._audit = audit or AuditRecorder(clock)
        self._on_stopped = on_stopped
        self._wakeup = wakeup
        self._node_id = node_id

    # -- drive steps (idempotent) ----------------------------------------------------

    async def drive_create(
        self, org_id: str, sandbox_id: str, actor_id: str | None = None
    ) -> Sandbox:
        sandbox = await self.load(org_id, sandbox_id)
        if sandbox.state is _S.PENDING:
            sandbox = await self.transition(org_id, sandbox_id, _S.CREATING)
        if sandbox.state is not _S.CREATING:
            return sandbox  # a previous attempt already finished (or the sandbox moved on)
        try:  # the owning node mints its own token, committed before any driver call
            sandbox = await provision_egress_env(
                self._uow_factory, self._egress, self._clock, sandbox
            )
        except EgressUnavailable as exc:
            return await self.record_failure(
                org_id,
                sandbox_id,
                exc,
                code=ERROR_EGRESS_UNAVAILABLE,
                phase=PHASE_CREATE,
                actor_id=actor_id,
            )
        ref: str | None = None
        try:
            info = await self._driver.create(self.spec(sandbox))  # adopts an existing container
            ref = info.ref
            await self._driver.start(ref)
        except DriverError as exc:
            image = sandbox.image_ref if ref is None else None  # only create pulls the image
            code = driver_error_code(exc, fallback=ERROR_START_FAILED, image=image)
            return await self.record_failure(
                org_id,
                sandbox_id,
                exc,
                driver_ref=ref,
                code=code,
                phase=PHASE_CREATE,
                actor_id=actor_id,
            )
        now = self._clock.now()
        return await self.transition(
            org_id, sandbox_id, _S.STARTED, driver_ref=ref, started_at=now, last_activity_at=now
        )

    async def drive_start(
        self, org_id: str, sandbox_id: str, actor_id: str | None = None
    ) -> Sandbox:
        sandbox = await self.load(org_id, sandbox_id)
        if sandbox.state is not _S.STARTING:
            return sandbox
        # No egress re-mint here: the start reuses the container and its original environment.
        now = self._clock.now()
        return await self._drive(
            org_id,
            sandbox,
            self._driver.start,
            _S.STARTED,
            failure_fallback=ERROR_START_FAILED,
            failure_phase=PHASE_START,
            actor_id=actor_id,
            started_at=now,
            last_activity_at=now,
            error_reason=None,
            error_code=None,
            stop_cause=None,
        )

    async def drive_stop(self, org_id: str, sandbox_id: str) -> Sandbox:
        sandbox = await self.load(org_id, sandbox_id)
        if sandbox.state is not _S.STOPPING:
            return sandbox
        await self._final_disk_sample(sandbox)  # the container still exists; no transaction open
        return await self._drive(
            org_id,
            sandbox,
            lambda ref: self._driver.stop(ref, timeout_s=STOP_TIMEOUT_S),
            _S.STOPPED,
            tolerate_missing=True,
            stopped_at=self._clock.now(),
        )

    async def drive_delete(self, org_id: str, sandbox_id: str, actor_id: str | None) -> Sandbox:
        sandbox = await self.load(org_id, sandbox_id)
        if sandbox.state is not _S.DESTROYING:
            return sandbox
        await self._final_disk_sample(sandbox)  # before the destroy removes the container
        if sandbox.driver_ref is not None:
            try:
                await self._driver.destroy(sandbox.driver_ref)
            except DriverNotFound:
                pass  # already gone; the outcome is the one we want
        return await self.transition(
            org_id,
            sandbox_id,
            _S.DESTROYED,
            audit=AuditNote(
                actor_id,
                "sandbox.delete",
                # round 65: attributable without a join to the create row (same redaction path)
                {"name": sandbox.name, "labels": user_labels(sandbox.labels)},
            ),
            deleted_at=self._clock.now(),
        )

    async def _final_disk_sample(self, sandbox: Sandbox) -> None:
        if self._final_disk is not None:
            await self._final_disk.sample(sandbox)

    async def _drive(
        self,
        org_id: str,
        sandbox: Sandbox,
        action: Callable[[str], Awaitable[None]],
        final: SandboxState,
        *,
        tolerate_missing: bool = False,
        failure_fallback: str = ERROR_INTERNAL,
        failure_phase: str | None = None,
        actor_id: str | None = None,
        **changes: Any,
    ) -> Sandbox:
        """Run one driver action with no transaction open, then record the outcome."""
        try:
            if sandbox.driver_ref is None:
                raise DriverNotFound("sandbox has no container instance")
            await action(sandbox.driver_ref)
        except DriverNotFound as exc:
            if not (tolerate_missing and sandbox.driver_ref is not None):
                code = driver_error_code(exc, fallback=failure_fallback)
                return await self.record_failure(
                    org_id, sandbox.id, exc, code=code, phase=failure_phase, actor_id=actor_id
                )
        except DriverError as exc:
            code = driver_error_code(exc, fallback=failure_fallback)
            return await self.record_failure(
                org_id, sandbox.id, exc, code=code, phase=failure_phase, actor_id=actor_id
            )
        return await self.transition(org_id, sandbox.id, final, **changes)

    async def refresh_egress(self, org_id: str, sandbox_id: str) -> Sandbox:
        """Re-mint an allowlisted sandbox's egress token into its stored env (own unit of work).

        For a reset, which recreates the container from the stored env. A start must not call
        it: the container it starts keeps the env it was created with. A no-op without
        ``egress``, for a sandbox with no allowlist, and for a blocked one (created with an empty
        list: ``block_all``, no proxy environment, no token to revoke). A sandbox whose list was
        PATCHed to ``[]`` still holds a token, so its epoch rises like any other. The credential
        epoch rises by 1 (the previous container's token is revoked through the proxy's lookup)
        and the policy generation becomes at least 1, so a legacy sandbox upgrades to a v2 token.
        """
        async with self._uow_factory() as uow:
            current = await self.require(uow, org_id, sandbox_id)
            if self._egress is None or current.egress_allowlist is None:
                return current
            if not current.egress_allowlist and current.network.block_all:
                return current  # created blocked: no proxy environment, nothing to revoke
            epoch = current.egress_credential_epoch + 1
            env = reminted_proxy_env(
                current.env,
                self._egress,
                current.id,
                self._clock.now(),
                current.auto_delete_minutes,
                epoch=epoch,
            )
            updated = current.model_copy(
                update={
                    "env": env,
                    "egress_credential_epoch": epoch,
                    "egress_policy_generation": max(1, current.egress_policy_generation),
                    "updated_at": self._clock.now(),
                }
            )
            saved = await uow.sandboxes.update(org_id, updated, expected_version=current.version)
            await uow.commit()
        return saved

    # -- persistence -----------------------------------------------------------------

    async def transition(
        self,
        org_id: str,
        sandbox_id: str,
        target: SandboxState,
        *,
        audit: AuditNote | None = None,
        job: SandboxJob | None = None,
        before_commit: Callable[[UnitOfWorkPort, Sandbox], Awaitable[None]] | None = None,
        **changes: Any,
    ) -> Sandbox:
        """Move to ``target`` in its own unit of work; illegal moves raise InvalidState.

        ``audit`` and ``job`` are written in the same unit of work as the move, so the
        intent and its follow-up job commit together. ``before_commit`` runs inside that unit
        of work after the state row is updated and before the commit: when it raises, the
        whole move rolls back (a start that must reserve quota uses it).
        """
        async with self._uow_factory() as uow:
            current = await self.require(uow, org_id, sandbox_id)
            try:
                assert_transition(current.state, target)
            except IllegalTransition as exc:
                raise InvalidState(
                    str(exc), details={"state": current.state.value, "target": target.value}
                ) from exc
            updated = current.model_copy(
                update={"state": target, "updated_at": self._clock.now(), **changes}
            )
            saved = await uow.sandboxes.update(org_id, updated, expected_version=current.version)
            if before_commit is not None:
                await before_commit(uow, saved)  # raising here rolls the whole move back
            if audit is not None:
                await self.record(uow, org_id, sandbox_id, audit)
            if job is not None:
                queued = await enqueue_job(uow, self._clock, org_id, job.kind, job.payload())
                await stamp_job(uow, queued.id, self._node_id)
            await uow.commit()
        if job is not None:
            self._wakeup.notify()
        if target in (_S.STOPPED, _S.DESTROYED) and self._on_stopped is not None:
            await self._on_stopped(org_id, sandbox_id)
        return saved

    async def enqueue(self, job: SandboxJob) -> None:
        """Enqueue ``job`` alone (a retry of an intent whose first job already ran out)."""
        async with self._uow_factory() as uow:
            queued = await enqueue_job(uow, self._clock, job.org_id, job.kind, job.payload())
            await stamp_job(uow, queued.id, self._node_id)
            await uow.commit()
        self._wakeup.notify()

    async def record_failure(
        self,
        org_id: str,
        sandbox_id: str,
        exc: DriverError,
        *,
        driver_ref: str | None = None,
        code: str | None = None,
        phase: str | None = None,
        actor_id: str | None = None,
    ) -> Sandbox:
        """Move the row to ``error`` with ``exc``'s message and ``code`` (from the type when
        ``None``: ``timeout`` for a driver timeout, else ``internal``).

        With ``phase`` (``create`` or ``start``) the same unit of work also writes the audit row
        ``sandbox.failed`` (outcome ``error``): both land or neither does. The actor is
        ``actor_id`` when known, else the system."""
        if code is None:
            code = driver_error_code(exc, fallback=ERROR_INTERNAL)
        async with self._uow_factory() as uow:
            current = await self.require(uow, org_id, sandbox_id)
            if not can_transition(current.state, _S.ERROR):
                return current
            changes: dict[str, Any] = {
                "state": _S.ERROR,
                "error_reason": failure_reason(exc)[:MAX_ERROR_REASON_CHARS],
                "error_code": code,
                "updated_at": self._clock.now(),
            }
            if driver_ref is not None:
                changes["driver_ref"] = driver_ref
            saved = await uow.sandboxes.update(
                org_id, current.model_copy(update=changes), expected_version=current.version
            )
            if phase is not None:
                requester = actor_id or await self._requester(uow, saved, phase)
                await self._record_failed(uow, saved, phase, requester)
            await uow.commit()
        return saved

    @staticmethod
    async def _requester(uow: UnitOfWorkPort, sandbox: Sandbox, phase: str) -> str | None:
        """The actor of the newest ``sandbox.create`` / ``sandbox.start`` row of ``sandbox``.

        The inline (job-less) drive is not handed the actor, but the intent row written in the
        request's own unit of work names it; ``None`` when no such row exists."""
        action = "sandbox.create" if phase == PHASE_CREATE else "sandbox.start"
        rows = await uow.audit.list(
            sandbox.org_id, action=action, target_id=sandbox.id, order="desc", limit=1
        )
        return rows[0].actor_id if rows else None

    async def _record_failed(
        self, uow: UnitOfWorkPort, sandbox: Sandbox, phase: str, actor_id: str | None
    ) -> None:
        details = {
            "phase": phase,
            "error_code": sandbox.error_code,
            "error_reason": sandbox.error_reason,
        }
        await self._audit.record(
            uow,
            org_id=sandbox.org_id,
            actor_type=ActorType.SYSTEM if actor_id is None else ActorType.API_KEY,
            actor_id=actor_id,
            action=SANDBOX_FAILED,
            target_type="sandbox",
            target_id=sandbox.id,
            outcome=AuditOutcome.ERROR,
            details=details,
        )

    async def record(self, uow: UnitOfWorkPort, org_id: str, target: str, note: AuditNote) -> None:
        await self._audit.record(
            uow,
            org_id=org_id,
            actor_type=ActorType.SYSTEM if note.actor_id is None else ActorType.API_KEY,
            actor_id=note.actor_id,
            action=note.action,
            target_type="sandbox",
            target_id=target,
            details=note.details,
        )

    async def load(self, org_id: str, sandbox_id: str) -> Sandbox:
        async with self._uow_factory() as uow:
            return await self.require(uow, org_id, sandbox_id)

    @staticmethod
    async def require(uow: UnitOfWorkPort, org_id: str, sandbox_id: str) -> Sandbox:
        sandbox = await uow.sandboxes.get(org_id, sandbox_id)
        if sandbox is None:
            raise NotFound(f"sandbox {sandbox_id} not found")
        return sandbox

    @staticmethod
    def spec(sandbox: Sandbox) -> SandboxSpec:
        # User labels stay in the database: container labels are the driver's ownership marks.
        return SandboxSpec(
            sandbox_id=sandbox.id,
            org_id=sandbox.org_id,
            name=f"sf-{sandbox.id}",
            image=sandbox.image_ref,
            resources=sandbox.resources,
            env=sandbox.env,
            network=sandbox.network,
            isolation=sandbox.labels.get(ISOLATION_LABEL),  # absent: the deployment default
            labels=egress_spec_labels(sandbox),
        )


# -- job handlers ----------------------------------------------------------------------


_job_egress: EgressReminting | None = None


def install_job_egress(reminting: EgressReminting | None) -> None:
    """Set the re-minting settings the job handlers' lifecycle gets (``None`` turns it off).

    Called once at startup by ``sandfort.wiring.wire_egress``, which
    ``sandfort.api.wiring.install_services`` calls. The job context is frozen, so the
    settings travel here instead.
    """
    global _job_egress
    _job_egress = reminting


def job_lifecycle(context: JobContext) -> Lifecycle:
    """The lifecycle core a job handler drives, with the installed egress re-minting."""
    return Lifecycle(
        context.uow_factory,
        context.driver,
        context.clock,
        on_stopped=context.on_stopped,
        egress=_job_egress,
    )


@register(SANDBOX_CREATE)
async def handle_create(payload: Mapping[str, Any], context: JobContext) -> None:
    job = SandboxJob.from_payload(payload)
    try:
        await job_lifecycle(context).drive_create(job.org_id, job.sandbox_id, job.actor_id)
    except NotFound:
        return  # the sandbox is gone; nothing left to create


@register(SANDBOX_START)
async def handle_start(payload: Mapping[str, Any], context: JobContext) -> None:
    job = SandboxJob.from_payload(payload)
    try:
        await job_lifecycle(context).drive_start(job.org_id, job.sandbox_id, job.actor_id)
    except NotFound:
        return


@register(SANDBOX_STOP)
async def handle_stop(payload: Mapping[str, Any], context: JobContext) -> None:
    job = SandboxJob.from_payload(payload)
    try:
        await job_lifecycle(context).drive_stop(job.org_id, job.sandbox_id)
    except NotFound:
        return


@register(SANDBOX_DELETE)
async def handle_delete(payload: Mapping[str, Any], context: JobContext) -> None:
    job = SandboxJob.from_payload(payload)
    try:
        await job_lifecycle(context).drive_delete(job.org_id, job.sandbox_id, job.actor_id)
    except NotFound:
        return
