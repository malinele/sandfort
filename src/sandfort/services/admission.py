"""Host admission (WP 5.7): may the host take one more reservation?

The configured host capacity (CPU millicores and memory MiB, ``0`` = unguarded) is multiplied
by ``Settings.host_overcommit_factor`` to give the effective capacity: a factor above 1 admits
more reservations than the host has resources for, below 1 keeps headroom. With the default
factor of 1.0 the check is the one the quota service always made. A request that would push
the host-wide reserved totals past the effective capacity raises ``CapacityExceeded`` (503).

The per-org row lock does not order two different orgs, so a guarded check first takes a
host-wide lock held to the end of the transaction: ``pg_advisory_xact_lock`` with a fixed key on
Postgres, a process-wide ``asyncio.Lock`` on SQLite (released when the root transaction ends).

A refusal because the host is full is also put on the caller's org audit chain, so the promise
that every non-GET call leaves a row holds for it too (``audit_capacity_refusal``). The service
that asked for the reservation calls it after the refused transaction rolled back, in its own
short transaction and with no driver call inside it, and then raises the same 503. That row is
the request's only one: recording a ``denied`` row through the request's audit recorder marks
the request, and the API's exception handler then writes no ``request.denied`` next to it (it
still records the 503, as ``denied``, when this write failed or never ran). Actions:

* ``sandbox.create_refused``: a create refused for host capacity, or (round 65) for the key's
  ``max_sandboxes`` cap (target: the org; ``audit_key_cap_refusal``, details ``reason``
  ``key_cap``, ``limit`` ``key_max_sandboxes``, ``max``, ``current``).
* ``sandbox.start_refused``: a start refused for host capacity (target: the sandbox).

Both carry outcome ``denied`` and details ``reason`` (``capacity``), ``requested`` (the
resources of this request) and ``host_full`` (``true``). The host-wide totals are other tenants'
usage and stay in the server log only.

Coalescing (``RefusalCoalescer``): a client that retries a 503 would write a permanent row per
retry, so for the same action, API key and reason at most one row is written per 60 seconds per
server process. The refusals suppressed in between are counted into the next row's details as
``refusals_coalesced`` (the key is absent when nothing was suppressed). A suppressed refusal
still counts as audited: the request gets no ``request.denied`` row from the exception handler.
"""

import asyncio
import logging
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, SessionTransaction

from sandfort.clock import Clock
from sandfort.config import Settings
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.db.repositories.quotas import LedgerInspection
from sandfort.domain.events import ActorType, AuditOutcome
from sandfort.domain.quota import Reservation
from sandfort.errors import CapacityExceeded, InternalError, QuotaExceeded
from sandfort.services.audit import AuditRecorder

logger = logging.getLogger(__name__)

SANDBOX_CREATE_REFUSED = "sandbox.create_refused"
SANDBOX_START_REFUSED = "sandbox.start_refused"
REASON_CAPACITY = "capacity"
REASON_KEY_CAP = "key_cap"
KEY_CAP_LIMIT = "key_max_sandboxes"
COALESCE_WINDOW = timedelta(seconds=60)
COALESCE_MAX_KEYS = 1024
MILLICORES_PER_VCPU = 1000
HOST_ADMISSION_LOCK_KEY = 0x53414E44464F5254  # "SANDFORT" as a bigint: the Postgres lock key
HOST_LOCK_HELD = "sandfort.host_admission_lock"  # session.info flag: this session holds it
_SQLITE_LOCKS: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = (
    weakref.WeakKeyDictionary()
)


RefusalKey = tuple[str, str, str | None, str]  # (action, org id, API key id, reason)


def refusal_key(action: str, org_id: str, actor_id: str | None, reason: str) -> RefusalKey:
    return (action, org_id, actor_id, reason)


@dataclass(slots=True)
class _Slot:
    written_at: datetime | None  # when the last row was written; None = the next one is due
    suppressed: int


class RefusalCoalescer:
    """At most one refusal row per key per window; the suppressed ones are counted.

    In memory and per process, bounded: beyond ``max_keys`` the oldest slots are dropped (their
    pending count is lost, so a flood of distinct keys cannot grow the map). A restart empties it.
    """

    def __init__(
        self,
        clock: Clock,
        window: timedelta = COALESCE_WINDOW,
        max_keys: int = COALESCE_MAX_KEYS,
    ) -> None:
        self._clock = clock
        self._window = window
        self._max_keys = max_keys
        self._slots: dict[RefusalKey, _Slot] = {}

    def size(self) -> int:
        return len(self._slots)

    def claim(self, key: RefusalKey) -> int | None:
        """``None``: suppressed and counted. Otherwise write a row now.

        The number returned is how many refusals were suppressed since the last row. Give the
        slot back with ``release`` when the write fails.
        """
        now = self._clock.now()
        slot = self._slots.pop(key, None)  # re-inserted below, so the newest is last
        if slot is not None and slot.written_at is not None:
            if timedelta(0) <= now - slot.written_at < self._window:
                slot.suppressed += 1
                self._slots[key] = slot
                return None
        carried = slot.suppressed if slot is not None else 0
        self._slots[key] = _Slot(written_at=now, suppressed=0)
        while len(self._slots) > self._max_keys:
            del self._slots[next(iter(self._slots))]
        return carried

    def release(self, key: RefusalKey, carried: int) -> None:
        """The row was not written: the next refusal writes it and still owes ``carried``."""
        self._slots.pop(key, None)
        self._slots[key] = _Slot(written_at=None, suppressed=carried)


def host_lock_for_loop() -> asyncio.Lock:
    """The process-wide SQLite host lock of the running event loop."""
    loop = asyncio.get_running_loop()
    lock = _SQLITE_LOCKS.get(loop)
    if lock is None:
        lock = _SQLITE_LOCKS[loop] = asyncio.Lock()
    return lock


async def lock_host(uow: object) -> None:
    """Serialise host admission across orgs until ``uow``'s transaction ends.

    Units of work without a SQLAlchemy session (test fakes) and other dialects skip it.
    """
    session = getattr(uow, "_session", None)
    if not isinstance(session, AsyncSession):
        return
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        await session.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": HOST_ADMISSION_LOCK_KEY}
        )
    elif dialect == "sqlite" and not session.info.get(HOST_LOCK_HELD):
        await _hold_sqlite_lock(session)


async def _hold_sqlite_lock(session: AsyncSession) -> None:
    lock = host_lock_for_loop()
    await lock.acquire()
    session.info[HOST_LOCK_HELD] = True
    sync_session = session.sync_session

    def release(_session: Session, transaction: SessionTransaction) -> None:
        # The listener stays registered (removing it mid-dispatch is unsafe); the flag makes
        # every later root transaction end a no-op until the next acquisition sets it again.
        if transaction.parent is None and session.info.pop(HOST_LOCK_HELD, None):
            lock.release()

    event.listen(sync_session, "after_transaction_end", release)


def ledger_inspection(uow: UnitOfWorkPort) -> LedgerInspection:
    """The unit of work's quota repository, which must report recounts and host totals."""
    repository = uow.quotas
    if not isinstance(repository, LedgerInspection):
        raise InternalError("quota repository cannot report recounts or host totals")
    return repository


def is_host_full(exc: CapacityExceeded) -> bool:
    """True for the refusal ``AdmissionService.admit`` raises (not a terminal cap or a probe)."""
    return exc.details.get("host_full") is True


async def audit_capacity_refusal(
    uow_factory: Callable[[], UnitOfWorkPort],
    audit: AuditRecorder,
    exc: CapacityExceeded,
    *,
    org_id: str,
    actor_id: str | None,
    action: str,
    target_type: str,
    target_id: str,
    coalescer: RefusalCoalescer | None = None,
    on_coalesced: Callable[[], None] | None = None,
) -> None:
    """Write the ``denied`` row of a host-full refusal in its own short unit of work.

    Best effort: a failed write is logged and never replaces the 503 the caller raises next.
    Other capacity errors (``is_host_full`` false) write nothing. With a ``coalescer`` a repeat
    of the same action, key and reason inside the window writes nothing and calls
    ``on_coalesced`` (the request counts as audited); the next row carries ``refusals_coalesced``.
    """
    if not is_host_full(exc):
        return
    details: dict[str, object] = {
        "reason": REASON_CAPACITY,
        "requested": exc.details.get("requested", {}),
        "host_full": True,
    }
    await _write_refusal(
        uow_factory,
        audit,
        details,
        org_id=org_id,
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        coalescer=coalescer,
        on_coalesced=on_coalesced,
    )


def is_key_cap(exc: QuotaExceeded) -> bool:
    """True for the 429 a create gets when its key already holds ``max_sandboxes`` (round 65)."""
    return exc.details.get("limit") == KEY_CAP_LIMIT


async def audit_key_cap_refusal(
    uow_factory: Callable[[], UnitOfWorkPort],
    audit: AuditRecorder,
    exc: QuotaExceeded,
    *,
    org_id: str,
    actor_id: str | None,
    coalescer: RefusalCoalescer | None = None,
    on_coalesced: Callable[[], None] | None = None,
) -> None:
    """Write ``sandbox.create_refused`` for a create refused by the key's ``max_sandboxes`` cap.

    Same row, outcome, coalescing and best-effort rules as ``audit_capacity_refusal``; the
    details are ``reason`` (``key_cap``), ``limit`` (``key_max_sandboxes``), ``max`` and
    ``current``. Other quota errors write nothing (the handler's ``request.denied`` stands).
    """
    if not is_key_cap(exc):
        return
    details: dict[str, object] = {
        "reason": REASON_KEY_CAP,
        "limit": KEY_CAP_LIMIT,
        "max": exc.details.get("max"),
        "current": exc.details.get("current"),
    }
    await _write_refusal(
        uow_factory,
        audit,
        details,
        org_id=org_id,
        actor_id=actor_id,
        action=SANDBOX_CREATE_REFUSED,
        target_type="org",
        target_id=org_id,
        coalescer=coalescer,
        on_coalesced=on_coalesced,
    )


async def _write_refusal(
    uow_factory: Callable[[], UnitOfWorkPort],
    audit: AuditRecorder,
    details: dict[str, object],
    *,
    org_id: str,
    actor_id: str | None,
    action: str,
    target_type: str,
    target_id: str,
    coalescer: RefusalCoalescer | None,
    on_coalesced: Callable[[], None] | None,
) -> None:
    """Coalesce, then write one ``denied`` row in its own unit of work; best effort."""
    reason = str(details["reason"])
    key = refusal_key(action, org_id, actor_id, reason)
    carried = 0
    if coalescer is not None:
        claimed = coalescer.claim(key)
        if claimed is None:
            if on_coalesced is not None:
                on_coalesced()
            return
        carried = claimed
        if carried:
            details["refusals_coalesced"] = carried
    try:
        async with uow_factory() as uow:
            await audit.record(
                uow,
                org_id=org_id,
                actor_type=ActorType.SYSTEM if actor_id is None else ActorType.API_KEY,
                actor_id=actor_id,
                action=action,
                target_type=target_type,
                target_id=target_id,
                outcome=AuditOutcome.DENIED,
                details=details,
            )
            await uow.commit()
    except Exception:
        if coalescer is not None:
            coalescer.release(key, carried)
        logger.exception("failed to audit a %s refusal", reason)


class AdmissionService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def admit(self, uow: UnitOfWorkPort, requested: Reservation) -> None:
        """Raise ``CapacityExceeded`` unless the host-wide totals plus ``requested`` fit."""
        cpu_cap = self._settings.host_capacity_cpu_millicores
        memory_cap = self._settings.host_capacity_memory_mib
        if cpu_cap <= 0 and memory_cap <= 0:
            return
        await lock_host(uow)  # before the host totals are read, so two orgs cannot both fit
        factor = self._settings.host_overcommit_factor
        host = await ledger_inspection(uow).host_totals()
        total = host.add(requested)
        over_cpu = cpu_cap > 0 and total.vcpus > cpu_cap * factor / MILLICORES_PER_VCPU
        over_memory = memory_cap > 0 and total.memory_mib > memory_cap * factor
        if over_cpu or over_memory:
            # The totals are other tenants' aggregate usage: the server log keeps them, the
            # response only says the host is full.
            logger.warning(
                "host capacity exhausted: reserved=%s requested=%s",
                host.model_dump(mode="json"),
                requested.model_dump(mode="json"),
            )
            raise CapacityExceeded(
                "host capacity exhausted",
                details={"requested": requested.model_dump(mode="json"), "host_full": True},
            )
