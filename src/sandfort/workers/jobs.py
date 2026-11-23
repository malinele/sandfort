"""Typed job payloads, the enqueue helper and the in-process wakeup signal.

A runner in the same process wakes the moment a job is enqueued (after the enqueuing
transaction committed); externally enqueued work is found by the runner's short poll.
"""

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar

from sandfort.clock import Clock
from sandfort.db.models.jobs import JobState
from sandfort.db.repositories.ports import JobRecord, UnitOfWorkPort
from sandfort.ids import JOB, new_id

SANDBOX_CREATE = "sandbox.create"
SANDBOX_START = "sandbox.start"
SANDBOX_STOP = "sandbox.stop"
SANDBOX_DELETE = "sandbox.delete"
SANDBOX_KINDS = (SANDBOX_CREATE, SANDBOX_START, SANDBOX_STOP, SANDBOX_DELETE)


class JobWakeup:
    """Wake sleeping runners; a generation counter closes the check-then-sleep race."""

    def __init__(self) -> None:
        self._generation = 0
        self._waiters: set[asyncio.Future[None]] = set()

    @property
    def generation(self) -> int:
        return self._generation

    def notify(self) -> None:
        self._generation += 1
        for waiter in list(self._waiters):
            waiter.get_loop().call_soon_threadsafe(_release, waiter)

    async def wait(self, *, since: int, timeout_s: float) -> None:
        """Return on a notify after generation ``since`` or after ``timeout_s``."""
        if self._generation != since:
            return
        waiter: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._waiters.add(waiter)
        try:
            await asyncio.wait_for(waiter, timeout_s)
        except TimeoutError:
            pass
        finally:
            self._waiters.discard(waiter)


def _release(waiter: asyncio.Future[None]) -> None:
    if not waiter.done():
        waiter.set_result(None)


DEFAULT_WAKEUP = JobWakeup()


@dataclass(frozen=True, slots=True)
class SandboxJob:
    """Payload shared by every sandbox lifecycle kind."""

    kind: ClassVar[str] = ""
    org_id: str
    sandbox_id: str
    actor_id: str | None = None

    def payload(self) -> dict[str, Any]:
        return {"org_id": self.org_id, "sandbox_id": self.sandbox_id, "actor_id": self.actor_id}

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "SandboxJob":
        actor = payload.get("actor_id")
        return cls(
            org_id=str(payload["org_id"]),
            sandbox_id=str(payload["sandbox_id"]),
            actor_id=None if actor is None else str(actor),
        )


@dataclass(frozen=True, slots=True)
class SandboxCreateJob(SandboxJob):
    kind: ClassVar[str] = SANDBOX_CREATE


@dataclass(frozen=True, slots=True)
class SandboxStartJob(SandboxJob):
    kind: ClassVar[str] = SANDBOX_START


@dataclass(frozen=True, slots=True)
class SandboxStopJob(SandboxJob):
    kind: ClassVar[str] = SANDBOX_STOP


@dataclass(frozen=True, slots=True)
class SandboxDeleteJob(SandboxJob):
    kind: ClassVar[str] = SANDBOX_DELETE


async def enqueue_job(
    uow: UnitOfWorkPort,
    clock: Clock,
    org_id: str,
    kind: str,
    payload: Mapping[str, Any],
    *,
    run_after: datetime | None = None,
) -> JobRecord:
    """Add a queued job to ``uow``; the caller commits, then calls ``wakeup.notify()``."""
    now = clock.now()
    job = JobRecord(
        id=new_id(JOB),
        org_id=org_id,
        kind=kind,
        payload=dict(payload),
        state=JobState.QUEUED.value,
        attempts=0,
        run_after=run_after or now,
        lease_expires_at=None,
        last_error=None,
        created_at=now,
        updated_at=now,
    )
    await uow.jobs.enqueue(job)
    return job
