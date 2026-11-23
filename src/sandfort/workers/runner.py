"""In-process async job runner: lease, run the registered handler, complete or back off.

Safe to run several instances in one process (or across processes): the repository's lease is
one guarded UPDATE, so a job is held by at most one runner at a time. A runner sleeps on the
wakeup signal and falls back to a short poll for work enqueued from outside this process.
Time for leases and backoff comes from the injected clock; sleeping uses real time.
"""

import asyncio
import contextlib
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import timedelta

from sandfort.clock import Clock
from sandfort.db.repositories.ports import JobRecord, UnitOfWorkPort
from sandfort.drivers.base import SandboxDriver
from sandfort.workers.handlers import DEFAULT_REGISTRY, HandlerRegistry, JobContext
from sandfort.workers.jobs import DEFAULT_WAKEUP, JobWakeup

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 5
BACKOFF_BASE_S = 1.0
BACKOFF_MAX_S = 300.0
POLL_INTERVAL_S = 0.5
LEASE_S = 120.0
JOB_TIMEOUT_S = 90.0
REAP_INTERVAL_S = 15.0


@dataclass(frozen=True, slots=True)
class RunnerConfig:
    poll_interval_s: float = POLL_INTERVAL_S
    lease_s: float = LEASE_S
    job_timeout_s: float = JOB_TIMEOUT_S
    reap_interval_s: float = REAP_INTERVAL_S
    max_attempts: int = MAX_ATTEMPTS
    backoff_base_s: float = BACKOFF_BASE_S
    backoff_max_s: float = BACKOFF_MAX_S


def backoff_delay(attempts: int, config: RunnerConfig) -> float:
    """Exponential delay after the ``attempts``-th failed attempt, capped."""
    exponent = max(attempts - 1, 0)
    return min(config.backoff_base_s * (2.0**exponent), config.backoff_max_s)


class JobRunner:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        driver: SandboxDriver,
        clock: Clock,
        *,
        registry: HandlerRegistry = DEFAULT_REGISTRY,
        wakeup: JobWakeup = DEFAULT_WAKEUP,
        config: RunnerConfig | None = None,
        on_stopped: Callable[[str, str], Awaitable[None]] | None = None,
        node_id: str | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._node_id = node_id  # lease only this node's jobs; None leases any (single process)
        self._clock = clock
        self._registry = registry
        self._wakeup = wakeup
        self._config = config or RunnerConfig()
        self._context = JobContext(uow_factory, driver, clock, on_stopped)
        self._task: asyncio.Task[None] | None = None
        self._last_reap = float("-inf")

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        if not self.running:
            self._task = asyncio.get_running_loop().create_task(self._loop())

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def __aenter__(self) -> "JobRunner":
        self.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.stop()

    # -- one step ----------------------------------------------------------------------

    async def run_once(self) -> bool:
        """Lease and process at most one due job; True when a job was processed."""
        job = await self._lease()
        if job is None:
            return False
        await self._process(job)
        return True

    async def reap(self) -> int:
        async with self._uow_factory() as uow:
            reaped = await uow.jobs.reap_expired(self._clock.now())
            await uow.commit()
        return reaped

    async def _lease(self) -> JobRecord | None:
        kinds = sorted(self._registry.kinds())
        now = self._clock.now()
        async with self._uow_factory() as uow:
            job = await uow.jobs.lease_next(
                kinds,
                now=now,
                lease_expires_at=now + timedelta(seconds=self._config.lease_s),
                node_id=self._node_id,
            )
            await uow.commit()
        return job

    async def _process(self, job: JobRecord) -> None:
        try:
            handler = self._registry.lookup(job.kind)
            await asyncio.wait_for(handler(job.payload, self._context), self._config.job_timeout_s)
        except Exception as exc:  # a failing handler must never take the runner down
            logger.warning(
                "job %s (%s) failed on attempt %d: %r", job.id, job.kind, job.attempts, exc
            )
            await self._fail(job, f"{type(exc).__name__}: {exc}")
            return
        async with self._uow_factory() as uow:
            await uow.jobs.complete(job.id, self._clock.now())
            await uow.commit()

    async def _fail(self, job: JobRecord, error: str) -> None:
        async with self._uow_factory() as uow:
            await uow.jobs.fail(
                job.id,
                error=error,
                now=self._clock.now(),
                backoff_s=backoff_delay(job.attempts, self._config),
                max_attempts=self._config.max_attempts,
            )
            await uow.commit()

    # -- loop --------------------------------------------------------------------------

    async def _loop(self) -> None:
        while True:
            generation = self._wakeup.generation  # read before leasing: no lost wakeups
            try:
                await self._reap_if_due()
                if await self.run_once():
                    continue
            except Exception:
                logger.exception("job runner iteration failed")
            await self._wakeup.wait(since=generation, timeout_s=self._config.poll_interval_s)

    async def _reap_if_due(self) -> None:
        now = time.monotonic()
        if now - self._last_reap < self._config.reap_interval_s:
            return
        self._last_reap = now
        reaped = await self.reap()
        if reaped:
            logger.info("requeued %d job(s) with expired leases", reaped)
