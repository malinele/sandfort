"""FROZEN: the outbox publisher every phase-4 package publishes through (D5).

``publish`` appends one event to the outbox through the caller's unit of work and
never commits: the event lands atomically with the state change the caller
commits, and is lost with it on rollback. ``event_type`` is normally an
``EventType`` member; the stored value is its plain string.
"""

from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol

from sandfort.clock import Clock
from sandfort.db.repositories.ports import (
    OutboxEventRecord,
    SandboxRepository,
    UnitOfWorkPort,
)
from sandfort.domain.events import EventType, SandboxEventPayload
from sandfort.domain.sandbox import Sandbox, SandboxState, visible_stop_cause
from sandfort.ids import new_event_id
from sandfort.services.label_scope import count_through

STATE_EVENTS: Mapping[SandboxState, EventType] = {
    SandboxState.STARTED: EventType.SANDBOX_STARTED,
    SandboxState.STOPPED: EventType.SANDBOX_STOPPED,
    SandboxState.DESTROYED: EventType.SANDBOX_DELETED,
    SandboxState.ERROR: EventType.SANDBOX_ERROR,
}


class EventPublisher(Protocol):
    async def publish(
        self, uow: UnitOfWorkPort, event_type: str, org_id: str, payload: Mapping[str, Any]
    ) -> None: ...


class NoOpEventPublisher:
    """Publishes nothing; for tests and wiring that do not exercise the outbox."""

    async def publish(
        self, uow: UnitOfWorkPort, event_type: str, org_id: str, payload: Mapping[str, Any]
    ) -> None:
        return None


class OutboxEventPublisher:
    """Writes the event through ``uow.events``; the caller commits."""

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    async def publish(
        self, uow: UnitOfWorkPort, event_type: str, org_id: str, payload: Mapping[str, Any]
    ) -> None:
        await uow.events.append(
            OutboxEventRecord(
                id=new_event_id(),
                org_id=org_id,
                event_type=str(event_type),
                payload=dict(payload),
                created_at=self._clock.now(),
            )
        )


class EventingSandboxRepository:
    """Decorates a ``SandboxRepository`` so lifecycle moves publish in the same unit of work.

    ``add`` publishes ``sandbox.created``; ``update`` publishes ``sandbox.started``,
    ``sandbox.stopped``, ``sandbox.deleted`` or ``sandbox.error`` when the state entered is one of
    those; the payload carries ``reason``, ``error_code`` and ``stop_cause`` (null unless the
    state is stopping or stopped). The event is appended through ``uow`` before the caller
    commits, so it lands with the transition.
    """

    def __init__(
        self, inner: SandboxRepository, uow: UnitOfWorkPort, publisher: EventPublisher
    ) -> None:
        self._inner = inner
        self._uow = uow
        self._publisher = publisher

    async def add(self, sandbox: Sandbox) -> None:
        await self._inner.add(sandbox)
        await self._publish(EventType.SANDBOX_CREATED, sandbox)

    async def update(self, org_id: str, sandbox: Sandbox, *, expected_version: int) -> Sandbox:
        previous = await self._inner.get(org_id, sandbox.id)
        saved = await self._inner.update(org_id, sandbox, expected_version=expected_version)
        entered = STATE_EVENTS.get(saved.state)
        if entered is not None and previous is not None and previous.state is not saved.state:
            await self._publish(entered, saved)
        return saved

    async def get(self, org_id: str, sandbox_id: str) -> Sandbox | None:
        return await self._inner.get(org_id, sandbox_id)

    async def get_by_name(self, org_id: str, name: str) -> Sandbox | None:
        return await self._inner.get_by_name(org_id, name)

    async def list(
        self,
        org_id: str,
        *,
        state: SandboxState | None = None,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Sequence[Sandbox]:
        return await self._inner.list(
            org_id, state=state, labels=labels, cursor=cursor, limit=limit
        )

    async def list_for_reconciler(self) -> Sequence[Sandbox]:
        return await self._inner.list_for_reconciler()

    async def count_in_scope(self, org_id: str, labels: Mapping[str, str]) -> int:
        return await count_through(self._inner, org_id, labels)

    async def _publish(self, event_type: EventType, sandbox: Sandbox) -> None:
        payload = SandboxEventPayload(
            sandbox_id=sandbox.id, state=sandbox.state.value, reason=sandbox.error_reason
        )
        # The frozen payload model has no code or cause field; both ride next to the reason.
        body = {
            **payload.model_dump(mode="json"),
            "error_code": sandbox.error_code,
            "stop_cause": visible_stop_cause(sandbox),
        }
        await self._publisher.publish(self._uow, event_type, sandbox.org_id, body)


def with_sandbox_events(
    uow_factory: Callable[[], UnitOfWorkPort], publisher: EventPublisher
) -> Callable[[], UnitOfWorkPort]:
    """A unit-of-work factory whose ``sandboxes`` repository publishes lifecycle events."""

    def factory() -> UnitOfWorkPort:
        uow = uow_factory()
        uow.sandboxes = EventingSandboxRepository(uow.sandboxes, uow, publisher)
        return uow

    return factory
