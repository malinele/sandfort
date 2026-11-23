"""FROZEN: typed job handler registry. Concrete handlers register themselves in later packages."""

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.drivers.base import SandboxDriver
from sandfort.errors import Conflict, NotFound


@dataclass(frozen=True, slots=True)
class JobContext:
    """What a handler may use: persistence, the driver and the clock."""

    uow_factory: Callable[[], UnitOfWorkPort]
    driver: SandboxDriver
    clock: Clock
    on_stopped: Callable[[str, str], Awaitable[None]] | None = None  # (org_id, sandbox_id)


class JobHandler(Protocol):
    async def __call__(self, payload: Mapping[str, Any], context: JobContext) -> None: ...


class HandlerRegistry:
    def __init__(self) -> None:
        self._handlers: dict[str, JobHandler] = {}

    def register[H: JobHandler](self, kind: str) -> Callable[[H], H]:
        """Decorator binding ``kind`` to a handler; a kind can be registered only once."""

        def decorator(handler: H) -> H:
            if kind in self._handlers:
                raise Conflict(f"job handler already registered for kind {kind!r}")
            self._handlers[kind] = handler
            return handler

        return decorator

    def lookup(self, kind: str) -> JobHandler:
        try:
            return self._handlers[kind]
        except KeyError:
            raise NotFound(f"no job handler registered for kind {kind!r}") from None

    def kinds(self) -> frozenset[str]:
        return frozenset(self._handlers)


DEFAULT_REGISTRY = HandlerRegistry()
register = DEFAULT_REGISTRY.register
lookup = DEFAULT_REGISTRY.lookup
