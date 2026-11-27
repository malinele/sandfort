"""Optional driver capability: the exit code of a dead instance.

Kept beside, not inside, the frozen protocols of ``drivers/base.py``: it is an additive,
optional member in the style of ``OomObservableDriver``. A driver that does not implement it,
or cannot read the runtime, simply leaves the exit code unknown (``None``).
"""

from typing import Protocol, runtime_checkable


@runtime_checkable
class ExitStatusDriver(Protocol):
    """Optional: tell the exit code the runtime recorded for an instance that is not running."""

    async def container_exit_code(self, ref: str) -> int | None:
        """The recorded exit code of ``ref``; ``None`` while it runs or when it cannot be read."""
        ...
