"""The line that replaces the driver's sandbox-death text in a session command's output.

The driver only sees its container die, so it writes a line that guesses at a resource limit
(``SANDBOX_DIED_MESSAGE``). The sandbox row knows better: a stop the caller or auto-stop asked
for says so, a stop with no recorded cause is described neutrally, and a death the row blames
on a resource limit or on the main process keeps the driver's wording. A sandbox that still
reads started (it died under a limit before the reconciler settled the row) keeps it too.
"""

import re

from sandfort.domain.sandbox import (
    STOP_CAUSE_AUTO_STOP,
    STOP_CAUSE_REQUESTED,
    STOP_CAUSE_UNKNOWN,
    Sandbox,
    visible_stop_cause,
)
from sandfort.drivers.docker.exec import SANDBOX_DIED_MESSAGE

STOPPED_ON_PURPOSE_TEMPLATE = (
    "the sandbox was stopped ({cause}) while this command ran; start it again"
)
STOPPED_UNKNOWN_MESSAGE = b"the sandbox stopped while this command ran"
_ON_PURPOSE = (STOP_CAUSE_REQUESTED, STOP_CAUSE_AUTO_STOP)


def death_line(sandbox: Sandbox | None) -> bytes:
    """The line to show where the driver wrote ``SANDBOX_DIED_MESSAGE``."""
    cause = None if sandbox is None else visible_stop_cause(sandbox)
    if cause in _ON_PURPOSE:
        return STOPPED_ON_PURPOSE_TEMPLATE.format(cause=cause).encode()
    if cause == STOP_CAUSE_UNKNOWN:
        return STOPPED_UNKNOWN_MESSAGE
    return SANDBOX_DIED_MESSAGE


def reword(data: bytes, sandbox: Sandbox | None) -> bytes:
    """``data`` with the driver's death line replaced by the line for the sandbox's cause."""
    if SANDBOX_DIED_MESSAGE not in data:
        return data
    return data.replace(SANDBOX_DIED_MESSAGE, death_line(sandbox))


# A code-context run says "cell" where an exec says "command", and a sandbox that stopped under
# a cell took the context's kernel (and its variables) with it.
CELL_LOST_HINT = (
    "the context and its variables are gone; start the sandbox and ensure the context again"
)
CELL_DIED_MESSAGE = (
    "the sandbox stopped while running this cell "
    f"(a resource limit was hit or its main process ended); {CELL_LOST_HINT}"
).encode()
_COMMAND_LIMIT = re.compile(rb"the command (was stopped because its output exceeded the limit)")


def cell_reword(data: bytes) -> bytes:
    """``data`` (a cell run's stderr) with the driver's command sentences worded for the cell.

    The output-limit sentence and the sandbox-death line are replaced; anything else stays.
    """
    reworded = _COMMAND_LIMIT.sub(rb"the cell \1", data)
    return reworded.replace(SANDBOX_DIED_MESSAGE, CELL_DIED_MESSAGE)
