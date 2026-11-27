"""The sandbox ``stop_cause`` values the server sends, as a type alias and module constants.

``SandboxInfo.stop_cause`` and ``Sandbox.stop_cause`` stay ``str | None`` so that a cause a
newer server adds does not break an older SDK. Branch on the constants, and use
:func:`is_known_stop_cause` to narrow the attribute to :data:`StopCause` for a type checker
(for example before an exhaustive ``match`` that ends in ``assert_never``).

The server reports a cause only while the state is ``stopping`` or ``stopped``; in every other
state the attribute is ``None``. A successful start clears it, and a second stop request never
overwrites it. The constants are named ``SANDBOX_STOP_CAUSE_*``, not ``STOP_*``, to keep them
apart from the exec stop reasons in ``stop_reasons``.

Restart guidance per value:

* ``requested``: a user or API key asked for the stop. Start the sandbox when you want it back.
* ``auto_stop``: the idle scanner stopped it after ``auto_stop_minutes`` without activity.
  Start it again; raise or disable ``auto_stop_minutes`` if the stop was unwanted.
* ``container_exited``: the reconciler found the container exited. Start it again; if it exits
  repeatedly, read the command logs for the cause.
* ``oom_killed``: the container was killed for exceeding its memory limit, as the runtime
  records it with exit code 137 (container and gvisor isolation tiers, microvm reports
  ``container_exited``). Resize the stopped sandbox to more memory before
  starting it again.
* ``unknown``: the stop was recorded without a cause (for example before the server stored
  causes). Starting it again is safe; the cause cannot be recovered.
"""

from typing import Final, Literal, TypeGuard, get_args

StopCause = Literal[
    "requested",
    "auto_stop",
    "container_exited",
    "oom_killed",
    "unknown",
]

SANDBOX_STOP_CAUSE_REQUESTED: Final = "requested"  # a user or API key asked for the stop
SANDBOX_STOP_CAUSE_AUTO_STOP: Final = "auto_stop"  # the idle scanner stopped it
SANDBOX_STOP_CAUSE_CONTAINER_EXITED: Final = "container_exited"  # the container exited
SANDBOX_STOP_CAUSE_OOM_KILLED: Final = "oom_killed"  # over its memory limit (container, gvisor)
SANDBOX_STOP_CAUSE_UNKNOWN: Final = "unknown"  # stopped with no recorded cause

KNOWN_STOP_CAUSES: Final[frozenset[str]] = frozenset(get_args(StopCause))


def is_known_stop_cause(value: str | None) -> TypeGuard[StopCause]:
    """True when ``value`` is a stop cause this SDK version knows (``None`` is not one)."""
    return value in KNOWN_STOP_CAUSES


# --- command stop causes ---------------------------------------------------------------

CommandStopCause = Literal["sandbox_stopped"]
"""Why a session command ended without finishing, as ``CommandInfo.stop_cause``,
``LogPage.stop_cause`` and the ``exit`` ``LogEvent.stop_cause`` report it.

Distinct from the sandbox :data:`StopCause`: ``sandbox_stopped`` means a sandbox stop ended the
command (state ``killed``, ``exit_code`` ``None``). The attributes stay ``str | None``; use
:func:`is_known_command_stop_cause` to narrow them.
"""

COMMAND_STOP_CAUSE_SANDBOX_STOPPED: Final = "sandbox_stopped"  # a sandbox stop ended it

KNOWN_COMMAND_STOP_CAUSES: Final[frozenset[str]] = frozenset(get_args(CommandStopCause))


def is_known_command_stop_cause(value: str | None) -> TypeGuard[CommandStopCause]:
    """True when ``value`` is a command stop cause this SDK knows (``None`` is not one)."""
    return value in KNOWN_COMMAND_STOP_CAUSES
