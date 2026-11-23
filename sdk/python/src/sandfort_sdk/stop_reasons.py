"""The ``stop_reason`` values the server sends, as a type alias and module constants.

``ExecResult.stop_reason`` stays ``str | None`` so that a value a newer server adds does not
break an older SDK. Branch on the constants, and use :func:`is_known_stop_reason` to narrow the
attribute to :data:`StopReason` for a type checker.

``queue_timeout`` and ``context_lost`` are sent by code-context runs only.
"""

from typing import Final, Literal, TypeGuard, get_args

StopReason = Literal[
    "timeout",
    "output_limit",
    "sandbox_stopped",
    "sandbox_deleted",
    "sandbox_reset",
    "oom_killed",
    "killed",
    "queue_timeout",
    "context_lost",
]

STOP_REASON_TIMEOUT: Final = "timeout"  # the run hit its time limit
STOP_REASON_OUTPUT_LIMIT: Final = "output_limit"  # the output exceeded the limit; truncated
STOP_REASON_SANDBOX_STOPPED: Final = "sandbox_stopped"  # the sandbox stopped during the run
STOP_REASON_SANDBOX_DELETED: Final = "sandbox_deleted"  # refines sandbox_stopped
STOP_REASON_SANDBOX_RESET: Final = "sandbox_reset"  # refines sandbox_stopped
# The sandbox ran out of memory and the server could see it (container tier only); refines
# "killed" and "sandbox_stopped"
STOP_REASON_OOM_KILLED: Final = "oom_killed"
STOP_REASON_KILLED: Final = "killed"  # the process was killed by a signal
STOP_REASON_QUEUE_TIMEOUT: Final = "queue_timeout"  # code context: waited too long for a turn
# Code context: the kernel is gone (e.g. a stuck context that was removed). Such a run reports
# this reason INSTEAD OF "timeout", yet its exit code is still 124 and ``timed_out`` is true, so
# code that checks only STOP_REASON_TIMEOUT must also check STOP_REASON_CONTEXT_LOST.
STOP_REASON_CONTEXT_LOST: Final = "context_lost"

KNOWN_STOP_REASONS: Final[frozenset[str]] = frozenset(get_args(StopReason))


def is_known_stop_reason(value: str | None) -> TypeGuard[StopReason]:
    """True when ``value`` is a stop reason this SDK version knows (``None`` is not one)."""
    return value in KNOWN_STOP_REASONS
