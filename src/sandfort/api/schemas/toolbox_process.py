"""Request/response models for ``/process/execute``, ``/process/code-run`` and code contexts."""

from typing import Literal, Self

from pydantic import BaseModel, Field, field_validator, model_validator

from sandfort.api.schemas.common import NoBool, RequestModel
from sandfort.api.schemas.sandboxes import MAX_NAME_LENGTH, NAME_PATTERN
from sandfort.api.schemas.text_checks import check_cwd, check_env
from sandfort.drivers.base import ExecResult

MAX_TIMEOUT_S = 3600
CONTEXT_NAME_DESCRIPTION = (
    "Optional context name. Uniqueness among the live contexts of the sandbox is enforced per "
    "API process: two creates of one name racing across processes may both succeed. The "
    "character rules of sandbox names apply (letters, digits, `_`, `.`, `-`, starting with a "
    f"letter or digit, at most {MAX_NAME_LENGTH} characters)."
)


class CodeContextCreateRequest(RequestModel):
    language: Literal["python"] = "python"
    cwd: str | None = Field(
        default=None,
        description=(
            "Working directory of the kernel. When omitted, the sandbox's default working "
            "directory is used."
        ),
    )
    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_NAME_LENGTH,
        pattern=NAME_PATTERN,
        description=CONTEXT_NAME_DESCRIPTION
        + " When a live context already has this name, that context is returned (200) "
        "instead of a new one, with its own `cwd`; the `cwd` of this request is ignored.",
    )

    @field_validator("cwd")
    @classmethod
    def valid_cwd(cls, value: str | None) -> str | None:
        return check_cwd(value)


class CodeContextResponse(BaseModel):
    id: str = Field(description="Context id, `ctx_` plus 16 hex characters.")
    language: Literal["python"] = "python"
    cwd: str = Field(description="The kernel's working directory.")
    name: str | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
        description="The name the context was created with; absent for an unnamed context.",
    )


class ExecuteRequest(RequestModel):
    command: str | None = None
    argv: list[str] | None = None
    cwd: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    timeout_s: NoBool[int] = Field(default=60, ge=1, le=MAX_TIMEOUT_S)
    stdin: str | None = None

    @field_validator("cwd")
    @classmethod
    def valid_cwd(cls, value: str | None) -> str | None:
        return check_cwd(value)

    @field_validator("env")
    @classmethod
    def valid_env(cls, value: dict[str, str]) -> dict[str, str]:
        check_env(value)
        return value

    @model_validator(mode="after")
    def _exactly_one_command_form(self) -> Self:
        if (self.command is None) == (self.argv is None):
            raise ValueError("provide exactly one of 'command' or 'argv'")
        if self.command is not None and not self.command.strip():
            raise ValueError("'command' must not be empty")
        if self.argv is not None and not self.argv:
            raise ValueError("'argv' must not be empty")
        return self


class CodeRunRequest(RequestModel):
    language: Literal["python", "javascript", "typescript", "bash"]
    code: str
    argv: list[str] = Field(default_factory=list)
    cwd: str | None = Field(
        default=None,
        description=(
            "Working directory for the run. When omitted, the container's default working "
            "directory is used, so relative paths resolve against the user's files."
        ),
    )
    env: dict[str, str] = Field(default_factory=dict)
    timeout_s: NoBool[int] = Field(default=60, ge=1, le=MAX_TIMEOUT_S)

    @field_validator("cwd")
    @classmethod
    def valid_cwd(cls, value: str | None) -> str | None:
        return check_cwd(value)

    @field_validator("env")
    @classmethod
    def valid_env(cls, value: dict[str, str]) -> dict[str, str]:
        check_env(value)
        return value


STOP_REASON_TIMEOUT = "timeout"
STOP_REASON_OUTPUT_LIMIT = "output_limit"
STOP_REASON_SANDBOX_STOPPED = "sandbox_stopped"
# The sandbox died under the command because it was deleted or reset, not from a limit. The
# route decides these from the sandbox row; ``derive_stop_reason`` never returns them.
STOP_REASON_SANDBOX_DELETED = "sandbox_deleted"
STOP_REASON_SANDBOX_RESET = "sandbox_reset"
# Explicit reasons that refine a derived 'sandbox_stopped'; any other derived reason wins.
SANDBOX_STOPPED_REFINEMENTS = frozenset({STOP_REASON_SANDBOX_DELETED, STOP_REASON_SANDBOX_RESET})
STOP_REASON_KILLED = "killed"
# An out-of-memory kill the driver could see (container tier only): the container died of it
# (the route reads the daemon's verdict) or the kernel killed a process of the exec (the
# driver's ``oom_killed`` flag). It refines a derived 'killed' or 'sandbox_stopped'; the route
# sets it, ``derive_stop_reason`` never returns it.
STOP_REASON_OOM_KILLED = "oom_killed"
OOM_REFINABLE = frozenset({STOP_REASON_KILLED, STOP_REASON_SANDBOX_STOPPED})
KILLED_EXIT_CODE = 137  # 128 + SIGKILL, e.g. an OOM kill inside the sandbox
# Code-context runs only (``ContextRunResponse``), a vocabulary of their own: the exec and
# code-run results never carry these. The route sets them; the flags never derive them.
CONTEXT_STOP_REASON_QUEUE_TIMEOUT = "queue_timeout"  # refines 'timeout': waited for the lock
CONTEXT_STOP_REASON_CONTEXT_LOST = "context_lost"  # the kernel is gone; on an otherwise plain exit

_STOP_REASON_DOC = (
    "Why the command was stopped: 'timeout', 'output_limit', 'sandbox_stopped', "
    "'sandbox_deleted', 'sandbox_reset', 'oom_killed' or 'killed'; null for a normal exit. "
    "'sandbox_stopped' means the sandbox itself died (for example it exceeded its "
    "memory or process limit); 'sandbox_deleted' and 'sandbox_reset' mean it was "
    "deleted or reset while the command ran (exit_code stays 137 and sandbox_stopped "
    "stays true in all three). 'killed' means the process got SIGKILL (exit 137), "
    "which includes user code killing itself, not only a sandbox-initiated kill. "
    "'oom_killed' means the sandbox ran out of memory and the server could see it: the "
    "container died of it (sandbox_stopped is true) or the kernel killed the process "
    "(exit 137, the sandbox keeps running). A dead container is reported on the container "
    "and gVisor isolation tiers, a killed process while the container keeps running on the "
    "container tier only, and under the microVM tier an out-of-memory kill still reads "
    "'killed' or 'sandbox_stopped'."
)
_CONTEXT_STOP_REASON_DOC = _STOP_REASON_DOC + (
    " Code-context runs add two values. 'queue_timeout': the run waited for another run on "
    "the same context longer than its timeout_s and never started (exit_code 124, timed_out "
    "true); the context is kept. 'context_lost': the kernel died or closed the connection, or "
    "the context was deleted, during the run (exit_code 1); its state is gone and later runs "
    "on it answer 404. 'context_lost' is also the value when the run's exec deadline passed "
    "with the cell stuck in native code and the kernel, still silent after the 2 s grace, was "
    "stopped and the context removed (exit_code 124 and timed_out true stay; the stderr "
    "line says so). A cell timeout, and an exec timeout after which the kernel answered the "
    "interrupt and the context was kept, stay 'timeout'."
)


def derive_stop_reason(
    *, exit_code: int, timed_out: bool, truncated: bool, sandbox_stopped: bool
) -> str | None:
    """Why a command was stopped, from the result flags only (never from its output text).

    Precedence: timeout, output limit, sandbox stopped, then a bare SIGKILL exit code.
    """
    if timed_out:
        return STOP_REASON_TIMEOUT
    if truncated:
        return STOP_REASON_OUTPUT_LIMIT
    if sandbox_stopped:
        return STOP_REASON_SANDBOX_STOPPED
    if exit_code == KILLED_EXIT_CODE:
        return STOP_REASON_KILLED
    return None


class ExecuteResponse(BaseModel):
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool
    duration_ms: int
    sandbox_stopped: bool = False  # the sandbox itself died while the command ran
    stop_reason: str | None = Field(default=None, description=_STOP_REASON_DOC)

    def _keeps_given_reason(self, derived: str | None) -> bool:
        """``True`` when the given ``stop_reason`` is an allowed refinement of ``derived``."""
        if self.stop_reason == STOP_REASON_OOM_KILLED:
            return derived in OOM_REFINABLE
        return (
            derived == STOP_REASON_SANDBOX_STOPPED
            and self.stop_reason in SANDBOX_STOPPED_REFINEMENTS
        )

    @model_validator(mode="after")
    def _derive_stop_reason(self) -> Self:
        """Derive the reason from the flags; keep a given refinement of 'sandbox_stopped'.

        The validator also runs when FastAPI validates the returned response, so a refinement
        the route set must survive it. Any other given value is replaced by the derived one.
        """
        derived = derive_stop_reason(
            exit_code=self.exit_code,
            timed_out=self.timed_out,
            truncated=self.truncated,
            sandbox_stopped=self.sandbox_stopped,
        )
        if not self._keeps_given_reason(derived):
            self.stop_reason = derived
        return self


class CellErrorResponse(BaseModel):
    type: str = Field(description="Class name of the exception, for example `ZeroDivisionError`.")
    message: str = Field(description="`str()` of the exception; may be empty.")


class ContextRunResponse(ExecuteResponse):
    """The execute response of a code-context run, plus the cell's structured outcome."""

    stop_reason: str | None = Field(default=None, description=_CONTEXT_STOP_REASON_DOC)
    result: str | None = Field(
        default=None,
        description=(
            "repr() of the cell's trailing expression; null when the cell has none, when it "
            "is None, when the cell raised, or when the run reported no outcome (an output "
            "limit, an exec timeout, a lost context). stdout still contains it, as in a "
            "notebook."
        ),
    )
    error: CellErrorResponse | None = Field(
        default=None,
        description=(
            "The exception the cell raised (including `TimeoutError` for a cell timeout, "
            "`KeyboardInterrupt` for an interrupt and `SyntaxError`); null otherwise. The "
            "traceback stays on stderr."
        ),
    )

    def _keeps_given_reason(self, derived: str | None) -> bool:
        if self.stop_reason == CONTEXT_STOP_REASON_QUEUE_TIMEOUT:
            return derived == STOP_REASON_TIMEOUT
        if self.stop_reason == CONTEXT_STOP_REASON_CONTEXT_LOST:
            return derived in (None, STOP_REASON_TIMEOUT)  # a removed stuck context is a timeout
        return super()._keeps_given_reason(derived)


def execute_response(result: ExecResult, *, stop_reason: str | None = None) -> ExecuteResponse:
    """The response for ``result``.

    ``stop_reason`` overrides the derived reason only where that is 'sandbox_stopped' and the
    override is 'sandbox_deleted' or 'sandbox_reset', or where it is 'killed' or
    'sandbox_stopped' and the override is 'oom_killed'; every other case keeps the derived one.
    """
    return ExecuteResponse(
        exit_code=result.exit_code,
        stdout=result.stdout.decode("utf-8", errors="replace"),
        stderr=result.stderr.decode("utf-8", errors="replace"),
        timed_out=result.timed_out,
        truncated=result.truncated,
        duration_ms=result.duration_ms,
        sandbox_stopped=result.sandbox_stopped,
        stop_reason=stop_reason,
    )


def context_run_response(
    result: ExecResult,
    *,
    stop_reason: str | None = None,
    value: str | None = None,
    error: CellErrorResponse | None = None,
) -> ContextRunResponse:
    """The code-context run response for ``result``; ``value`` is the trailing repr.

    Besides the ``execute_response`` refinements, ``stop_reason`` 'queue_timeout' refines a
    derived 'timeout' and 'context_lost' is kept where nothing else stopped the run or the
    run only timed out (the stuck kernel was stopped and its context removed). A run
    stopped at the output limit reports ``KILLED_EXIT_CODE`` whichever stream overflowed.
    """
    base = execute_response(result)
    fields = base.model_dump(exclude={"stop_reason"})
    if base.stop_reason == STOP_REASON_OUTPUT_LIMIT:
        fields["exit_code"] = KILLED_EXIT_CODE
    return ContextRunResponse(
        **fields,
        stop_reason=stop_reason,
        result=value,
        error=error,
    )
