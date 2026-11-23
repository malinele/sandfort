"""Error taxonomy: every error carries a stable ``code`` and an HTTP ``status``."""

from typing import Any, ClassVar


class SandfortError(Exception):
    """Base class; subclasses set ``code`` and ``status``."""

    code: ClassVar[str] = "INTERNAL"
    status: ClassVar[int] = 500

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = details or {}


class ValidationFailed(SandfortError):
    code = "VALIDATION_ERROR"
    status = 400


class Unauthorized(SandfortError):
    code = "UNAUTHORIZED"
    status = 401


class Forbidden(SandfortError):
    code = "FORBIDDEN"
    status = 403


class NotFound(SandfortError):
    """Also returned for resources that belong to another org."""

    code = "NOT_FOUND"
    status = 404


# Stable machine-readable reasons carried in ``details["reason"]`` of every CONFLICT answer.
NAME_TAKEN = "name_taken"
ALREADY_EXISTS = "already_exists"
CONCURRENT_UPDATE = "concurrent_update"
NO_CONTAINER = "no_container"
IN_PROGRESS = "in_progress"
IN_USE = "in_use"
CLOSED = "closed"
OPERATION_FAILED = "operation_failed"
CHANGED_DURING_RESET = "changed_during_reset"
UNSUPPORTED_MODE = "unsupported_mode"
DISK_FULL = "disk_full"
RUNTIME_CONFLICT = "runtime_conflict"
RESULT_UNAVAILABLE = "result_unavailable"
CONFLICT_REASON = "conflict"


class Conflict(SandfortError):
    """409 CONFLICT; ``details["reason"]`` tells the situations apart without parsing text.

    Reasons:

    - ``name_taken``: a sandbox, volume or snapshot with that name already exists in the org.
    - ``already_exists``: the object (member, external id, file, row id) already exists.
    - ``concurrent_update``: another writer changed the row first (stale version); retry.
    - ``no_container``: the sandbox has no running container instance for the call.
    - ``in_progress``: the same work (idempotency key, snapshot) has not finished yet.
    - ``in_use``: the object is still used by a sandbox (mounted volume, source snapshot).
    - ``closed``: the PTY or session is closed or not in a state that accepts the call.
    - ``operation_failed``: a git or fs command in the sandbox failed.
    - ``git_missing``: the sandbox's image has no git; create it from one that has (python:3.12).
    - ``changed_during_reset``: the sandbox changed state while a reset was replacing it.
    - ``unsupported_mode``: the operation is not supported in the configured run mode.
    - ``disk_full``: the runtime reported that the sandbox disk is full.
    - ``runtime_conflict``: the runtime refused the operation for another reason.
    - ``result_unavailable``: a keyed command ran, but its answer was not kept for replay.
    - ``conflict``: the fallback when none of the above applies.

    An explicit ``reason`` key in ``details`` wins over the ``reason`` argument.
    """

    code = "CONFLICT"
    status = 409

    def __init__(
        self,
        message: str,
        *,
        reason: str = CONFLICT_REASON,
        details: dict[str, Any] | None = None,
    ) -> None:
        merged = {"reason": reason, **(details or {})}
        super().__init__(message, details=merged)
        self.reason: str = merged["reason"]


def no_container_message(state: str | None) -> str:
    """The ``no_container`` text for a sandbox in ``state`` (``None`` when it is not known)."""
    if state in ("destroying", "destroyed"):
        return "the sandbox was deleted; create a new one"
    if state == "stopped":
        return "sandbox has no container instance; start it first"
    return "sandbox has no container instance"


def no_container_conflict(state: str | None = None, stop_cause: str | None = None) -> Conflict:
    """409 ``no_container`` with the message for ``state``.

    A known state stays in the details as ``state``; a known stop cause of the sandbox is added
    as ``stop_cause`` (omitted when ``None``). The message does not depend on the cause.
    """
    details: dict[str, Any] = {}
    if state is not None:
        details["state"] = state
    if stop_cause is not None:
        details["stop_cause"] = stop_cause
    return Conflict(no_container_message(state), reason=NO_CONTAINER, details=details or None)


class InvalidState(SandfortError):
    code = "INVALID_STATE"
    status = 409


class PayloadTooLarge(SandfortError):
    code = "PAYLOAD_TOO_LARGE"
    status = 413


MIB = 1024 * 1024


def upload_limit_error(limit: int, size: int, *, at_least: bool = False) -> PayloadTooLarge:
    """413 naming the limit and the size of the refused upload.

    ``at_least`` is for a body found too long while streaming: ``size`` is then the bytes
    received so far, not the final size.
    """
    shown = f"{limit // MIB} MiB ({limit} bytes)" if limit % MIB == 0 else f"{limit} bytes"
    bound = "at least " if at_least else ""
    return PayloadTooLarge(
        f"upload limit is {shown}; this upload is {bound}{size} bytes",
        details={"limit_bytes": limit, "size_bytes": size},
    )


class UnsupportedMediaType(SandfortError):
    """A request body in a media type the API does not read (only JSON is accepted)."""

    code = "UNSUPPORTED_MEDIA_TYPE"
    status = 415


class Unprocessable(SandfortError):
    code = "UNPROCESSABLE"
    status = 422


class InvalidRequest(Unprocessable):
    """A request value the API refuses: 422 in the ``VALIDATION_ERROR`` vocabulary."""

    code = "VALIDATION_ERROR"


class IdempotencyMismatch(Unprocessable):
    """An idempotency key was reused with a different request body."""

    code = "IDEMPOTENCY_MISMATCH"


class QuotaExceeded(SandfortError):
    code = "QUOTA_EXCEEDED"
    status = 429


class RateLimited(SandfortError):
    code = "RATE_LIMITED"
    status = 429

    def __init__(
        self,
        message: str,
        *,
        retry_after_s: int = 1,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details=details)
        self.retry_after_s = retry_after_s


class NodeUnavailable(SandfortError):
    """The node that owns a sandbox cannot serve the request right now; retry later."""

    code = "NODE_UNAVAILABLE"
    status = 503

    def __init__(
        self,
        message: str,
        *,
        reason: str,
        node_id: str,
        retry_after_s: int = 1,
    ) -> None:
        super().__init__(message, details={"reason": reason, "node_id": node_id})
        self.retry_after_s = retry_after_s


DEFAULT_CAPACITY_RETRY_AFTER_S = 5


class CapacityExceeded(SandfortError):
    """No room right now (host capacity, an org's terminal cap, a failed readiness probe)."""

    code = "CAPACITY"
    status = 503

    def __init__(
        self,
        message: str,
        *,
        retry_after_s: int = DEFAULT_CAPACITY_RETRY_AFTER_S,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details=details)
        self.retry_after_s = retry_after_s


DEFAULT_DNS_RETRY_AFTER_S = 2


class DnsUnavailable(SandfortError):
    """A host name could not be looked up (resolver timeout or failure); not a verdict. Retry."""

    code = "DNS_UNAVAILABLE"
    status = 503
    reason: ClassVar[str] = "dns_unavailable"  # in ``details``; not a Conflict reason

    def __init__(
        self,
        message: str,
        *,
        retry_after_s: int = DEFAULT_DNS_RETRY_AFTER_S,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details={"reason": self.reason, **(details or {})})
        self.retry_after_s = retry_after_s


class InternalError(SandfortError):
    code = "INTERNAL"
    status = 500
