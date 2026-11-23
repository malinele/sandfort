"""Typed exceptions mirroring the server error codes (``sandfort.errors``).

``SandfortSDKError`` is the base to catch everything this SDK raises. ``ApiError`` covers only
the HTTP error answers of the server; ``SandboxFailedError``, ``SandboxTimeoutError``,
``AmbiguousSandboxName`` and ``TransportError`` (with ``InvalidResponseError``) are its
siblings, not its subclasses, so ``except ApiError`` does not catch them.

``Conflict`` (409) has three typed subclasses: ``NameTaken`` (``name_taken``: a sandbox with that
name exists) and ``NoContainer`` (``no_container``: the sandbox is stopped or deleted; ``state``
says which), both chosen by ``details["reason"]``, and ``ReadOnlyPath`` (code ``READ_ONLY_PATH``:
a write into a read-only mount). Any other 409 stays a plain ``Conflict``, and
``except Conflict`` catches all of them.

:data:`CONTEXT_GONE_ERRORS` is ``(NoContainer, NotFound)``: what a call on a code context raises
once its kernel is gone (the sandbox was stopped, or the context or the sandbox deleted), so one
``except CONTEXT_GONE_ERRORS`` covers both.
"""

import re
from typing import Any, ClassVar

# The " (request id ...)" tail a caller may append to a failure message.
_REQUEST_ID_TAIL = re.compile(r" \(request id [^)]*\)$")


def request_id_tail(text: str, request_id: str | None) -> str:
    """``" (request id <id>)"`` to end ``text`` with; ``""`` without an id or when ``text``
    already names that id in this form (so a failure line mentions it once)."""
    if not request_id or f"(request id {request_id})" in text:
        return ""
    return f" (request id {request_id})"


class SandfortSDKError(Exception):
    """Base class for everything this SDK raises."""


class TransportError(SandfortSDKError):
    """The request never produced a response (connect failure, timeout, ...).

    ``request_id`` is the ``x-request-id`` of a stream response that broke off after it began
    (``None`` when no response, or no such header, was seen).
    """

    def __init__(self, *args: object, request_id: str | None = None) -> None:
        super().__init__(*args)
        self.request_id = request_id


class RequestTimedOut(TransportError):
    """The request timed out (connect, write or read) before the server answered.

    ``request_sent`` is False when the timeout came before the request left the client
    (connecting, or waiting for a pooled connection): the server cannot have seen it.
    """

    def __init__(self, *args: object, request_sent: bool = True) -> None:
        super().__init__(*args)
        self.request_sent = request_sent


class InvalidResponseError(SandfortSDKError):
    """A successful HTTP response did not carry the expected envelope or payload.

    ``request_id`` is the ``x-request-id`` of a stream response whose event was malformed
    (``None`` elsewhere, or when the response had no such header).
    """

    def __init__(self, *args: object, request_id: str | None = None) -> None:
        super().__init__(*args)
        self.request_id = request_id


class SandboxTimeoutError(SandfortSDKError):
    """The sandbox did not reach ``started`` within the wait budget.

    ``sandbox_id`` and ``state`` (the last state seen) let the caller clean up: the sandbox
    exists server-side and keeps running until it is deleted. Both are ``None`` when the
    raise site had no sandbox to name (e.g. a snapshot wait).

    ``deleted`` is True exactly when the create-timeout cleanup deleted the sandbox the call
    made (the message then says it "was deleted" and ``sandbox_id`` names it); False otherwise,
    so an adapter need not parse the message.
    """

    def __init__(
        self,
        *args: object,
        sandbox_id: str | None = None,
        state: str | None = None,
        deleted: bool = False,
    ) -> None:
        super().__init__(*args)
        self.sandbox_id = sandbox_id
        self.state = state
        self.deleted = deleted


def _rebuild_failed(
    cls: "type[SandboxFailedError]", args: tuple[Any, ...], state: dict[str, Any]
) -> "SandboxFailedError":
    """Recreate a :class:`SandboxFailedError` without calling its keyword-only ``__init__``."""
    exc = cls.__new__(cls, *args)
    BaseException.__init__(exc, *args)
    exc.__dict__.update(state)
    return exc


class SandboxFailedError(SandfortSDKError):
    """The sandbox settled in a state that can never become ``started``.

    ``request_id`` is the ``x-request-id`` of the reply that showed that state (``None`` when
    the raise site had no reply); quote it when reporting the failure.

    ``exc.message`` (also ``args[0]``) never contains the code. Only ``str(exc)`` composes
    ``"<message> [<error_code>]"`` when the code is set (placed before a trailing
    `` (request id ...)``), so a logged failure keeps its code. With ``request_id`` set,
    ``str(exc)`` ends with `` (request id <id>)``, unless ``message`` already names that id
    (a caller that added it there); the id is mentioned once.
    """

    code = "SANDBOX_FAILED"

    def __init__(
        self,
        message: str,
        *,
        sandbox_id: str,
        state: str,
        request_id: str | None = None,
        error_reason: str | None = None,
        deleted: bool = False,
        error_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message  # the text without the " [code]" suffix that ``str()`` adds
        self.sandbox_id = sandbox_id
        self.state = state
        self.request_id = request_id
        self.error_reason = error_reason
        self.error_code = error_code  # the sandbox's machine-readable code, e.g. "timeout"
        self.deleted = deleted  # True when ``create_sandbox`` deleted the failed sandbox

    def __reduce__(self) -> tuple[Any, ...]:
        """Pickle and copy by state: ``__init__`` takes keyword-only arguments, which the
        default ``(cls, args)`` rebuild cannot supply. Subclasses inherit this."""
        return (_rebuild_failed, (type(self), self.args, dict(self.__dict__)))

    def __str__(self) -> str:
        text = self.message
        if self.error_code:
            tail = _REQUEST_ID_TAIL.search(text)
            cut = tail.start() if tail else len(text)
            text = f"{text[:cut]} [{self.error_code}]{text[cut:]}"
        return text + request_id_tail(text, self.request_id)

    def as_deleted(self) -> "SandboxFailedError":
        """The same failure, marked (and worded) as followed by a delete of the sandbox."""
        return type(self)(
            f"{self.message} (the failed sandbox was deleted)",
            sandbox_id=self.sandbox_id,
            state=self.state,
            request_id=self.request_id,
            error_reason=self.error_reason,
            deleted=True,
            error_code=self.error_code,
        )


class SandboxDestroyedError(SandboxFailedError):
    """The sandbox is ``destroyed``: it was deleted, so it can never become ``started``.

    Raised, for example, when a keyed create is replayed with ``wait`` after the sandbox it made
    was deleted. ``state`` is ``"destroyed"``; ``error_code`` is ``None`` unless the record kept
    the code of a failure from before the delete. ``except SandboxFailedError`` still catches it.
    """


class AmbiguousSandboxName(SandfortSDKError):
    """Several live sandboxes carry the name given to ``get``; pass an id (``sbx_...``).

    ``candidates`` holds ``(sandbox_id, state)`` pairs of the sandboxes that tie.
    """

    def __init__(self, name: str, candidates: tuple[tuple[str, str], ...]) -> None:
        listing = ", ".join(f"{sandbox_id} ({state})" for sandbox_id, state in candidates)
        super().__init__(f"several sandboxes are named '{name}': {listing}")
        self.name = name
        self.candidates = candidates


class ApiError(SandfortSDKError):
    """An error envelope returned by the server; subclasses map known codes.

    ``details`` is always a dict (``{}`` when the server sent none). ``has_details`` is True only
    when the server sent a non-empty ``details`` object, so a stream error event without details
    can be told apart from one that carried some.

    ``str(exc)`` is ``message``, ending with `` (request id <id>)`` when ``request_id`` is set
    (``message`` itself never carries it).
    """

    default_code: ClassVar[str] = "API_ERROR"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or type(self).default_code
        self.status_code = status_code
        self.details: dict[str, Any] = details or {}  # always a dict, ``{}`` when absent
        self.has_details = bool(details)  # False when the server sent no (or empty) details
        self.request_id = request_id

    def __str__(self) -> str:
        return self.message + request_id_tail(self.message, self.request_id)


class ValidationFailed(ApiError):
    default_code = "VALIDATION_ERROR"


class IdempotencyMismatch(ValidationFailed):
    """An ``Idempotency-Key`` was reused with other arguments (422 ``IDEMPOTENCY_MISMATCH``)."""

    default_code = "IDEMPOTENCY_MISMATCH"


class Unauthorized(ApiError):
    default_code = "UNAUTHORIZED"


class Forbidden(ApiError):
    default_code = "FORBIDDEN"


class NotFound(ApiError):
    default_code = "NOT_FOUND"

    # Typed like ``NoContainer.state`` so that ``except CONTEXT_GONE_ERRORS as exc`` can read
    # ``exc.state`` under a strict type checker; a not-found answer carries no sandbox state.
    state: str | None = None


class Conflict(ApiError):
    default_code = "CONFLICT"


class NameTaken(Conflict):
    """409 ``name_taken``: a sandbox with that name already exists in the org."""


class ReadOnlyPath(Conflict):
    """409 ``READ_ONLY_PATH``: a write into a read-only mount (a volume mounted read-only).

    ``details["path"]`` names the refused path when the server reports it.
    """

    default_code = "READ_ONLY_PATH"


class NoContainer(Conflict):
    """409 ``no_container``: the sandbox has no container (it is stopped or deleted).

    ``state`` is the sandbox state the server reported in ``details["state"]``, else ``None``.
    """

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        state = self.details.get("state")
        self.state: str | None = state if isinstance(state, str) else None


class InvalidState(ApiError):
    default_code = "INVALID_STATE"


class PayloadTooLarge(ApiError):
    default_code = "PAYLOAD_TOO_LARGE"


class Unprocessable(ApiError):
    default_code = "UNPROCESSABLE"


class QuotaExceeded(ApiError):
    default_code = "QUOTA_EXCEEDED"


class RateLimited(ApiError):
    default_code = "RATE_LIMITED"

    def __init__(
        self,
        message: str,
        *,
        retry_after_s: int = 1,
        retry_after_header_s: int | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.retry_after_s = retry_after_s
        self.retry_after_header_s = retry_after_header_s


class ServiceUnavailable(ApiError):
    """Any 503: ``NODE_UNAVAILABLE`` (the owning node cannot serve now), ``CAPACITY``, ...

    The request may succeed later. ``retry_after_s`` is the ``Retry-After`` delay the retry loop
    uses (1 if the header is absent or unusable). ``retry_after_header_s`` is the value the
    server really sent, ``None`` when it sent none: a caller that tells a person when to retry
    uses this one, so a default is never shown as the server's word.
    """

    default_code = "NODE_UNAVAILABLE"

    def __init__(
        self,
        message: str,
        *,
        retry_after_s: int = 1,
        retry_after_header_s: int | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.retry_after_s = retry_after_s
        self.retry_after_header_s = retry_after_header_s


class CapacityExceeded(ServiceUnavailable):
    default_code = "CAPACITY"


class InternalError(ApiError):
    default_code = "INTERNAL"


class Unsupported(ApiError):
    default_code = "UNSUPPORTED"


class DriverTimeout(ApiError):
    default_code = "DRIVER_TIMEOUT"


class DriverError(ApiError):
    default_code = "DRIVER_ERROR"


# A code context (or its sandbox) is gone: 409 ``no_container`` after a stop, 404 after a delete.
CONTEXT_GONE_ERRORS: tuple[type[NoContainer | NotFound], ...] = (NoContainer, NotFound)

_HTTP_UNAVAILABLE = 503
_CONFLICT_BY_REASON: dict[str, type[Conflict]] = {
    "name_taken": NameTaken,
    "no_container": NoContainer,
}
_BY_CODE: dict[str, type[ApiError]] = {
    cls.default_code: cls
    for cls in (
        ValidationFailed,
        IdempotencyMismatch,
        Unauthorized,
        Forbidden,
        NotFound,
        Conflict,
        ReadOnlyPath,
        InvalidState,
        PayloadTooLarge,
        Unprocessable,
        QuotaExceeded,
        RateLimited,
        ServiceUnavailable,
        CapacityExceeded,
        InternalError,
        Unsupported,
        DriverTimeout,
        DriverError,
    )
}


def error_for(
    code: str,
    message: str,
    *,
    status_code: int | None = None,
    details: dict[str, Any] | None = None,
    request_id: str | None = None,
    retry_after_s: int = 1,
    retry_after_header_s: int | None = None,
) -> ApiError:
    """Build the typed exception for a server error ``code`` (``ApiError`` if unknown).

    Any 503 is a :class:`ServiceUnavailable` (or a subclass such as ``CapacityExceeded``),
    whatever its code.
    """
    cls = _BY_CODE.get(code, ApiError)
    if cls is Conflict:
        cls = _CONFLICT_BY_REASON.get(str((details or {}).get("reason")), Conflict)
    if status_code == _HTTP_UNAVAILABLE and not issubclass(cls, ServiceUnavailable):
        cls = ServiceUnavailable
    kwargs: dict[str, Any] = {
        "code": code,
        "status_code": status_code,
        "details": details,
        "request_id": request_id,
    }
    if issubclass(cls, RateLimited | ServiceUnavailable):
        kwargs["retry_after_s"] = retry_after_s
        kwargs["retry_after_header_s"] = retry_after_header_s
    return cls(message, **kwargs)


def snapshot_pause_s(
    snapshot_id: str, state: str, deadline: float, now: float, poll_interval_s: float
) -> float:
    """Seconds to sleep before the next poll; raise once the deadline has passed."""
    remaining = deadline - now
    if remaining <= 0:
        raise SandboxTimeoutError(
            f"snapshot {snapshot_id} still {state} after the wait budget elapsed", state=state
        )
    return min(remaining, poll_interval_s)
