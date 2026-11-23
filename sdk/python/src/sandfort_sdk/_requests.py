"""Pure builders for request paths, query params and JSON bodies, and the retry policy (no I/O)."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from math import ceil
from typing import Any, Literal, NamedTuple
from urllib.parse import quote

import httpx

from sandfort_sdk._create_cleanup import MAX_LONG_POLL_S as MAX_LONG_POLL_S
from sandfort_sdk._create_cleanup import STATE_STARTED
from sandfort_sdk._create_cleanup import create_body as create_body
from sandfort_sdk._create_cleanup import is_ready as is_ready
from sandfort_sdk._create_cleanup import mounts_payload as mounts_payload
from sandfort_sdk._create_cleanup import poll_budget as poll_budget
from sandfort_sdk.exceptions import SandboxFailedError
from sandfort_sdk.exceptions import snapshot_pause_s as snapshot_pause_s
from sandfort_sdk.image import Image
from sandfort_sdk.models import Page
from sandfort_sdk.stop_causes import StopCause

SANDBOXES_PATH = "/v1/sandboxes"
SNAPSHOTS_PATH = "/v1/snapshots"
SNAPSHOT_FROM_SANDBOX_PATH = f"{SNAPSHOTS_PATH}/from-sandbox"
IMAGE_BUILDS_PATH = "/v1/images/builds"
VOLUMES_PATH = "/v1/volumes"
ISOLATION_PATH = "/v1/isolation"
SortOrder = Literal["asc", "desc"]  # the ``order`` of the list methods
DEFAULT_WAIT_TIMEOUT_S = 120.0
DEFAULT_POLL_INTERVAL_S = 0.5
DEFAULT_EXEC_TIMEOUT_S = 60
SNAPSHOT_READY = "ready"
SNAPSHOT_ERROR = "error"
IDEMPOTENCY_HEADER = "Idempotency-Key"
EXEC_KEY_MAX_LENGTH = 255
PRINTABLE_FIRST, PRINTABLE_LAST = 0x20, 0x7E  # space to tilde
DEFAULT_MAX_RETRIES = 2
QUOTA_EXCEEDED_CODE = "QUOTA_EXCEEDED"
RATE_LIMITED_CODE = "RATE_LIMITED"
IN_PROGRESS_REASON = "in_progress"
Outcome = httpx.Response | httpx.HTTPError
RETRY_AFTER_CAP_S = 30.0
BACKOFF_FIRST_S = 0.5
BACKOFF_CAP_S = 8.0
_REPEATABLE_METHODS = frozenset({"GET", "HEAD", "DELETE"})


@dataclass(frozen=True, slots=True)
class IdentifiedPage[T](Page[T]):
    """A :class:`Page` that also carries the ``x-request-id`` of the reply it came from."""

    request_id: str | None = None


def idempotency_headers(key: str | None) -> dict[str, str] | None:
    """The ``Idempotency-Key`` header for a create, or ``None`` when no key is given."""
    if key is None:
        return None
    if not key.strip():
        raise ValueError("'idempotency_key' must not be empty")
    return {IDEMPOTENCY_HEADER: key}


def checked_max_retries(max_retries: int) -> int:
    if max_retries < 0:
        raise ValueError("max_retries must be >= 0")
    return max_retries


def has_idempotency_key(method: str, headers: Mapping[str, str] | None) -> bool:
    """True for a POST that carries an ``Idempotency-Key`` header."""
    keys = {name.lower() for name in headers or {}}
    return method.upper() == "POST" and IDEMPOTENCY_HEADER.lower() in keys


def is_repeatable(method: str, headers: Mapping[str, str] | None) -> bool:
    """GET, HEAD and DELETE, or a POST carrying an ``Idempotency-Key``, are safe to resend."""
    return method.upper() in _REPEATABLE_METHODS or has_idempotency_key(method, headers)


def backoff_s(attempt: int) -> float:
    """Pause before resending after the ``attempt``-th (0-based) 503 or transport error."""
    return min(BACKOFF_FIRST_S * (1 << attempt), BACKOFF_CAP_S)


def jittered_s(delay_s: float, rand: float) -> float:
    """Full jitter: between half and all of ``delay_s``; ``rand`` is a draw from [0, 1]."""
    return delay_s * (0.5 + 0.5 * min(max(rand, 0.0), 1.0))


def parse_retry_after_header(value: str | None, now: datetime | None = None) -> int | None:
    """Seconds from a ``Retry-After`` value: delta-seconds or an HTTP-date; ``None`` when the
    header is absent or unusable.

    A date in the past gives 0; a date is rounded up to whole seconds.
    """
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        moment = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return max(0, ceil((moment - (now or datetime.now(UTC))).total_seconds()))


def parse_retry_after(value: str | None, now: datetime | None = None) -> int:
    """:func:`parse_retry_after_header`, with 1 when the header is absent or unusable (the
    delay the retry loop needs)."""
    seconds = parse_retry_after_header(value, now)
    return 1 if seconds is None else seconds


def rate_limit_pause_s(retry_after_s: int) -> float:
    return float(min(max(retry_after_s, 0), RETRY_AFTER_CAP_S))


def sandbox_path(sandbox_id: str, suffix: str = "") -> str:
    return f"{SANDBOXES_PATH}/{quote(sandbox_id, safe='')}{suffix}"


def toolbox_path(sandbox_id: str, tail: str) -> str:
    return sandbox_path(sandbox_id, f"/toolbox/process/{tail}")


def segment(value: str) -> str:
    """One URL path segment, percent-encoded (ids never get to add path separators)."""
    return quote(value, safe="")


def area_path(sandbox_id: str, area: str, tail: str = "") -> str:
    """Path under ``/toolbox/{area}`` (``fs``, ``git``, ``pty``)."""
    return sandbox_path(sandbox_id, f"/toolbox/{area}{tail}")


def session_path(sandbox_id: str, session_id: str | None = None) -> str:
    suffix = "" if session_id is None else f"/{segment(session_id)}"
    return toolbox_path(sandbox_id, f"sessions{suffix}")


def deletable_session_path(sandbox_id: str, session_id: str) -> str:
    """Path of one session for a delete; a blank id is refused (it would address the list)."""
    if not session_id.strip():
        raise ValueError("'session_id' must not be empty")
    return session_path(sandbox_id, session_id)


def command_path(sandbox_id: str, session_id: str, command_id: str, tail: str = "") -> str:
    return f"{session_path(sandbox_id, session_id)}/commands/{segment(command_id)}{tail}"


def session_create_body(cwd: str | None, env: dict[str, str] | None) -> dict[str, Any]:
    body: dict[str, Any] = {"cwd": cwd, "env": env}
    return {key: value for key, value in body.items() if value is not None}


def session_command_body(command: str, *, run_async: bool, timeout_s: int) -> dict[str, Any]:
    if not command.strip():
        raise ValueError("'command' must not be empty")
    return {"command": command, "mode": "async" if run_async else "sync", "timeout_s": timeout_s}


def log_params(offset: int, limit: int | None) -> dict[str, Any]:
    if offset < 0:
        raise ValueError("offset must be >= 0")
    params: dict[str, Any] = {"offset": offset, "limit": limit}
    return {key: value for key, value in params.items() if value is not None}


def page_params(cursor: str | None, limit: int | None) -> dict[str, Any]:
    return list_params(None, None, cursor, limit)


def snapshot_path(snapshot_id: str) -> str:
    return f"{SNAPSHOTS_PATH}/{segment(snapshot_id)}"


def build_logs_path(snapshot_id: str) -> str:
    return f"{IMAGE_BUILDS_PATH}/{segment(snapshot_id)}/logs"


def volume_path(volume_id: str) -> str:
    return f"{VOLUMES_PATH}/{segment(volume_id)}"


def _with_name(body: dict[str, Any], name: str | None) -> dict[str, Any]:
    return body if name is None else {**body, "name": name}


def _with_labels(body: dict[str, Any], labels: dict[str, str] | None) -> dict[str, Any]:
    return body if not labels else {**body, "labels": labels}


def snapshot_register_body(
    image: str, name: str | None, labels: dict[str, str] | None = None
) -> dict[str, Any]:
    if not image.strip():
        raise ValueError("'image' must not be empty")
    return _with_labels(_with_name({"image": image}, name), labels)


def snapshot_from_sandbox_body(
    sandbox_id: str, name: str, labels: dict[str, str] | None = None
) -> dict[str, Any]:
    if not sandbox_id.strip() or not name.strip():
        raise ValueError("'sandbox_id' and 'name' must not be empty")
    return _with_labels({"sandbox_id": sandbox_id, "name": name}, labels)


def image_build_body(spec: Image | Mapping[str, Any], name: str | None) -> dict[str, Any]:
    """``spec`` is a DSL :class:`Image` or a raw mapping already in the wire form."""
    payload = spec.serialize() if isinstance(spec, Image) else dict(spec)
    return _with_name({"spec": payload}, name)


def volume_create_body(name: str) -> dict[str, Any]:
    if not name.strip():
        raise ValueError("'name' must not be empty")
    return {"name": name}


def list_params(
    state: str | None,
    labels: dict[str, str] | None,
    cursor: str | None,
    limit: int | None,
    include_destroyed: bool = False,
    order: SortOrder | None = None,
    stop_cause: StopCause | None = None,
) -> dict[str, Any]:
    """Query params of a sandbox list; every value that is ``None`` is left out."""
    params: dict[str, Any] = {
        "state": state,
        "cursor": cursor,
        "limit": limit,
        "order": order,
        "stop_cause": stop_cause,
    }
    if include_destroyed:
        params["include_destroyed"] = "true"
    if labels:
        params["label"] = [f"{key}={value}" for key, value in labels.items()]
    return {key: value for key, value in params.items() if value is not None}


def wait_params(timeout_s: float) -> dict[str, Any]:
    return {"wait_for": STATE_STARTED, "timeout_s": timeout_s}


def argv_from_command(
    command: str | Sequence[str] | None, argv: list[str] | None
) -> tuple[str | None, list[str] | None]:
    """A list or tuple ``command`` is an argv: it is sent as ``argv``, not as a shell string.

    Passing it together with ``argv`` is a ``ValueError``, like giving both ``command`` and
    ``argv``; an empty one or one with a non-string element is a ``ValueError`` too.
    """
    if command is None or isinstance(command, str):
        return command, argv
    if argv is not None:
        raise ValueError("provide exactly one of 'command' or 'argv'")
    words = list(command)
    if not words or not all(isinstance(word, str) for word in words):
        raise ValueError("'command' as a list must be a non-empty list of strings (an argv)")
    return None, words


def exec_idempotency_headers(key: str | None) -> dict[str, str] | None:
    """The ``Idempotency-Key`` header of an exec, or ``None`` when no key is given.

    The key is 1 to 255 printable ASCII characters (space to ``~``) without a leading or
    trailing space, which HTTP would drop; anything else is a ``ValueError`` before any request.
    """
    if key is None:
        return None
    if not 1 <= len(key) <= EXEC_KEY_MAX_LENGTH:
        raise ValueError(f"'idempotency_key' must be 1 to {EXEC_KEY_MAX_LENGTH} characters")
    if not all(PRINTABLE_FIRST <= ord(ch) <= PRINTABLE_LAST for ch in key):
        raise ValueError("'idempotency_key' must be printable ASCII")
    if key != key.strip(" "):
        raise ValueError("'idempotency_key' must not start or end with a space")
    return {IDEMPOTENCY_HEADER: key}


def exec_body(
    *,
    command: str | Sequence[str] | None,
    argv: list[str] | None,
    cwd: str | None,
    env: dict[str, str] | None,
    timeout_s: int,
    stdin: str | None,
) -> dict[str, Any]:
    command, argv = argv_from_command(command, argv)
    if (command is None) == (argv is None):
        raise ValueError("provide exactly one of 'command' or 'argv'")
    body: dict[str, Any] = {
        "command": command,
        "argv": argv,
        "cwd": cwd,
        "env": env,
        "stdin": stdin,
        "timeout_s": timeout_s,
    }
    return {key: value for key, value in body.items() if value is not None}


def code_run_body(
    *,
    language: str,
    code: str,
    argv: list[str] | None,
    env: dict[str, str] | None,
    timeout_s: int,
    cwd: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "language": language,
        "code": code,
        "argv": argv,
        "cwd": cwd,
        "env": env,
        "timeout_s": timeout_s,
    }
    return {key: value for key, value in body.items() if value is not None}


def snapshot_is_ready(snapshot_id: str, state: str, sandbox_id: str) -> bool:
    """True once ready; raise if the snapshot settled in ``error``."""
    if state == SNAPSHOT_READY:
        return True
    if state == SNAPSHOT_ERROR:
        raise SandboxFailedError(
            f"snapshot {snapshot_id} of sandbox {sandbox_id} is {state}",
            sandbox_id=sandbox_id,
            state=state,
        )
    return False


def error_fields(response: httpx.Response) -> tuple[str, str]:
    """The envelope ``error.code`` and ``error.details.reason`` ("" when absent)."""
    try:
        body = response.json()
    except ValueError:
        return "", ""
    error = body.get("error") if isinstance(body, dict) else None
    if not isinstance(error, dict):
        return "", ""
    details = error.get("details")
    reason = details.get("reason") if isinstance(details, dict) else None
    return str(error.get("code") or ""), str(reason or "")


# Failures that leave no response behind; anything else (bad URL, redirects) is final.
RETRYABLE_ERRORS = (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError)


def retry_pause(
    outcome: Outcome,
    attempt: int,
    rand: Callable[[], float],
    *,
    keyed_post: bool,
    repeatable: bool = True,
    retry_timeouts: bool = True,
) -> float | None:
    """Seconds to wait before resending, or ``None`` when ``outcome`` is final.

    503 and transport errors back off with full jitter (a timeout only if ``retry_timeouts``);
    a 503 that carries ``Retry-After`` waits at least that long, capped at
    ``RETRY_AFTER_CAP_S``. A 429 waits ``Retry-After`` (seconds or an HTTP-date), except
    ``QUOTA_EXCEEDED_CODE``: a quota does not free itself. A 409 ``in_progress`` is resent only
    for a keyed POST (the first create is still running). A call that is not ``repeatable`` is
    resent only after a 429 ``RATE_LIMITED``: the server did not process that request.
    """
    if isinstance(outcome, httpx.HTTPError):
        timed_out = isinstance(outcome, httpx.TimeoutException)
        retryable = repeatable and isinstance(outcome, RETRYABLE_ERRORS)
        retryable = retryable and (retry_timeouts or not timed_out)
        return jittered_s(backoff_s(attempt), rand()) if retryable else None
    status = outcome.status_code
    if status == httpx.codes.TOO_MANY_REQUESTS:
        code = error_fields(outcome)[0]
        if code == QUOTA_EXCEEDED_CODE or not (repeatable or code == RATE_LIMITED_CODE):
            return None
        return rate_limit_pause_s(parse_retry_after(outcome.headers.get("Retry-After")))
    if status == httpx.codes.SERVICE_UNAVAILABLE and repeatable:
        own_s = jittered_s(backoff_s(attempt), rand())
        header = outcome.headers.get("Retry-After")
        if header is None:
            return own_s
        return max(own_s, rate_limit_pause_s(parse_retry_after(header)))
    if status == httpx.codes.CONFLICT and keyed_post:
        if error_fields(outcome)[1] == IN_PROGRESS_REASON:
            return jittered_s(backoff_s(attempt), rand())
    return None


# Floor of the timeout of an attempt whose deadline has (almost) passed.
MIN_ATTEMPT_TIMEOUT_S = 0.001


class CallPlan(NamedTuple):
    """How one transport call is timed and resent, fixed before its first attempt."""

    repeatable: bool
    keyed_post: bool
    retries: int
    timeout: float  # of every attempt, unless ``deadline`` is set
    deadline: float | None  # ``time.monotonic()`` value bounding all attempts and pauses
    retry_timeouts: bool


def replayable_body(content: Any) -> bool:
    """True when ``content`` can be sent again: none, or bytes held in memory (not a stream)."""
    return content is None or isinstance(content, bytes | bytearray | memoryview)


def plan_call(
    method: str,
    headers: Mapping[str, str] | None,
    content: Any,
    *,
    timeout: float,
    max_retries: int,
    read_timeout_s: float | None,
    deadline: float | None,
) -> CallPlan:
    """A one-shot ``content`` stream is never resent: a resend would send a short body."""
    return CallPlan(
        repeatable=is_repeatable(method, headers),
        keyed_post=has_idempotency_key(method, headers),
        retries=max_retries if replayable_body(content) else 0,
        timeout=read_timeout_s or timeout,
        deadline=deadline,
        retry_timeouts=read_timeout_s is None and deadline is None,
    )


def attempt_timeout(plan: CallPlan, now: float) -> float:
    """The timeout of the next attempt: the plan's, or the time left before its deadline."""
    if plan.deadline is None:
        return plan.timeout
    return max(plan.deadline - now, MIN_ATTEMPT_TIMEOUT_S)


def next_pause(
    plan: CallPlan, outcome: Outcome, attempt: int, rand: Callable[[], float], now: float
) -> float | None:
    """The pause before resending, or ``None``; one that would pass the deadline is not taken."""
    if attempt >= plan.retries:
        return None
    pause = retry_pause(
        outcome, attempt, rand, keyed_post=plan.keyed_post,
        repeatable=plan.repeatable, retry_timeouts=plan.retry_timeouts,
    )  # fmt: skip
    if pause is None or plan.deadline is None:
        return pause
    return pause if now + pause < plan.deadline else None
