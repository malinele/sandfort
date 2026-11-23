"""``login`` and the ``sandbox`` group (create, list, get, isolation, stop, start, reset, rm).

``sandbox delete`` is a hidden alias of ``sandbox rm``, ``sandbox ls`` of ``sandbox list``.
"""

import logging
import math
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, NoReturn
from urllib.parse import urlsplit

import httpx
import typer
from sandfort_sdk import (
    SANDBOX_STOP_CAUSE_AUTO_STOP,
    SANDBOX_STOP_CAUSE_CONTAINER_EXITED,
    SANDBOX_STOP_CAUSE_OOM_KILLED,
    SANDBOX_STOP_CAUSE_REQUESTED,
    SANDBOX_STOP_CAUSE_UNKNOWN,
    ApiError,
    Client,
    Resources,
    SandboxFailedError,
    SandboxInfo,
    SandfortSDKError,
    StopCause,
    VolumeMount,
    is_known_stop_cause,
)
from sandfort_sdk.exceptions import TransportError, request_id_tail

from sandfort_cli.config import (
    API_KEY_ENV,
    URL_SCHEMES,
    check_configured_key,
    open_client,
    save_profile,
    validate_base_url,
)
from sandfort_cli.login_key import (
    KEY_FILE_OPTION,
    KEY_FROM_STDIN_NOTE,
    KEY_PROMPT_HINT,
    KEY_STDIN_OPTION,
    key_from_stdin,
    key_without_prompt,
    no_key_message,
    no_key_source_error,
    reads_key_from_stdin,
    reject_key_stdin_conflict,
    stdin_not_text_error,
)
from sandfort_cli.mounts import (
    MOUNT_HELP,
    MOUNT_SHAPE,
    VOLUMES_FIELD,
    mount_lines,
    name_mount_option,
    path_problem,
    source_problem,
    split_mount_mode,
)
from sandfort_cli.mounts import render_sandbox as render_mounted_sandbox
from sandfort_cli.number_parsing import (
    PLAIN_DECIMAL_RE,
    PLAIN_DIGITS_HINT,
    PLUS_SIGN,
    SURROUNDING_SPACES_HINT,
    UNDERSCORE_HINT,
    misleads_as_digits,
    parse_plain_decimal,
    whole_number_hints,
)
from sandfort_cli.output import (
    EXIT_FAILURE,
    LABELS_FIELD,
    AppState,
    CliError,
    ErrorExtras,
    _json_errors,
    app_state,
    clean_hint,
    clean_strings,
    cli_errors,
    describe_error,
    error_payload,
    is_blank,
    print_fields,
    print_json,
    reject_empty_name,
    reject_empty_option,
    reject_empty_options,
    render_isolation,
    render_message,
    render_sandboxes,
    sandbox_fields,
    sandbox_payload,
    shown,
)
from sandfort_cli.refs import SandboxNameNotFound, resolve_live_sandbox_id, resolve_sandbox_id
from sandfort_cli.sanitise import (
    BARE_USERINFO_RE,
    BRACKETED_AUTHORITY_RE,
    ELLIPSIS,
    MASK,
    MAX_ECHOED_URL_CHARS,
    MAX_ECHOED_VALUE_CHARS,
    MAX_HOST_CHARS,
    MAX_RAW_CHARS,
    MAX_RELAYED_CHARS,
    MAX_RELAYED_SCOPES,
    PORT_MAX,
    USAGE_MESSAGE_CHARS,
    USERINFO_ACROSS_BREAKS_RE,
    USERINFO_ANYWHERE_RE,
    USERINFO_RE,
    caller_key,
    drop_partial_url,
    echo_url,
    endpoint_url,
    redact_reason,
    sanitise_text,
)
from sandfort_cli.volume_refs import MOUNT_OPTION, resolve_volume_refs

# The sanitiser lives in sanitise.py and the number helpers in number_parsing.py; these names keep
# their old import path from here.
__all__ = [
    "BARE_USERINFO_RE",
    "MASK",
    "MAX_ECHOED_URL_CHARS",
    "MAX_RELAYED_CHARS",
    "PLAIN_DECIMAL_RE",
    "PLAIN_DIGITS_HINT",
    "PLUS_SIGN",
    "SURROUNDING_SPACES_HINT",
    "UNDERSCORE_HINT",
    "USERINFO_ACROSS_BREAKS_RE",
    "USERINFO_ANYWHERE_RE",
    "drop_partial_url",
    "misleads_as_digits",
]

# The --help epilog of the root app and of every group that prints the json error.
JSON_ERROR_EPILOG = (
    'With --json a failure prints one {"error": {...}} object with code, message, details and '
    'request_id. "source": "client" means no request of the failed step reached the server '
    "(connect failure, bad local input); without it a request may have reached it."
)
sandbox_app = typer.Typer(
    name="sandbox", help="Manage sandboxes.", epilog=JSON_ERROR_EPILOG, no_args_is_help=True
)

# The ``<...>`` usage placeholders are rendered by ``output.AngleArgument``, installed when
# ``sandfort_cli.output`` is imported (every command module imports it).
SANDBOX_METAVAR = "<sandbox>"
NAME_METAVAR = "<name>"
INTEGER_METAVAR = "INTEGER"

SandboxId = Annotated[str, typer.Argument(metavar=SANDBOX_METAVAR, help="Sandbox id or name.")]
NOT_FOUND_CODE = "NOT_FOUND"


@contextmanager
def ref_errors(
    exit_code: int = EXIT_FAILURE,
    sandbox_ref: str | None = None,
    extras: ErrorExtras | None = None,
) -> Iterator[None]:
    """:func:`cli_errors`, with a sandbox name that matches no live sandbox reported under
    ``--json`` with the not-found code of a missing id (``NOT_FOUND``), so a script branches on
    one code. There is no ``"source"`` field: the name lookup (a list or get call) did reach the
    server, and ``"source": "client"`` means no request of the failed step did. The text line
    and the exit code are unchanged. ``extras`` joins the one json error document (see
    :func:`cli_errors`).
    """
    with cli_errors(exit_code, sandbox_ref, extras):
        try:
            yield
        except SandboxNameNotFound as exc:
            if not _json_errors.get():
                raise
            payload = error_payload(exc)
            payload["error"]["code"] = NOT_FOUND_CODE
            print_json({**payload, **(extras() if extras else {})})
            raise typer.Exit(exit_code) from None


def range_text(low: int | None, high: int | None) -> str:
    """The bound of a whole number as the usage error words it (empty when there is none)."""
    if low is not None and high is not None:
        return f" from {low} to {high}"
    if low is not None:
        return " greater than 0" if low == 1 else f" of at least {low}"
    return "" if high is None else f" of at most {high}"


# A whole number as a user types it: ASCII digits, an optional leading minus (the range check
# decides whether a negative value is allowed), nothing else.
WHOLE_NUMBER_RE = re.compile(r"-?[0-9]+")


def parse_whole_number(
    raw: str, param_hint: str, *, high: int | None = None, low: int | None = 1
) -> int:
    """``raw`` as a whole number from ``low`` (default 1; ``None``: no lower bound) to ``high``
    (``None``: no upper bound); any other value is the unified usage error (``Invalid value for
    X: ...``, exit 2). Only plain ASCII digits with an optional leading minus are a number:
    ``+5``, `` 5 ``, ``1_000`` and non-ASCII digits are refused although ``int()`` takes them."""
    value: int | None = None
    if WHOLE_NUMBER_RE.fullmatch(raw):
        try:
            value = int(raw)
        except ValueError:  # beyond int()'s digit limit
            value = None
    below = value is not None and low is not None and value < low
    above = value is not None and high is not None and value > high
    if value is None or below or above:
        raise typer.BadParameter(
            f"must be a whole number{range_text(low, high)}, got {echo_value(raw)}"
            f"{whole_number_hints(raw)}",
            param_hint=param_hint,
        )
    return value


def parse_optional_whole_number(
    raw: str | None, param_hint: str, *, high: int | None = None, low: int | None = None
) -> int | None:
    """:func:`parse_whole_number` for an option that may be absent (``None``); here ``low``
    defaults to no lower bound, which is what a plain integer option accepts."""
    return None if raw is None else parse_whole_number(raw, param_hint, high=high, low=low)


ERROR_STATE = "error"
STATUS_PATH = "/v1/status"
SANDBOXES_PATH = "/v1/sandboxes"
PROBE_TIMEOUT_S = 5.0
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_REDIRECT_MIN = 300
HTTP_REDIRECT_MAX = 400
HTTP_SERVER_ERROR_MIN = 500
HTTP_REQUEST_TIMEOUT = 408
HTTP_TOO_MANY_REQUESTS = 429
# Answers that say "try again" like the 5xx family does.
RETRY_STATUSES = frozenset({HTTP_REQUEST_TIMEOUT, HTTP_TOO_MANY_REQUESTS})
EXIT_USAGE = 2
USAGE_ERROR_CODE = "USAGE_ERROR"
SCHEME_RE = re.compile(r"^(https?)(?=://)", re.IGNORECASE)
REDIRECT_HINT = (
    "redirects are not followed; use the final url (for example the https one) as the base url"
)
KEY_NOT_VERIFIED_NOTE = (
    "api key: NOT verified (a wrong key shows on the next command; "
    "use --verify-key to check it now)"
)
# Errors raised before any byte of the request is written.
NEVER_SENT_ERRORS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.UnsupportedProtocol,
    httpx.InvalidURL,
)
USERINFO_REMOVED_NOTE = (
    "note: userinfo was removed from the saved base url (it would replace the api key "
    "as a Basic authorization header)"
)
REQUEST_ID_HEADER = "x-request-id"
STRICT_FLAG = "--require-verified"
KEY_VERIFIED = "verified"
KEY_LIMITED_SCOPE = "limited-scope"
KEY_NOT_CHECKED = "not-checked"
BUILD_PREFIX_LEN = 12
WAIT_HELP = "With --wait: give up after this many seconds (must be > 0; default: the SDK's)."


class IsolationTier(StrEnum):
    """The tiers ``--isolation`` accepts; the server decides which of them it offers."""

    CONTAINER = "container"
    GVISOR = "gvisor"
    MICROVM = "microvm"


class ListOrder(StrEnum):
    """The orders ``sandbox list --order`` accepts (by creation time)."""

    ASC = "asc"
    DESC = "desc"


STOP_CAUSE_OPTION = "--stop-cause"
STOP_CAUSES = (
    SANDBOX_STOP_CAUSE_REQUESTED,
    SANDBOX_STOP_CAUSE_AUTO_STOP,
    SANDBOX_STOP_CAUSE_CONTAINER_EXITED,
    SANDBOX_STOP_CAUSE_OOM_KILLED,
    SANDBOX_STOP_CAUSE_UNKNOWN,
)
STOP_CAUSE_METAVAR = "CAUSE"


def check_stop_cause(value: str | None) -> StopCause | None:
    """``--stop-cause`` checked against the SDK's five values (exit 2 before any request).

    ``None`` (not given) passes. A blank or unknown value is a usage error that names the
    accepted values.
    """
    if value is None:
        return None
    if is_known_stop_cause(value):
        return value
    raise typer.BadParameter(
        f"{stop_cause_reason(value)}; expected one of: {', '.join(STOP_CAUSES)}",
        param_hint=STOP_CAUSE_OPTION,
    )


def stop_cause_reason(value: str) -> str:
    """Why ``value`` is not a stop cause; a hint when whitespace or letter case is the fault."""
    if is_blank(value):
        return "must not be empty"
    if value != value.strip() and is_known_stop_cause(value.strip()):
        return "unknown stop cause: surrounding whitespace is not allowed"
    unknown = f"unknown stop cause {echo_value(value)}"
    return f"{unknown}: values are lowercase" if is_known_stop_cause(value.lower()) else unknown


def single_value[T](values: list[T] | None, option: str) -> T | None:
    """The one value of an option that takes a single value; ``None`` when it was not given.

    Given more than once it is a usage error naming the option (exit 2, before any request),
    like a repeated KEY in ``--label``: it is never silently last-wins.
    """
    if not values:
        return None
    if len(values) > 1:
        raise typer.BadParameter("is given more than once", param_hint=option)
    return values[0]


def parse_mount(value: str) -> VolumeMount:
    """``VOLUME:PATH[:ro|rw]`` (split at the first colon) as a :class:`VolumeMount`.

    ``VOLUME`` is a ``vol_`` id or a volume name; the name is resolved later, by the create
    command. A blank value is the shared ``must not be empty`` usage error; a value without the
    colon, with a blank volume or path, or with a mode-like but unknown mode is a usage error
    naming the expected shape (exit 2).
    """
    reject_empty_name(value, MOUNT_OPTION)
    volume_id, separator, rest = value.partition(":")
    parsed = split_mount_mode(rest)
    if separator and not is_blank(volume_id):
        problem = source_problem(volume_id, rest) or path_problem(rest, parsed)
        if problem is not None:
            raise typer.BadParameter(
                f"invalid mount {echo_value(value)}; {problem}; expected {MOUNT_SHAPE}",
                param_hint=MOUNT_OPTION,
            )
    if not separator or is_blank(volume_id) or parsed is None or is_blank(parsed[0]):
        raise typer.BadParameter(
            f"invalid mount {echo_value(value)}; expected {MOUNT_SHAPE}", param_hint=MOUNT_OPTION
        )
    return VolumeMount(volume_id.strip(), parsed[0].strip(), parsed[1])


def echo_value(value: str) -> str:
    """``value`` as a usage message may echo it (quoted): sanitised, cut to its own cap.

    The cut is on the value, not on the message, so the reason that follows it is never lost.
    """
    shown = sanitise_text(value, api_key=caller_key(), limit=MAX_ECHOED_VALUE_CHARS)
    if not shown and len(value) > MAX_RAW_CHARS:
        shown = ELLIPSIS
    return repr(shown)


def parse_pairs(values: list[str] | None, kind: str) -> dict[str, str] | None:
    """Repeated ``KEY=VALUE`` options (``--label``, ``--env``, the list ``--label``; split at
    the first ``=``) as a dict; ``None`` if none.

    A blank value is legal; a blank key (:func:`is_blank`: also one made only of invisible or
    control characters) is a usage error, and so is a key given twice, compared after
    stripping (the key that is sent), in any of these KEY=VALUE options. It is never silently
    last-wins."""
    if not values:
        return None
    pairs: dict[str, str] = {}
    for value in values:
        key, separator, item = value.partition("=")
        if separator and key and is_blank(key):
            raise typer.BadParameter(
                f"invalid {kind} {echo_value(value)}; {kind} key is blank or invisible",
                param_hint=f"--{kind}",
            )
        if not separator or is_blank(key):
            raise typer.BadParameter(
                f"invalid {kind} {echo_value(value)}; expected KEY=VALUE", param_hint=f"--{kind}"
            )
        name = key.strip()
        if name in pairs:
            raise typer.BadParameter(
                f"{kind} key {echo_value(name)} is given more than once", param_hint=f"--{kind}"
            )
        pairs[name] = item
    return pairs


def build_resources(
    cpu_millicores: int | None, memory_mib: int | None, disk_gib: int | None
) -> Resources | None:
    """``Resources`` with SDK defaults for the unset values; ``None`` when none was given."""
    if cpu_millicores is None and memory_mib is None and disk_gib is None:
        return None
    defaults = Resources()
    return Resources(
        cpu_millicores=defaults.cpu_millicores if cpu_millicores is None else cpu_millicores,
        memory_mib=defaults.memory_mib if memory_mib is None else memory_mib,
        disk_gib=defaults.disk_gib if disk_gib is None else disk_gib,
    )


def report_immediate_error(
    state: AppState, info: SandboxInfo, request_id: str | None = None
) -> None:
    """Report a create (without ``--wait``) whose reply is already in state ``error``; exit 1.

    The failure line is the one the ``--wait`` path prints; the hint names ``--wait`` and
    ``sandbox rm``. With ``--json`` the error object (with ``error.hint``) goes to stdout.
    ``request_id`` is the create reply's (``Sandbox.request_id``); the failure carries it.
    """
    reason = f": {info.error_reason}" if info.error_reason else ""
    failed = SandboxFailedError(
        f"sandbox {info.id} is {info.state}{reason}",
        sandbox_id=info.id,
        state=info.state,
        request_id=request_id,
        error_reason=info.error_reason,
        error_code=info.error_code,
    )
    hint = (
        "the sandbox was kept; repeat the create with --wait to have it deleted on failure, "
        f"or delete it with: sandfort sandbox rm {info.id}"
    )
    if state.json_output:
        print_json(error_payload(failed, hint))
    else:
        typer.echo(f"error: {describe_error(failed)}", err=True)
        typer.echo(clean_hint(hint), err=True)
    raise typer.Exit(EXIT_FAILURE)


FAILED_START_STATES = frozenset({ERROR_STATE, "start_failed"})
DELETE_REASON_CHARS = 120


def with_note(failed: SandboxFailedError, note: str) -> SandboxFailedError:
    """``failed`` with ``(<note>)`` after its message; every other field is kept."""
    return type(failed)(
        f"{failed.message} ({note})",
        sandbox_id=failed.sandbox_id,
        state=failed.state,
        request_id=failed.request_id,
        error_reason=failed.error_reason,
        deleted=failed.deleted,
        error_code=failed.error_code,
    )


def delete_refusal(exc: SandfortSDKError) -> str:
    """Why a delete failed, as a short phrase (the server's message when it sent one)."""
    text = str(getattr(exc, "message", None) or exc).strip() or type(exc).__name__
    return text[:DELETE_REASON_CHARS]


def settle_failed_start(
    client: Client, failed: SandboxFailedError, *, keep: bool
) -> SandboxFailedError:
    """Mirror the SDK for a ``create --wait`` that ended in a failed start.

    A sandbox in the ``error`` (or ``start_failed``) state is deleted unless ``keep`` is set or
    the SDK already deleted it; the returned error says whether it was deleted or kept, and why
    (``--keep-on-failure`` or the refused delete), with the ``sandbox rm`` command to remove it.
    The id, state, reason, code and request id stay on the error, so ``--json`` carries them.
    """
    if failed.deleted or failed.state not in FAILED_START_STATES:
        return failed
    remove = f"delete it with: sandfort sandbox rm {failed.sandbox_id}"
    if keep:
        return with_note(failed, f"the failed sandbox was kept (--keep-on-failure); {remove}")
    try:
        client.delete(failed.sandbox_id)
    except SandfortSDKError as exc:
        why = f"the failed sandbox was kept: it could not be deleted ({delete_refusal(exc)})"
        return with_note(failed, f"{why}; {remove}")
    return failed.as_deleted()


WAIT_TIMEOUT_RANGE = "must be a finite number greater than 0"


def parse_wait_timeout(wait: bool, raw: str | None) -> float | None:
    """The ``--wait-timeout`` value as seconds; ``None`` when not given.

    The option is taken as text and converted here, so a value that is not a plain ASCII
    number gets the same usage error (exit 2, also under ``--json``) as ``nan``, ``inf``, zero
    and a negative number: it requires ``--wait`` and must be a finite number greater than 0.
    A refused value gets the whole-number options' hints (surrounding whitespace, characters
    that are not plain ASCII digits).
    """
    if raw is None:
        return None
    seconds = parse_plain_decimal(raw)
    out_of_range = not math.isfinite(seconds) or seconds <= 0
    hints = whole_number_hints(raw) if out_of_range else ""
    if not wait and out_of_range:
        raise typer.BadParameter(
            f"requires --wait, and {WAIT_TIMEOUT_RANGE}{hints}", param_hint="--wait-timeout"
        )
    if not wait:
        raise typer.BadParameter("requires --wait", param_hint="--wait-timeout")
    if out_of_range:
        raise typer.BadParameter(f"{WAIT_TIMEOUT_RANGE}{hints}", param_hint="--wait-timeout")
    return seconds


USERINFO_REMOVED_CONFIGURED_NOTE = (
    "note: userinfo was removed from the configured base url (it would replace the api key "
    "as a Basic authorization header)"
)
NAME_CHECK_LOGGER = "sandfort_sdk._create_cleanup"


class _QuietNameCheck(logging.Filter):
    """Keep the SDK's name pre-check warnings from printing a traceback on stderr.

    A name check that fails on a transport error is dropped (the create itself reports the
    same connect error cleanly); any other record loses only its traceback.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        info = record.exc_info
        if info is not None and isinstance(info[1], TransportError):
            return False
        record.exc_info = None
        record.exc_text = None
        return True


@contextmanager
def quiet_name_check() -> Iterator[None]:
    """Run a create with the name pre-check's logging stripped of tracebacks."""
    logger = logging.getLogger(NAME_CHECK_LOGGER)
    quiet = _QuietNameCheck()
    logger.addFilter(quiet)
    try:
        yield
    finally:
        logger.removeFilter(quiet)


def lower_scheme(url: str) -> str:
    """``url`` trimmed, with an ``HTTP``/``Https`` scheme in any case written in lowercase."""
    return SCHEME_RE.sub(lambda match: match.group(1).lower(), url.strip())


def strip_userinfo(url: str) -> str:
    """``url`` without its ``user:password@`` part (pattern based, like :func:`redact_url`)."""
    return USERINFO_RE.sub(r"\1", url)


def is_invalid_url(exc: Exception) -> bool:
    """True when ``exc`` means the url itself is unusable, so nothing was ever sent."""
    return isinstance(exc, httpx.InvalidURL | httpx.UnsupportedProtocol | ValueError)


def probe_failure(
    base_url: str,
    reason: str,
    *,
    never_sent: bool,
    redirected: bool = False,
    invalid: bool = False,
    api_key: str = "",
    strict: bool = False,
) -> CliError:
    """The login error for a base url that did not answer the status endpoint.

    With ``invalid`` (the url cannot be used, nothing was sent) it says the url is not valid
    instead. The url and the reason go through :func:`sanitise_text`: no control characters,
    no userinfo, masked query values and fragment, and the ``api_key`` masked, so a secret in
    the url never reaches stderr or the json error. With ``strict`` (``--require-verified``)
    the hint never offers ``--no-verify`` (it cannot be combined with the strict flag).
    """
    shown = echo_url(base_url, api_key)
    reason = sanitise_text(reason, base_url=base_url, api_key=api_key)
    if invalid:
        return CliError(
            f"base url {shown} is not a valid url ({reason}); nothing was sent, check the url",
            client=True,
        )
    unchecked = "" if strict else ", or use --no-verify to save it unchecked"
    hint = f"check the url{' and retry' if strict else ''}{unchecked}"
    if redirected:
        hint = f"{REDIRECT_HINT}{unchecked}"
    return CliError(
        f"base url {shown} did not answer the status endpoint ({STATUS_PATH}): {reason}; {hint}",
        client=never_sent,
    )


def request_never_sent(exc: Exception) -> bool:
    """True when ``exc`` means the request did not leave: a bad url or a connect failure."""
    if isinstance(exc, NEVER_SENT_ERRORS):
        return True
    return not isinstance(exc, httpx.HTTPError)


def probe_server(base_url: str, api_key: str = "", *, strict: bool = False) -> str:
    """One unauthenticated ``GET /v1/status``; the build prefix (or ``unreported``) on success.

    The request goes out without the url's userinfo. Raises :class:`CliError` for a connect
    failure, a url that cannot be parsed, a non-2xx answer or a body that is not the status
    document (a json object whose ``data`` carries a ``build_sha`` key).
    """
    try:
        reply = httpx.get(
            endpoint_url(base_url, STATUS_PATH), timeout=PROBE_TIMEOUT_S, follow_redirects=False
        )
    except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
        reason = str(exc) or type(exc).__name__
        raise probe_failure(
            base_url,
            reason,
            never_sent=request_never_sent(exc),
            invalid=is_invalid_url(exc),
            api_key=api_key,
            strict=strict,
        ) from None
    if not reply.is_success:
        raise probe_failure(
            base_url,
            f"HTTP {reply.status_code}",
            never_sent=False,
            redirected=is_redirect_status(reply.status_code),
            api_key=api_key,
            strict=strict,
        )
    try:
        body = reply.json()
    except (ValueError, RecursionError):  # not json, or nested so deeply that parsing gives up
        body = None
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict) or "build_sha" not in data:
        raise probe_failure(
            base_url,
            "the reply is not a status document",
            never_sent=False,
            api_key=api_key,
            strict=strict,
        )
    build_sha = data["build_sha"]
    if isinstance(build_sha, str):
        clean_sha = sanitise_text(build_sha, base_url=base_url, api_key=api_key)
        if clean_sha:
            return clean_sha[:BUILD_PREFIX_LEN]
    return "unreported"


def is_redirect_status(status_code: int) -> bool:
    """True for a 3xx answer (redirects are never followed by the probes)."""
    return HTTP_REDIRECT_MIN <= status_code < HTTP_REDIRECT_MAX


@dataclass(frozen=True)
class KeyCheck:
    """The outcome of a key check that did not fail the login.

    ``verified`` is the legacy json ``key_verified`` value (``True``, ``False`` or
    ``"limited-scope"``); ``status`` is the ``key_status`` string (``verified``,
    ``limited-scope`` or ``not-checked``).
    """

    note: str
    verified: bool | str
    status: str
    # Set when a check request was answered (``where`` names it); the scopes and request id are
    # the server's own (sanitised) and go into the json result of a limited-scope key.
    where: str = ""
    missing_scopes: tuple[str, ...] = ()
    request_id: str | None = None
    server_code: str | None = None
    # Missing scopes the server named beyond the relay cap (counted, not listed).
    scopes_beyond_cap: int = 0


@dataclass(frozen=True)
class ServerReply:
    """The server's error envelope (``success`` false) as far as the body carried it."""

    code: str | None
    message: str | None
    details: dict[str, Any]
    request_id: str | None


class KeyCheckError(CliError):
    """A failed key check; ``details`` (server code and request id) go into the json error."""

    def __init__(
        self,
        message: str,
        *,
        client: bool = False,
        request_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, client=client)
        self.request_id = request_id
        self.details: dict[str, Any] = details or {}


def text_or_none(value: object) -> str | None:
    """``value`` stripped when it is a non-blank string, else ``None``."""
    return value.strip() or None if isinstance(value, str) else None


def parse_server_reply(reply: httpx.Response) -> ServerReply | None:
    """The server's error envelope in ``reply``, or ``None`` when the body is not one.

    A body counts as the server's own when it is a json object with ``"success": false`` (a proxy
    or login page is not). The ``error`` fields are optional: absent ones come back as ``None``.
    """
    try:
        body = reply.json()
    except (ValueError, RecursionError):  # not json, or nested so deeply that parsing gives up
        return None
    if not isinstance(body, dict) or body.get("success") is not False:
        return None
    error = body.get("error")
    fields: dict[str, Any] = error if isinstance(error, dict) else {}
    details = fields.get("details")
    return ServerReply(
        code=text_or_none(fields.get("code")),
        message=text_or_none(fields.get("message")),
        details=details if isinstance(details, dict) else {},
        request_id=envelope_request_id(reply, body, fields),
    )


def envelope_request_id(
    reply: httpx.Response, body: dict[str, Any], fields: dict[str, Any]
) -> str | None:
    """The request id of an error envelope: the error's own, else the envelope ``meta``'s, else
    the ``x-request-id`` header of the response."""
    meta = body.get("meta")
    meta_id = text_or_none(meta.get("request_id")) if isinstance(meta, dict) else None
    return (
        text_or_none(fields.get("request_id"))
        or meta_id
        or text_or_none(reply.headers.get(REQUEST_ID_HEADER))
    )


def missing_scopes(server: ServerReply) -> list[str]:
    """The scope names in the envelope's ``details.missing_scopes`` (``[]`` when absent)."""
    scopes = server.details.get("missing_scopes")
    if not isinstance(scopes, list):
        return []
    return [scope for scope in scopes if isinstance(scope, str) and scope.strip()]


BEYOND_CAP_FIELD = "missing_scopes_beyond_cap"


def scopes_beyond_cap(server: ServerReply) -> int:
    """The count :func:`clean_reply` stored next to the relayed scopes (``0`` when absent)."""
    count = server.details.get(BEYOND_CAP_FIELD)
    return count if isinstance(count, int) and not isinstance(count, bool) and count > 0 else 0


def beyond_cap_note(count: int) -> str:
    """``, and N more`` for the text line of the scopes (empty when nothing was cut)."""
    return f", and {count} more" if count > 0 else ""


def clean_reply(server: ServerReply | None, base_url: str, api_key: str) -> ServerReply | None:
    """``server`` with the code, message, request id and every missing scope run through
    :func:`sanitise_text`; a field left empty by it counts as absent."""
    if server is None:
        return None

    def clean(value: str | None) -> str | None:
        if value is None:
            return None
        return sanitise_text(value, base_url=base_url, api_key=api_key) or None

    details = dict(server.details)
    if "missing_scopes" in details:
        named = missing_scopes(server)
        cleaned = (clean(scope) for scope in named[:MAX_RELAYED_SCOPES])
        details["missing_scopes"] = [scope for scope in cleaned if scope]
        details[BEYOND_CAP_FIELD] = max(0, len(named) - MAX_RELAYED_SCOPES)
    else:
        details.pop(BEYOND_CAP_FIELD, None)
    return ServerReply(
        code=clean(server.code),
        message=clean(server.message),
        details=details,
        request_id=clean(server.request_id),
    )


def server_said(server: ServerReply | None, base_url: str) -> str:
    """``; the server said CODE: message`` (url secrets masked), or ``""`` without either."""
    if server is None:
        return ""
    said = ": ".join(part for part in (server.code, server.message) if part)
    return f"; the server said {redact_reason(said, base_url)}" if said else ""


def error_details(server: ServerReply | None) -> dict[str, Any]:
    """The json ``details`` of a key-check error: the server code and request id, if sent."""
    if server is None:
        return {}
    pairs = (("server_code", server.code), ("request_id", server.request_id))
    return {key: value for key, value in pairs if value}


def forbidden_check(where: str, server: ServerReply | None) -> KeyCheck:
    """The 403 outcome: limited scope for the server's own envelope, else not checked."""
    if server is None:
        return KeyCheck(
            f"api key: NOT verified; the 403 answer ({where}) did not come from the server's "
            "API (the body is not its error envelope, for example a proxy or login page); "
            "the profile was saved anyway",
            False,
            KEY_NOT_CHECKED,
            where,
        )
    scopes = missing_scopes(server)
    beyond = scopes_beyond_cap(server)
    listed = f"{', '.join(scopes)}{beyond_cap_note(beyond)}"
    missing = f"; the server reports missing scope(s): {listed}" if scopes else ""
    text = (
        f"api key: the server answered 403 ({where}); the key is probably valid but "
        f"lacks the sandbox read scope{missing}"
    )
    text += request_id_tail(text, server.request_id)
    return KeyCheck(
        text,
        KEY_LIMITED_SCOPE,
        KEY_LIMITED_SCOPE,
        where,
        tuple(scopes),
        server.request_id,
        server.code,
        beyond,
    )


def strict_advice(step: str) -> str:
    """The advice of a failed check under ``--require-verified``: ``step`` (when it is not
    just a retry), then the strict flag as the one to drop. It never names ``--verify-key`` or
    ``--no-verify``: the user did not type the first and the second cannot be combined with
    the strict flag."""
    return f"{step}, or drop {STRICT_FLAG} if saving without the key check is acceptable"


def key_check_failure(
    status_code: int,
    where: str,
    base_url: str,
    server: ServerReply | None,
    api_key: str = "",
    *,
    strict: bool = False,
) -> KeyCheckError:
    """The error for a 401 or any other unexpected answer; names the server's code, message and
    request id when its envelope parsed. A 3xx gets the redirect hint; a 5xx, 408 or 429 the
    retry advice. With ``strict`` (``--require-verified``) the advice says retry, or drop the
    strict flag, instead of ``login without --verify-key``."""
    shown = echo_url(base_url, api_key)
    full_where = where + server_said(server, base_url)
    retry_helps = status_code >= HTTP_SERVER_ERROR_MIN or status_code in RETRY_STATUSES
    if status_code == HTTP_UNAUTHORIZED:
        text = f"server {shown} rejected the api key ({full_where}); the profile was not saved"
    elif is_redirect_status(status_code):
        advice = (
            strict_advice(REDIRECT_HINT)
            if strict
            else f"{REDIRECT_HINT}, or login without --verify-key"
        )
        text = (
            f"could not verify the api key against {shown} ({full_where}); {advice}; "
            "the profile was not saved"
        )
    else:
        check_url = "check the base url (its query string is sent too)"
        if strict:
            advice = strict_advice("retry" if retry_helps else check_url)
        elif retry_helps:
            advice = "retry or login without --verify-key"
        else:
            advice = f"{check_url} or login without --verify-key"
        text = (
            f"could not verify the api key against {shown} ({full_where}); "
            f"the profile was not saved, {advice}"
        )
    request_id = server.request_id if server else None
    return KeyCheckError(
        text + request_id_tail(text, request_id),
        request_id=request_id,
        details=error_details(server),
    )


def send_key_check(base_url: str, api_key: str, *, strict: bool = False) -> httpx.Response:
    """The one authenticated ``GET /v1/sandboxes?limit=1`` (the limit is merged into the query
    already on the base url). A failed request raises :class:`KeyCheckError`."""
    shown = echo_url(base_url, api_key)
    try:
        url = httpx.URL(endpoint_url(base_url, SANDBOXES_PATH)).copy_merge_params({"limit": 1})
        return httpx.get(
            url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=PROBE_TIMEOUT_S,
            follow_redirects=False,
        )
    except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
        reason = sanitise_text(str(exc) or type(exc).__name__, base_url=base_url, api_key=api_key)
        if is_invalid_url(exc):
            text = (
                f"could not verify the api key: base url {shown} is not a valid url ({reason}); "
                "nothing was sent, check the url"
            )
        else:
            advice = strict_advice("retry") if strict else "retry or login without --verify-key"
            text = (
                f"could not verify the api key against {shown} (GET {SANDBOXES_PATH}): {reason}; "
                f"the profile was not saved, {advice}"
            )
        raise KeyCheckError(text, client=request_never_sent(exc)) from None


def verify_key(base_url: str, api_key: str, *, strict: bool = False) -> KeyCheck:
    """One authenticated ``GET /v1/sandboxes?limit=1`` with the key being saved.

    A 2xx is ``verified``. A 403 whose body is the server's error envelope is ``limited-scope``
    (the key is probably valid; missing scopes are named when the envelope lists them); a 403
    that is not the envelope (a proxy page) is ``not-checked``. 401, any other status or a failed
    request raises :class:`KeyCheckError` (the login then saves nothing).
    """
    reply = send_key_check(base_url, api_key, strict=strict)
    where = f"HTTP {reply.status_code} on GET {SANDBOXES_PATH}"
    if reply.is_success:
        return KeyCheck(f"api key: verified ({where})", True, KEY_VERIFIED, where)
    server = clean_reply(parse_server_reply(reply), base_url, api_key)
    if reply.status_code == HTTP_FORBIDDEN:
        return forbidden_check(where, server)
    raise key_check_failure(reply.status_code, where, base_url, server, api_key, strict=strict)


VERIFY_FLAG_OPTIONS = {"verify_key_flag": "--verify-key", "require_verified": "--require-verified"}
# For each key-check flag, the parameters it cannot be combined with.
VERIFY_CONFLICTS = {
    "no_verify": ("verify_key_flag", "require_verified"),
    "verify_key_flag": ("no_verify",),
    "require_verified": ("no_verify",),
}


def reject_verify_conflict(ctx: typer.Context, param: typer.CallbackParam, value: bool) -> bool:
    """Eager flag callback: ``--no-verify`` with ``--verify-key`` or ``--require-verified`` is
    a usage error (exit 2).

    The flags are eager, so this runs before any prompt; the later of two in the command line
    sees the earlier one in ``ctx.params``.
    """
    if not value or param.name is None:
        return value
    for other in VERIFY_CONFLICTS.get(param.name, ()):
        if ctx.params.get(other):
            flag = VERIFY_FLAG_OPTIONS.get(other) or VERIFY_FLAG_OPTIONS[param.name]
            raise typer.BadParameter("cannot be combined with --no-verify", param_hint=flag)
    return value


def usage_error_payload(message: str) -> dict[str, Any]:
    """The json object of a usage error: code ``USAGE_ERROR``, ``"source": "client"``.

    The message is sanitised like any relayed text (the caller's own key is masked). A url
    echoed inside it is already cut on its own (:func:`echo_url`), so the cap here is wide
    enough for the reason after it to survive.
    """
    clean = sanitise_text(message, api_key=caller_key(), limit=USAGE_MESSAGE_CHARS)
    payload = error_payload(CliError(clean, client=True))
    payload["error"]["code"] = USAGE_ERROR_CODE
    return payload


def missing_option(option: str, envvar: str | None = None) -> NoReturn:
    """Report a required login option that was not given, without prompting (json mode).

    Stdout carries one ``{"error": {...}}`` usage-error object; the exit status is 2.
    """
    hint = f" (or set {envvar})" if envvar else ""
    message = f"missing option '{option}'{hint}; with --json the login does not prompt"
    print_json(usage_error_payload(message))
    raise typer.Exit(EXIT_USAGE)


def collect_credentials(
    state: AppState,
    base_url: str | None,
    api_key: str | None,
    key_file: str | None = None,
    api_key_from_flag: bool = False,
    key_stdin: bool = False,
) -> tuple[str, str]:
    """The base url and api key; a missing key is prompted for on a terminal only.

    The key comes from ``--api-key``, ``--key-file``, ``SANDFORT_API_KEY`` or
    ``SANDFORT_API_KEY_FILE`` (:func:`key_without_prompt`), or from one line of stdin with
    ``--key-stdin``. With none of them it is read from one line of stdin when stdin is not a
    terminal (a piped key) and prompted for when it is. Under ``--json`` there is no prompt:
    a terminal without a key is a json usage error (:func:`missing_option`), so stdout never
    carries a prompt. A base url that is also missing is prompted for first, so it takes the
    first stdin line and the key the next.
    """
    if base_url is None and state.json_output:
        missing_option("--base-url")
    key: str | None = None
    if key_stdin:
        reject_key_stdin_conflict(api_key, key_file, api_key_from_flag=api_key_from_flag)
    else:
        key = key_without_prompt(api_key, key_file, api_key_from_flag=api_key_from_flag)
    from_stdin = key is None and reads_key_from_stdin(key_stdin)
    if key is None and not from_stdin and state.json_output:
        missing_option("--api-key", API_KEY_ENV)
    if base_url is None:
        base_url = typer.prompt("Base url")
    if from_stdin:
        key = key_from_stdin(key_stdin)
        if key is None:
            if state.json_output:
                message = no_key_message(key_stdin)
                if not key_stdin:
                    message = f"missing option '--api-key'; {message}"
                print_json(usage_error_payload(message))
                raise typer.Exit(EXIT_USAGE)
            raise no_key_source_error(key_stdin)
        if not state.json_output:
            typer.echo(KEY_FROM_STDIN_NOTE)  # a label only: the key is never echoed
    elif key is None:
        typer.echo(KEY_PROMPT_HINT)
        try:
            key = typer.prompt("Api key", hide_input=True)
        except UnicodeError:  # stdin is not valid text: the same usage error as a malformed key
            raise stdin_not_text_error() from None
    return base_url, key


def exit_with_key_error(state: AppState, exc: KeyCheckError) -> NoReturn:
    """Fail the login with a key-check error; the json object carries its ``details``."""
    if not state.json_output:
        raise exc
    payload = error_payload(exc)
    if exc.details:
        payload["error"]["details"] = dict(exc.details)
    print_json(payload)
    raise typer.Exit(EXIT_FAILURE)


@dataclass(frozen=True)
class LoginResult:
    """What a successful login saved and reported."""

    path: Path
    notes: list[str]
    check: KeyCheck
    userinfo_removed: bool = False


def invalid_url_message(typed: str, reason: str, api_key: str = "") -> str:
    """``base url X is not a valid url (reason); ...`` with X sanitised (no userinfo)."""
    shown = echo_url(typed, api_key)
    return f"base url {shown} is not a valid url ({reason}); nothing was sent, check the url"


def invalid_url_error(typed: str, reason: str, api_key: str = "") -> typer.BadParameter:
    """The usage error (exit 2, nothing sent) for a base url found unusable on this machine.

    Every locally detected unusable url (unsupported scheme, no host, a port that is not a
    number or is out of range) is reported through here, with the same wording.
    """
    return typer.BadParameter(invalid_url_message(typed, reason, api_key), param_hint="--base-url")


def reject_bad_login_input(base_url: str, api_key: str) -> str:
    """The base url (scheme lowercased, trailing slash dropped) after the usage checks.

    An empty base url, an unsupported scheme and an empty api key are usage errors (exit 2,
    the json usage-error object under ``--json``), like a missing option.
    """
    typed = lower_scheme(base_url)
    if not typed:
        raise typer.BadParameter("must not be empty", param_hint="--base-url")
    if not typed.startswith(URL_SCHEMES):
        reason = "unsupported scheme, it must start with http:// or https://"
        raise invalid_url_error(typed, reason, api_key)
    if not typed.rstrip("/").startswith(URL_SCHEMES):  # ``http://`` or ``https:///``: no host
        raise invalid_url_error(typed, "no host", api_key)
    if not api_key.strip():
        raise typer.BadParameter("must not be empty", param_hint="--api-key")
    # The check every later command applies to the configured key: refused here, nothing saved.
    check_configured_key(api_key, "--api-key")
    return validate_base_url(typed)


def reject_unusable_url(typed: str, api_key: str = "") -> str:
    """``typed`` without its userinfo, after the structural checks beyond scheme and host.

    The checks are the same wherever a base url comes from (login or the configuration): no
    host, a port that is not a number or out of range, whitespace or brackets in the host and
    any url the local parsers refuse. Each raises the unified invalid-url usage error.
    """
    cleaned = strip_userinfo(typed)
    reject_empty_host(typed, cleaned, api_key)
    reject_long_host(typed, cleaned, api_key)
    reject_bad_port(typed, cleaned, api_key)
    reject_malformed_url(typed, cleaned, api_key)
    return cleaned


def check_configured_url(base_url: str, source: str, api_key: str = "") -> str:
    """The configured base url (environment variable or profile) after the login checks.

    ``source`` names where it came from (shown as the parameter of the usage error). An
    unusable url raises the same invalid-url usage error as ``login`` (exit 2, one json usage
    object under ``--json``) before any client is built.
    """
    typed = lower_scheme(base_url)
    try:
        if not typed.startswith(URL_SCHEMES):
            reason = "unsupported scheme, it must start with http:// or https://"
            raise invalid_url_error(typed, reason, api_key)
        if not typed.rstrip("/").startswith(URL_SCHEMES):
            raise invalid_url_error(typed, "no host", api_key)
        reject_unusable_url(typed, api_key)
    except typer.BadParameter as exc:
        exc.param_hint = source
        raise
    return typed


def url_authority(cleaned: str) -> str:
    """The authority (host and port) of ``cleaned``, a url whose userinfo was removed."""
    netloc = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", cleaned)
    return re.split(r"[/?#]", netloc, maxsplit=1)[0]


def reject_bad_port(typed: str, cleaned: str, api_key: str = "") -> None:
    """Raise the invalid-url usage error when the port of ``cleaned`` is unusable.

    A port that is not a number (letters, non-ASCII digits) is an ``invalid port``; a number
    outside 1-65535 (a negative one included) is ``port out of range``. Caught up front and
    before the ``--no-verify`` branch, so it is an invalid url and not a name-resolution
    failure, and an unchecked save never stores it. An empty port (``host:``) is accepted.
    """
    netloc = url_authority(cleaned)
    port = netloc.rpartition("]:")[2] if netloc.startswith("[") else netloc.rpartition(":")[2]
    if port.startswith("-") and port[1:].isascii() and port[1:].isdigit():
        raise invalid_url_error(typed, f"port out of range 1-{PORT_MAX}", api_key)
    if not port or port == netloc:
        return
    if not (port.isascii() and port.isdigit()):
        raise invalid_url_error(typed, "invalid port", api_key)
    digits = port.lstrip("0")
    if digits and len(digits) <= len(str(PORT_MAX)) and int(digits) <= PORT_MAX:
        return
    raise invalid_url_error(typed, f"port out of range 1-{PORT_MAX}", api_key)


def reject_empty_host(typed: str, cleaned: str, api_key: str = "") -> None:
    """Raise the invalid-url usage error when ``cleaned`` (``typed`` minus userinfo) has no host.

    Covers the user-only forms (``http://user@``) and a bare port (``http://:80``); a bracketed
    IPv6 host counts as a host (a malformed one is caught by :func:`reject_malformed_url`).
    """
    netloc = url_authority(cleaned)
    host = netloc if netloc.startswith("[") else netloc.partition(":")[0]
    if not host:
        raise invalid_url_error(typed, "no host", api_key)


def reject_long_host(typed: str, cleaned: str, api_key: str = "") -> None:
    """Raise the invalid-url usage error when the host of ``cleaned`` is longer than a hostname
    can be (``MAX_HOST_CHARS``); like the other structural checks it runs on every path, the
    unchecked save included."""
    netloc = url_authority(cleaned)
    host = netloc.partition("]")[0] if netloc.startswith("[") else netloc.partition(":")[0]
    if len(host) > MAX_HOST_CHARS:
        reason = f"the host is longer than {MAX_HOST_CHARS} characters"
        raise invalid_url_error(typed, reason, api_key)


def reject_malformed_url(typed: str, cleaned: str, api_key: str = "") -> None:
    """Raise the invalid-url usage error when ``cleaned`` is structurally unusable.

    Whitespace or a control character in the host, brackets that do not enclose the whole host
    (an unclosed IPv6 bracket, text after it) and any url the local parsers refuse (Python's
    ``urlsplit`` and httpx's, the one the requests use) are caught here, before the
    ``--no-verify`` branch, so nothing is sent and an unchecked save never stores them. The
    reason is a fixed phrase: a parser's own message may quote parts of the url.
    """
    authority = url_authority(cleaned)
    if any(char.isspace() or not char.isprintable() for char in authority):
        raise invalid_url_error(typed, "whitespace or a control character in the host", api_key)
    if not typed.isprintable():  # userinfo, path or query: the client would refuse it later
        raise invalid_url_error(typed, "a control character in the url", api_key)
    has_brackets = "[" in authority or "]" in authority
    if has_brackets and not BRACKETED_AUTHORITY_RE.fullmatch(authority):
        raise invalid_url_error(typed, "malformed brackets in the host", api_key)
    try:
        urlsplit(cleaned)
        httpx.URL(cleaned)
    except (ValueError, httpx.InvalidURL):
        raise invalid_url_error(typed, "the url cannot be parsed", api_key) from None


def require_verified_failure(check: KeyCheck) -> KeyCheckError:
    """The error of ``--require-verified`` for a check that did not end ``verified``.

    The details carry ``key_status``, the missing scopes (when named), the request id and the
    server code (when the server's envelope sent them).
    """
    if check.status == KEY_LIMITED_SCOPE:
        named = ", ".join(check.missing_scopes) + beyond_cap_note(check.scopes_beyond_cap)
        scopes = f"; missing scope(s): {named}" if named else ""
        reason = (
            f"the server answered 403 ({check.where}), the key is probably valid but lacks "
            f"the sandbox read scope{scopes}"
        )
    else:
        reason = (
            f"the 403 answer ({check.where}) did not come from the server's API "
            "(the body is not its error envelope, for example a proxy or login page)"
        )
    text = (
        f"the api key was not verified: {reason}; --require-verified saves a key only "
        "after a successful check, the profile was not saved"
    )
    details: dict[str, Any] = {"key_status": check.status}
    if check.missing_scopes or check.scopes_beyond_cap:
        details["missing_scopes"] = list(check.missing_scopes)
        details[BEYOND_CAP_FIELD] = check.scopes_beyond_cap
    if check.request_id:
        details["request_id"] = check.request_id
    if check.server_code:
        details["server_code"] = check.server_code
    return KeyCheckError(
        text + request_id_tail(text, check.request_id),
        request_id=check.request_id,
        details=details,
    )


def perform_login(
    base_url: str,
    api_key: str,
    *,
    no_verify: bool,
    verify_key_flag: bool,
    require_verified: bool = False,
) -> LoginResult:
    """Check the url (and, with ``verify_key_flag`` or ``require_verified``, the key), then
    save the profile.

    The scheme is written in lowercase and userinfo is removed from the saved url, so the
    stored profile is the url that was verified. With ``require_verified`` any key check that
    does not end ``verified`` fails the login and nothing is saved.
    """
    typed = reject_bad_login_input(base_url, api_key)
    key = api_key.strip()
    cleaned = reject_unusable_url(typed, key)
    shown = echo_url(cleaned, key)
    if no_verify:
        notes = [f"server {shown}: not checked (--no-verify)"]
    else:
        notes = [f"server {shown}: build {probe_server(cleaned, key, strict=require_verified)}"]
    if cleaned != typed:
        notes.append(USERINFO_REMOVED_NOTE)
    if verify_key_flag or require_verified:
        check = verify_key(cleaned, key, strict=require_verified)
        if require_verified and check.status != KEY_VERIFIED:
            raise require_verified_failure(check)
    else:
        check = KeyCheck(KEY_NOT_VERIFIED_NOTE, False, KEY_NOT_CHECKED)
    notes.append(check.note)
    return LoginResult(save_profile(cleaned, api_key), notes, check, cleaned != typed)


def login_payload(result: LoginResult) -> dict[str, Any]:
    """The json success object: the profile path and the key check outcome.

    A limited-scope key adds ``missing_scopes``, ``missing_scopes_beyond_cap`` (the number of
    missing scopes the server named beyond the relay cap, ``0`` when none) and ``request_id``;
    ``userinfo_removed`` is ``true`` (and only then present) when userinfo was removed from the
    saved base url.
    """
    payload: dict[str, Any] = {
        "profile": str(result.path),
        "key_verified": result.check.verified,
        "key_status": result.check.status,
    }
    if result.check.status == KEY_LIMITED_SCOPE:
        payload["missing_scopes"] = list(result.check.missing_scopes)
        payload[BEYOND_CAP_FIELD] = result.check.scopes_beyond_cap
        payload["request_id"] = result.check.request_id
    if result.userinfo_removed:
        payload["userinfo_removed"] = True
    return payload


def login_message(result: LoginResult) -> str:
    """The text success line; a check that was answered but not verified is not "Logged in"."""
    if result.check.status == KEY_NOT_CHECKED and result.check.where:
        return f"Profile saved to {result.path}; the api key was not verified"
    return f"Logged in; profile saved to {result.path}"


def login(
    ctx: typer.Context,
    base_url: Annotated[
        str | None,
        typer.Option("--base-url", help="Server base url (prompted for when omitted)."),
    ] = None,
    api_key: Annotated[
        str | None,
        typer.Option(
            "--api-key",
            envvar=API_KEY_ENV,
            help="API key (prompted for when omitted; with --json it must be given).",
        ),
    ] = None,
    key_file: Annotated[
        str | None,
        typer.Option(
            KEY_FILE_OPTION,
            metavar="PATH",
            help="Read the API key from the first line of this private file (mode 600). "
            "The key is taken from --api-key, --key-file, SANDFORT_API_KEY, "
            "SANDFORT_API_KEY_FILE, in that order, before any prompt.",
        ),
    ] = None,
    key_stdin: Annotated[
        bool,
        typer.Option(
            KEY_STDIN_OPTION,
            help="Read the API key from one line of stdin (printf '%s\\n' \"$KEY\" | "
            "sandfort login --key-stdin). Without any key source and with stdin not a "
            "terminal this is what login does anyway. Cannot be combined with --api-key "
            "or --key-file.",
        ),
    ] = False,
    no_verify: Annotated[
        bool,
        typer.Option(
            "--no-verify",
            help="Save the profile without asking the server's status endpoint first "
            "(air-gapped hosts, servers that are not up yet).",
            is_eager=True,
            callback=reject_verify_conflict,
        ),
    ] = False,
    verify_key_flag: Annotated[
        bool,
        typer.Option(
            "--verify-key",
            help="After the status check, make one authenticated GET of the sandbox list "
            "with this key; a rejected key (401) fails the login. Cannot be combined "
            "with --no-verify.",
            is_eager=True,
            callback=reject_verify_conflict,
        ),
    ] = False,
    require_verified: Annotated[
        bool,
        typer.Option(
            "--require-verified",
            help="Strict mode for bootstrap scripts: implies the key check and succeeds only "
            "when the check is answered 2xx; any other outcome (a limited-scope 403 included) "
            "exits 1 and saves nothing. Cannot be combined with --no-verify.",
            is_eager=True,
            callback=reject_verify_conflict,
        ),
    ] = False,
) -> None:
    """Store the server url and api key in the local profile (mode 600).

    The key is read from --api-key, --key-file PATH, SANDFORT_API_KEY or SANDFORT_API_KEY_FILE
    (in that order) and only then taken from stdin: with --key-stdin, or when stdin is not a
    terminal, one line of stdin is the key (``printf '%s\\n' "$KEY" | sandfort login``), and
    more than one line or none is a usage error; on a terminal the key is prompted for.

    Unless --no-verify is given, the url is checked first with one unauthenticated GET of
    /v1/status; a url that does not answer it is not saved. The key is not checked unless
    --verify-key or --require-verified is given. Userinfo in the url is never sent and is
    removed from the saved url; echoed urls hide it and mask query values and the fragment.
    Text relayed from the server is stripped of terminal escapes and control characters, cut
    to a few hundred characters, and has the api key and userinfo masked. The json result has
    key_verified (kept for compatibility) and key_status: verified, limited-scope or
    not-checked; a limited-scope key adds missing_scopes, missing_scopes_beyond_cap (a count of
    the missing scopes not listed, 0 when none) and request_id, and userinfo_removed is true
    when userinfo was removed from the saved url. An empty api key, a malformed api key
    (inner whitespace, a control or non-ASCII character), an empty base url
    or an unusable url (unsupported scheme, no host, a port that is not a number or is outside
    1-65535, whitespace or brackets that do not parse in the host, any url that cannot be
    parsed) is a usage error (exit 2): nothing is sent and nothing is saved, also with
    --no-verify.
    """
    state = app_state(ctx)
    with cli_errors():
        source = ctx.get_parameter_source("api_key")
        from_flag = source is not None and source.name == "COMMANDLINE"
        typed_url, typed_key = collect_credentials(
            state, base_url, api_key, key_file, api_key_from_flag=from_flag, key_stdin=key_stdin
        )
        try:
            result = perform_login(
                typed_url,
                typed_key,
                no_verify=no_verify,
                verify_key_flag=verify_key_flag,
                require_verified=require_verified,
            )
        except KeyCheckError as exc:
            exit_with_key_error(state, exc)
        if not state.json_output:
            for note in result.notes:
                typer.echo(note)
        render_message(state, login_message(result), login_payload(result))


@sandbox_app.command("create")
def create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(metavar=NAME_METAVAR, help="Sandbox name.")],
    snapshot: Annotated[
        str | None, typer.Option("--snapshot", "-s", help="Snapshot image to start from.")
    ] = None,
    wait: Annotated[bool, typer.Option("--wait", help="Block until started.")] = False,
    wait_timeout_text: Annotated[
        str | None, typer.Option("--wait-timeout", metavar="SECONDS", help=WAIT_HELP)
    ] = None,
    keep_on_failure: Annotated[
        bool,
        typer.Option(
            "--keep-on-failure",
            help="With --wait: keep a sandbox whose start ends in the error state for "
            "inspection (default: it is deleted before the error is reported).",
        ),
    ] = False,
    mount: Annotated[
        list[str] | None,
        typer.Option(MOUNT_OPTION, "-m", help=MOUNT_HELP),
    ] = None,
    egress: Annotated[
        list[str] | None,
        typer.Option(
            "--egress",
            help="Restrict outbound traffic to this host through the egress proxy (repeatable).",
        ),
    ] = None,
    block_network: Annotated[
        bool | None,
        typer.Option(
            "--block-network/--no-block-network",
            help="Block all outbound network traffic, or explicitly keep it open "
            "(default: the server's setting).",
        ),
    ] = None,
    auto_stop_text: Annotated[
        str | None,
        typer.Option(
            "--auto-stop",
            metavar=INTEGER_METAVAR,
            help="Stop the sandbox after this many idle minutes.",
        ),
    ] = None,
    auto_delete_text: Annotated[
        str | None,
        typer.Option(
            "--auto-delete",
            metavar=INTEGER_METAVAR,
            help="Delete the sandbox this many minutes after it stops "
            "(negative: never, 0: once stopped, on the next sweep, within about a minute).",
        ),
    ] = None,
    env: Annotated[
        list[str] | None,
        typer.Option("--env", "-e", help="Environment variable as KEY=VALUE (repeatable)."),
    ] = None,
    label: Annotated[
        list[str] | None,
        typer.Option("--label", "-l", help="Label as KEY=VALUE (repeatable)."),
    ] = None,
    cpu_text: Annotated[
        str | None,
        typer.Option("--cpu-millicores", metavar=INTEGER_METAVAR, help="CPU in millicores."),
    ] = None,
    memory_text: Annotated[
        str | None, typer.Option("--memory-mib", metavar=INTEGER_METAVAR, help="Memory in MiB.")
    ] = None,
    disk_text: Annotated[
        str | None, typer.Option("--disk-gib", metavar=INTEGER_METAVAR, help="Disk in GiB.")
    ] = None,
    isolation: Annotated[
        IsolationTier | None,
        typer.Option(
            "--isolation",
            help="Isolation tier to run on (default: the server's; see 'sandbox isolation').",
        ),
    ] = None,
) -> None:
    """Create a sandbox."""
    reject_empty_name(name, NAME_METAVAR)
    reject_empty_option(snapshot, "--snapshot")
    reject_empty_options(egress, "--egress")
    mounts = [parse_mount(value) for value in mount] if mount else None
    auto_stop = parse_optional_whole_number(auto_stop_text, "--auto-stop")
    auto_delete = parse_optional_whole_number(auto_delete_text, "--auto-delete")
    cpu_millicores = parse_optional_whole_number(cpu_text, "--cpu-millicores")
    memory_mib = parse_optional_whole_number(memory_text, "--memory-mib")
    disk_gib = parse_optional_whole_number(disk_text, "--disk-gib")
    wait_timeout = parse_wait_timeout(wait, wait_timeout_text)
    env_vars = parse_pairs(env, "env")
    labels = parse_pairs(label, "label")
    with cli_errors():
        egress_allowlist = list(egress) if egress else None
        resources = build_resources(cpu_millicores, memory_mib, disk_gib)
        timeout_args: dict[str, Any] = {}
        if wait_timeout is not None:
            timeout_args["wait_timeout_s"] = wait_timeout
        with open_client() as client, quiet_name_check():
            if mounts:
                mounts = resolve_volume_refs(client, mounts)
            try:
                sandbox = client.create_sandbox(
                    name=name,
                    snapshot=snapshot,
                    wait=wait,
                    delete_on_failure=not keep_on_failure,
                    **timeout_args,
                    mounts=mounts,
                    egress_allowlist=egress_allowlist,
                    block_network=block_network,
                    auto_stop_minutes=auto_stop,
                    auto_delete_minutes=auto_delete,
                    env=env_vars,
                    labels=labels,
                    resources=resources,
                    isolation=None if isolation is None else isolation.value,
                )
            except SandboxFailedError as failed:
                settled = settle_failed_start(client, failed, keep=keep_on_failure)
                raise settled from None  # its str() and the text line end with the request id
            except ApiError as refused:
                raise name_mount_option(refused, mount or []) from None
            if not wait and sandbox.info.state == ERROR_STATE:
                report_immediate_error(app_state(ctx), sandbox.info, sandbox.request_id)
            render_sandbox(app_state(ctx), sandbox.info)


@sandbox_app.command("list")
def list_sandboxes(
    ctx: typer.Context,
    state_values: Annotated[
        list[str] | None, typer.Option("--state", help="Only sandboxes in this state.")
    ] = None,
    label: Annotated[
        list[str] | None,
        typer.Option("--label", "-l", help="Only sandboxes with label KEY=VALUE (repeatable)."),
    ] = None,
    show_all: Annotated[
        bool,
        typer.Option("--all", help="Include destroyed sandboxes (tombstones, hidden by default)."),
    ] = False,
    order_values: Annotated[
        list[ListOrder] | None,
        typer.Option("--order", help="asc or desc (newest first); the server default if unset."),
    ] = None,
    stop_cause_values: Annotated[
        list[str] | None,
        typer.Option(
            STOP_CAUSE_OPTION,
            metavar=STOP_CAUSE_METAVAR,
            help="Only sandboxes stopped for this cause (the five values are listed below).",
        ),
    ] = None,
) -> None:
    """List sandboxes.

    Destroyed sandboxes are hidden unless --all or --state destroyed is given.
    --stop-cause keeps only the sandboxes that stopped for that cause.
    --state, --order and --stop-cause take one value each; --label may be repeated.

    The REASON column shows the error code and reason of a failed sandbox.
    For a stopped sandbox it shows the stop_cause.
    The five values, which are also the ones --stop-cause accepts:

    requested, auto_stop, container_exited, oom_killed, unknown
    """
    state = single_value(state_values, "--state")
    order = single_value(order_values, "--order")
    cause = check_stop_cause(single_value(stop_cause_values, STOP_CAUSE_OPTION))
    reject_empty_option(state, "--state")
    labels = parse_pairs(label, "label")
    with cli_errors():
        with open_client() as client:
            sandboxes = client.iter_sandboxes(
                state=state, labels=labels, include_destroyed=show_all,
                order=None if order is None else order.value, stop_cause=cause,
            )  # fmt: skip
            render_sandboxes(app_state(ctx), [sandbox.info for sandbox in sandboxes])


# `sandbox ls`: the same command as `list`, hidden from --help.
sandbox_app.command("ls", hidden=True)(list_sandboxes)


IMAGE_MOUNTS_FIELD = "image mounts"
IMAGE_MOUNTS_KEY = "image_mounts"


def image_mounts_of(info: SandboxInfo) -> list[str]:
    """The paths the sandbox's image mounts (empty when the server reports none)."""
    return [str(path) for path in info.image_mounts]


def render_sandbox(state: AppState, info: SandboxInfo) -> None:
    """The sandbox view: the mounted-volumes view plus the image mounts (a text row when there
    are any; always a list in json)."""
    mounts = image_mounts_of(info)
    key = caller_key()
    if state.json_output:
        payload = {**sandbox_payload(info), IMAGE_MOUNTS_KEY: clean_strings(mounts, key)}
        print_json(payload)
        return
    if not mounts:
        render_mounted_sandbox(state, info)
        return
    fields = sandbox_fields(info)
    if info.volumes:
        fields[VOLUMES_FIELD] = mount_lines(info.volumes)
    fields[IMAGE_MOUNTS_FIELD] = ", ".join(shown(path, key) for path in mounts)
    print_fields("sandbox", fields, folded=(LABELS_FIELD, VOLUMES_FIELD, IMAGE_MOUNTS_FIELD))


@sandbox_app.command("get")
def get(ctx: typer.Context, sandbox_id: SandboxId) -> None:
    """Show one sandbox.

    A stopped sandbox has a stop_cause row (why it stopped: requested, auto_stop,
    container_exited, oom_killed, unknown), the value the REASON column of `sandbox list`
    shows; a failed one has error_code and error_reason rows.
    """
    reject_empty_name(sandbox_id, SANDBOX_METAVAR)
    with ref_errors(), open_client() as client:
        render_sandbox(app_state(ctx), client.get(resolve_sandbox_id(client, sandbox_id)).info)


@sandbox_app.command("isolation")
def isolation_tiers(ctx: typer.Context) -> None:
    """Show the default isolation tier and the tiers this server offers."""
    with cli_errors(), open_client() as client:
        render_isolation(app_state(ctx), client.isolation())


@sandbox_app.command("stop")
def stop(ctx: typer.Context, sandbox_id: SandboxId) -> None:
    """Stop a sandbox."""
    reject_empty_name(sandbox_id, SANDBOX_METAVAR)
    with ref_errors(), open_client() as client:
        render_sandbox(app_state(ctx), client.stop(resolve_sandbox_id(client, sandbox_id)).info)


def _start(client: Client, sandbox_id: str, wait: bool, wait_timeout: float | None) -> SandboxInfo:
    """Start; with ``wait``, the SDK blocks until started under one deadline (``wait_timeout``
    seconds, the SDK's default if None) that also covers the start request."""
    return client.start(sandbox_id, wait=wait, wait_timeout_s=wait_timeout).info


@sandbox_app.command("start")
def start(
    ctx: typer.Context,
    sandbox_id: SandboxId,
    wait: Annotated[bool, typer.Option("--wait", help="Block until started.")] = False,
    wait_timeout_text: Annotated[
        str | None, typer.Option("--wait-timeout", metavar="SECONDS", help=WAIT_HELP)
    ] = None,
) -> None:
    """Start a stopped sandbox."""
    reject_empty_name(sandbox_id, SANDBOX_METAVAR)
    wait_timeout = parse_wait_timeout(wait, wait_timeout_text)
    with ref_errors(), open_client() as client:
        info = _start(client, resolve_sandbox_id(client, sandbox_id), wait, wait_timeout)
        render_sandbox(app_state(ctx), info)


@sandbox_app.command("reset")
def reset(ctx: typer.Context, sandbox_id: SandboxId) -> None:
    """Replace a sandbox's container with a fresh one (same id, spec and volumes)."""
    reject_empty_name(sandbox_id, SANDBOX_METAVAR)
    with ref_errors(), open_client() as client:
        sandbox = client.get(resolve_sandbox_id(client, sandbox_id))
        render_sandbox(app_state(ctx), sandbox.reset().info)


def _delete_one(client: Client, ref: str, if_exists: bool) -> SandboxInfo | None:
    """Delete ``ref``; ``None`` when ``if_exists`` and the sandbox was already gone.

    "Already gone" is decided before the delete call; whatever the delete answers afterwards
    (deleting, destroying or destroyed) counts as a delete.
    """
    if not if_exists:
        return client.delete(resolve_sandbox_id(client, ref)).info
    sandbox_id = resolve_live_sandbox_id(client, ref)
    if sandbox_id is None:
        typer.echo(f"{ref}: not found, skipped", err=True)
        return None
    return client.delete(sandbox_id).info


def _rm_payloads(refs: list[str], results: list[SandboxInfo | None]) -> list[dict[str, Any]]:
    """One json object per processed ref: the sandbox, or ``{"ref": ..., "skipped": ...}``."""
    return [
        {"ref": ref, "skipped": "not_found"} if info is None else sandbox_payload(info)
        for ref, info in zip(refs, results, strict=False)
    ]


@sandbox_app.command("rm")
def rm(
    ctx: typer.Context,
    refs: Annotated[
        list[str],
        typer.Argument(metavar="<sandbox>...", help="Sandbox ids or names, deleted in order."),
    ],
    if_exists: Annotated[
        bool,
        typer.Option(
            "--if-exists",
            help="Skip a sandbox that does not exist or is already destroyed (note on stderr, "
            "exit code unchanged). Other errors still fail.",
        ),
    ] = False,
) -> None:
    """Delete sandboxes; prints one id per line (--json: the sandbox object, or a list).

    With --json every processed ref is reported, also when a later ref fails: then ONE document
    holds the error and the processed refs ({"error": {...}, "processed": [...]}). A skipped
    ref is {"ref": ..., "skipped": "not_found"}.
    """
    json_output = app_state(ctx).json_output
    for ref in refs:
        reject_empty_name(ref, SANDBOX_METAVAR)
    results: list[SandboxInfo | None] = []

    def processed() -> dict[str, Any]:
        return {"processed": _rm_payloads(refs, results)} if results else {}

    with ref_errors(extras=processed), open_client() as client:
        reported = False
        try:
            for ref in refs:
                info = _delete_one(client, ref, if_exists)
                results.append(info)
                if info is not None and not json_output:
                    typer.echo(shown(info.id, caller_key()))
        except (SandfortSDKError, CliError):
            # ``ref_errors`` prints the ONE document: the error with the processed refs.
            reported = True
            raise
        finally:
            # Success, or a failure nobody else reports (an unexpected exception, an
            # interrupt): the processed refs are still printed as json.
            if json_output and results and not reported:
                payloads = _rm_payloads(refs, results)
                print_json(payloads[0] if len(refs) == 1 else payloads)


# `sandbox delete`: the same command as `rm` (arguments, options, output), hidden from --help.
sandbox_app.command("delete", hidden=True)(rm)
