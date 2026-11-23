"""Profile storage and credential resolution.

The profile is a small json file in a private directory (``SANDFORT_CONFIG_DIR``, else
``$XDG_CONFIG_HOME/sandfort`` when ``XDG_CONFIG_HOME`` is an absolute path, else
``~/.config/sandfort``). ``SANDFORT_BASE_URL`` and ``SANDFORT_API_KEY`` override its values;
``SANDFORT_API_KEY_FILE`` names a private file holding the key (``SANDFORT_API_KEY`` wins):
the key is on its first line, the file is a regular file owned by the current user with no
group or other access (mode 600 or stricter). The mode and owner checks are skipped where the
platform has no POSIX modes. The api key is only ever handed to the SDK client; nothing here
prints or logs it.
"""

import json
import os
import re
import shlex
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

import httpx
import typer
from sandfort_sdk import ApiError, Client, InvalidResponseError, SandfortSDKError
from sandfort_sdk import _requests as sdk_requests
from sandfort_sdk import _transport as sdk_transport
from sandfort_sdk.exceptions import error_for

from sandfort_cli.output import CliError, _json_errors
from sandfort_cli.sanitise import scrub_local

CONFIG_DIR_ENV = "SANDFORT_CONFIG_DIR"
XDG_CONFIG_HOME_ENV = "XDG_CONFIG_HOME"
BASE_URL_ENV = "SANDFORT_BASE_URL"
API_KEY_ENV = "SANDFORT_API_KEY"
API_KEY_FILE_ENV = "SANDFORT_API_KEY_FILE"
# Fixed text: names the variables only, never a key.
NOT_LOGGED_IN_MESSAGE = (
    "not logged in; run 'sandfort login' or set SANDFORT_BASE_URL and "
    "SANDFORT_API_KEY (or SANDFORT_API_KEY_FILE)"
)
# Group and other permission bits: a key file with any of them set is refused.
KEY_FILE_FORBIDDEN_MODE_BITS = 0o077
# Only the first line is read; this caps what is read from a file that is not a key file.
KEY_FILE_READ_LIMIT = 4096
# Lines of a key file scanned for the one key line (blank lines around it are fine).
KEY_FILE_MAX_LINES = 64
PROFILE_FILENAME = "profile.json"
PROFILE_MODE = 0o600
CONFIG_DIR_MODE = 0o700
URL_SCHEMES = ("http://", "https://")
# An api key as sent in the Authorization header: printable ASCII, no whitespace inside.
API_KEY_TOKEN_RE = re.compile(r"[\x21-\x7e]+")
# Fixed text only: a malformed key is never echoed.
MALFORMED_KEY_MESSAGE = (
    "is malformed (an api key is printable ASCII with no whitespace inside or around it)"
)
# A real key is about 60 characters; the cap is far above that and only stops absurd input.
MAX_API_KEY_CHARS = 512
TOO_LONG_KEY_MESSAGE = f"is too long (an api key is at most {MAX_API_KEY_CHARS} characters)"
# Ends every profile-key error: a damaged stored key is fixed by logging in again.
LOGIN_TAIL = "; run 'sandfort login'"
# A stored key field of the wrong json type, or empty: fixed text, the value is never echoed.
NOT_A_STRING_KEY_MESSAGE = "is not a string (an api key is a json string)" + LOGIN_TAIL
EMPTY_KEY_MESSAGE = "is empty (an api key is a non-empty string)" + LOGIN_TAIL
PROFILE_KEY_FIELD = "api_key"
# Marks an SDK function already wrapped by :func:`install_body_guards`.
GUARD_MARK = "_sandfort_cli_body_guard"

ParseResponse = Callable[[httpx.Response], sdk_transport.Reply]
ErrorFields = Callable[[httpx.Response], tuple[str, str]]


NOT_AN_ENVELOPE = "response is not a Sandfort envelope"
# Appended when the request went out over http: the hosted API answers only https, so a plain
# http base URL ends in a redirect or a page, never an envelope.
HTTP_BASE_URL_HINT = "the server answers only https; check SANDFORT_BASE_URL"


def _sent_over_http(response: httpx.Response) -> bool:
    try:
        return response.request.url.scheme == "http"
    except RuntimeError:  # a response built without a request
        return False


def not_an_envelope(response: httpx.Response) -> InvalidResponseError:
    """The invalid-response error for a non-envelope answer, with the https hint after an
    http request."""
    message = (
        f"{NOT_AN_ENVELOPE}; {HTTP_BASE_URL_HINT}" if _sent_over_http(response) else NOT_AN_ENVELOPE
    )
    return InvalidResponseError(message)


def non_envelope_error(response: httpx.Response) -> SandfortSDKError:
    """What the SDK raises for a body that is not an envelope: ``HTTP_<status>`` for an error
    status, else :class:`InvalidResponseError`."""
    status = response.status_code
    if response.is_error:
        return error_for(
            f"HTTP_{status}", response.reason_phrase or "http error", status_code=status
        )
    return not_an_envelope(response)


def raw_details_error(response: httpx.Response) -> ApiError | None:
    """The typed error for the reply's code and actual status (as the SDK builds it: a 404
    ``NOT_FOUND`` is a ``NotFound``, any 503 a ``ServiceUnavailable``, a 409 ``CONFLICT`` a
    ``Conflict``), keeping a ``details`` that is not an object (a string or a list), which the
    SDK's reason lookup cannot read; ``None`` when that is not the case."""
    try:
        body = response.json()
    except (ValueError, RecursionError):
        return None
    error = body.get("error") if isinstance(body, dict) else None
    if not isinstance(error, dict):
        return None
    details = error.get("details")
    if details is None or isinstance(details, dict):
        return None
    request_id = error.get("request_id")
    built = error_for(
        str(error.get("code", f"HTTP_{response.status_code}")),
        str(error.get("message", "request failed")),
        status_code=response.status_code,
        request_id=request_id if isinstance(request_id, str) else None,
    )
    # Set after the build: the SDK's conflict-reason lookup reads ``details`` as an object.
    built.details = details
    built.has_details = bool(details)
    return built


def guard_parse_response(parse: ParseResponse) -> ParseResponse:
    """``parse`` with a body nested too deeply (or otherwise unparseable) handled as a
    non-envelope answer, and a non-object ``details`` kept instead of crashing."""

    def guarded(response: httpx.Response) -> sdk_transport.Reply:
        try:
            return parse(response)
        except InvalidResponseError as exc:
            if str(exc) != NOT_AN_ENVELOPE:
                raise
            raise not_an_envelope(response) from None
        except (RecursionError, ValueError):
            raise non_envelope_error(response) from None
        except AttributeError:
            kept = raw_details_error(response)
            if kept is None:
                raise
            raise kept from None

    setattr(guarded, GUARD_MARK, True)
    return guarded


def guard_error_fields(fields: ErrorFields) -> ErrorFields:
    """``fields`` (the retry check's code and reason) with an unparseable body as no fields."""

    def guarded(response: httpx.Response) -> tuple[str, str]:
        try:
            return fields(response)
        except (RecursionError, ValueError):
            return "", ""

    setattr(guarded, GUARD_MARK, True)
    return guarded


def install_body_guards() -> None:
    """Wrap the SDK's shared body parsing (idempotent).

    The SDK looks both functions up by module-global name, so rebinding them is enough. The
    login path parses its own replies and already catches these errors.
    """
    transport_names = vars(sdk_transport)
    if not getattr(transport_names["parse_response"], GUARD_MARK, False):
        transport_names["parse_response"] = guard_parse_response(sdk_transport.parse_response)
    request_names = vars(sdk_requests)
    if not getattr(request_names["error_fields"], GUARD_MARK, False):
        request_names["error_fields"] = guard_error_fields(sdk_requests.error_fields)


install_body_guards()


@dataclass(frozen=True)
class Settings:
    base_url: str
    api_key: str = field(repr=False)


def config_dir() -> Path:
    override = os.environ.get(CONFIG_DIR_ENV)
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get(XDG_CONFIG_HOME_ENV)
    # The XDG spec: a relative value is invalid and must be ignored.
    if xdg and Path(xdg).is_absolute():
        return Path(xdg) / "sandfort"
    return Path.home() / ".config" / "sandfort"


def profile_path() -> Path:
    return config_dir() / PROFILE_FILENAME


def validate_base_url(base_url: str) -> str:
    cleaned = base_url.strip().rstrip("/")
    if not cleaned.startswith(URL_SCHEMES):
        raise CliError("base url must start with http:// or https://", client=True)
    return cleaned


def save_profile(base_url: str, api_key: str) -> Path:
    """Write the profile atomically with mode 600 (never wider, whatever the umask)."""
    if not api_key.strip():
        raise CliError("api key must not be empty", client=True)
    payload = json.dumps({"base_url": validate_base_url(base_url), "api_key": api_key.strip()})
    path = profile_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=CONFIG_DIR_MODE)
    staging = path.with_name(path.name + ".tmp")
    fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PROFILE_MODE)
    try:
        os.fchmod(fd, PROFILE_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
    except BaseException:
        staging.unlink(missing_ok=True)
        raise
    os.replace(staging, path)
    return path


def malformed_profile_error() -> CliError:
    return CliError(
        f"profile {profile_path()} is malformed; run 'sandfort login' again", client=True
    )


_warned_profile_paths: set[Path] = set()


def warn_if_profile_is_open(path: Path) -> None:
    """Once per process and path, say on stderr that a profile readable by group or others
    should be locked down, with the ``chmod`` command to paste. Never names the key. Skipped
    where the platform has no POSIX modes and in ``--json`` mode (like the other notes)."""
    if os.name != "posix" or path in _warned_profile_paths or _json_errors.get():
        return
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return
    if not mode & KEY_FILE_FORBIDDEN_MODE_BITS:
        return
    _warned_profile_paths.add(path)
    hint = shlex.quote(scrub_local(str(path), ""))
    typer.echo(
        f"warning: profile {hint} is readable by group or others (mode {mode:03o}) and holds "
        f"your api key; run 'chmod {PROFILE_MODE:o} {hint}'",
        err=True,
    )


def read_profile() -> dict[str, Any]:
    """The profile as stored (any value type); ``{}`` when there is no profile file. A profile
    whose mode lets group or others read it is used, with one warning on stderr."""
    path = profile_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, RecursionError):  # unreadable, not json, or nested too deeply
        raise CliError(
            f"profile {path} is unreadable; run 'sandfort login' again", client=True
        ) from None
    warn_if_profile_is_open(path)
    if not isinstance(raw, dict):
        raise malformed_profile_error()
    return raw


def load_profile() -> dict[str, str]:
    return {key: value for key, value in read_profile().items() if isinstance(value, str)}


def stored_base_url(raw: dict[str, Any]) -> str | None:
    """The profile's base url; ``None`` when the field is absent.

    A field that is present but not a usable string (a number, null, a list, an empty or
    blank string) makes the profile malformed, which is not the same as being logged out.
    """
    if "base_url" not in raw:
        return None
    value = raw["base_url"]
    if not isinstance(value, str) or not value.strip():
        raise malformed_profile_error()
    return value


def stored_api_key(raw: dict[str, Any]) -> str | None:
    """The profile's api key; ``None`` when the field is absent (not logged in).

    A field that is present but not a json string (a number, null, a list, an object, a
    boolean) or is the empty string is a damaged profile, not a logged-out one: the unified
    usage error (exit 2) naming the profile path. The value itself is never echoed. Any other
    string goes on to :func:`check_profile_key` unchanged.
    """
    if PROFILE_KEY_FIELD not in raw:
        return None
    value = raw[PROFILE_KEY_FIELD]
    if not isinstance(value, str):
        raise ProfileKeyError(NOT_A_STRING_KEY_MESSAGE)
    if not value:
        raise ProfileKeyError(EMPTY_KEY_MESSAGE)
    return value


class ProfileKeyError(typer.BadParameter):
    """A usage error (exit 2) about the stored profile's api key, worded
    ``api_key in <profile path> <problem>`` without click's ``Invalid value for`` frame."""

    def __init__(self, problem: str) -> None:
        super().__init__(f"{PROFILE_KEY_FIELD} in {profile_path()} {problem}")

    def format_message(self) -> str:
        return self.message


def key_problem(api_key: str) -> str | None:
    """Why a configured key cannot go into the Authorization header; ``None`` when it can."""
    if len(api_key.strip()) > MAX_API_KEY_CHARS:
        return TOO_LONG_KEY_MESSAGE
    if API_KEY_TOKEN_RE.fullmatch(api_key.strip()) is None:
        return MALFORMED_KEY_MESSAGE
    return None


def check_configured_key(api_key: str, source: str, subject: str | None = None) -> None:
    """A configured key that cannot go into the Authorization header (inner whitespace, a
    control or non-ASCII character) is the unified usage error (exit 2), naming only where it
    came from; the key itself is never echoed. A key longer than ``MAX_API_KEY_CHARS`` is a
    usage error too (a "too long" one), whatever it holds.

    Surrounding whitespace is judged differently by source: a key from the environment or the
    ``--api-key`` option passes with it (the check looks at the stripped key, which is what is
    sent), while a stored profile key with it is refused (:func:`check_profile_key`).

    ``subject`` (``the api key read from stdin``) makes the message a full sentence that names
    where the key came from; without it the message is the bare problem after ``source``."""
    problem = key_problem(api_key)
    if problem is not None:
        message = problem if subject is None else f"{subject} {problem}"
        raise typer.BadParameter(message, param_hint=source)


def check_profile_key(api_key: str) -> None:
    """:func:`check_configured_key` for the stored profile's key, as a :class:`ProfileKeyError`;
    every problem (too long, malformed, whitespace-only or surrounded by whitespace) ends with
    the login hint, like the other damaged-profile errors. A key with surrounding whitespace
    is refused, not stripped and sent."""
    problem = key_problem(api_key)
    if problem is None and api_key != api_key.strip():
        # Never stripped and sent: a stored key with surrounding whitespace is damaged too.
        problem = MALFORMED_KEY_MESSAGE
    if problem is None:
        return
    raise ProfileKeyError(problem + LOGIN_TAIL)


def key_file_error(problem: str) -> typer.BadParameter:
    """A usage error (exit 2) about ``SANDFORT_API_KEY_FILE``; ``problem`` never holds the key."""
    return typer.BadParameter(problem, param_hint=API_KEY_FILE_ENV)


def check_key_file_status(status: os.stat_result, path: Path) -> None:
    """Refuse a key file that is not a regular file; on POSIX also one owned by another user or
    readable by group or others. Where the platform has no POSIX modes the mode and owner
    checks are skipped."""
    if not stat.S_ISREG(status.st_mode):
        raise key_file_error("path is not a regular file")
    if os.name != "posix":
        return
    if status.st_uid != os.geteuid():
        raise key_file_error("file is not owned by the current user")
    mode = stat.S_IMODE(status.st_mode)
    if mode & KEY_FILE_FORBIDDEN_MODE_BITS:
        # The path is shown so it can be pasted: control characters removed, shell-quoted.
        hint = shlex.quote(scrub_local(str(path), ""))
        raise key_file_error(
            f"file is readable by group or others (mode {mode:03o}); run 'chmod 600 {hint}'"
        )


def read_key_lines(handle: BinaryIO) -> list[str]:
    """The non-blank lines of a key file, at most two (a second one is already too many).

    Every line is cut at ``KEY_FILE_READ_LIMIT`` bytes and at most ``KEY_FILE_MAX_LINES`` lines
    are scanned; a line longer than the limit is malformed. A UTF-8 byte order mark is ignored.
    """
    lines: list[str] = []
    for _ in range(KEY_FILE_MAX_LINES):
        raw = handle.readline(KEY_FILE_READ_LIMIT)
        if not raw:
            return lines
        if len(raw) >= KEY_FILE_READ_LIMIT and not raw.endswith(b"\n"):
            raise key_file_error(
                f"a line is longer than {KEY_FILE_READ_LIMIT} characters; file "
                + MALFORMED_KEY_MESSAGE
            )
        try:
            text = raw.decode("utf-8-sig").strip()
        except UnicodeDecodeError:
            raise key_file_error("file is not valid text (UTF-8)") from None
        if text:
            lines.append(text)
            if len(lines) > 1:
                return lines
    if lines and handle.read(1):  # more than the scanned lines: not a one-key file
        lines.append("")
    return lines


def read_key_file(raw_path: str, label: str = API_KEY_FILE_ENV) -> str:
    """The key in the file at ``raw_path``: its one non-blank line, whitespace stripped.

    A missing, unreadable, non-regular, empty or non-text file, a path that cannot be expanded
    (``~user`` of an unknown user) or opened, a line longer than ``KEY_FILE_READ_LIMIT``, a
    file with more than one non-blank line (``label`` must hold exactly one key line; nothing
    of the content is echoed), or (on POSIX) a file owned by another user or accessible to
    group or others (mode wider than 600), is a usage error naming the variable and the
    problem. Blank lines before or after the key are ignored. The mode and owner checks
    are skipped where the platform has no POSIX modes. A UTF-8 byte order mark is ignored. The
    status is read from the opened descriptor, so the checked file is the read one; a symlink
    is followed.
    """
    try:
        path = Path(raw_path).expanduser()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except (FileNotFoundError, NotADirectoryError):
        raise key_file_error("file does not exist") from None
    except (RuntimeError, ValueError):  # unknown ~user (no home directory), or a NUL byte
        raise key_file_error("path is not valid (it cannot be expanded or opened)") from None
    except OSError:
        raise key_file_error("file cannot be read") from None
    try:
        check_key_file_status(os.fstat(fd), path)
    except BaseException:
        os.close(fd)
        raise
    try:
        with os.fdopen(fd, "rb") as handle:
            lines = read_key_lines(handle)
    except OSError:
        raise key_file_error("file cannot be read") from None
    if len(lines) > 1:
        raise key_file_error(f"{label} must hold exactly one key line")
    if not lines:
        raise key_file_error("file is empty (it must hold the key on one line)")
    return lines[0]


def key_from_file_variable(subject: str | None = None) -> str | None:
    """The checked key named by ``SANDFORT_API_KEY_FILE``; ``None`` when it is unset or empty.
    ``subject`` is passed on to :func:`check_configured_key`."""
    raw_path = os.environ.get(API_KEY_FILE_ENV)
    if not raw_path:
        return None
    key = read_key_file(raw_path)
    check_configured_key(key, API_KEY_FILE_ENV, subject)
    return key


def resolve_settings() -> Settings:
    """Base url and key from the environment, falling back to the stored profile.

    The key comes from ``SANDFORT_API_KEY``, else the file named by ``SANDFORT_API_KEY_FILE``,
    else the profile. Userinfo in a configured url is dropped before the client is built (it
    would replace the api key with a Basic authorization header); text mode says so on stderr.
    """
    raw = read_profile()
    env_url = os.environ.get(BASE_URL_ENV)
    base_url = env_url or stored_base_url(raw)
    # The environment overrides the profile, so a damaged profile key only matters without it,
    # and a key file is only read when SANDFORT_API_KEY is not set.
    env_key = os.environ.get(API_KEY_ENV)
    file_key = None if env_key else key_from_file_variable()
    api_key = env_key or file_key or stored_api_key(raw)
    if not base_url or not api_key:
        raise CliError(NOT_LOGGED_IN_MESSAGE, client=True)
    if env_key:
        check_configured_key(api_key, API_KEY_ENV)
    elif not file_key:
        check_profile_key(api_key)
    source = BASE_URL_ENV if env_url else f"base_url in {profile_path()}"
    # Imported here, not at module level: the validator lives with the login code, which
    # imports this module (a top-level import would be a cycle).
    from sandfort_cli.sandboxes import (
        USERINFO_REMOVED_CONFIGURED_NOTE,
        check_configured_url,
        strip_userinfo,
    )

    typed = check_configured_url(base_url, source, api_key)
    cleaned = strip_userinfo(typed)
    if cleaned != typed and not _json_errors.get():
        typer.echo(USERINFO_REMOVED_CONFIGURED_NOTE, err=True)
    return Settings(base_url=validate_base_url(cleaned), api_key=api_key)


def open_client() -> Client:
    settings = resolve_settings()
    return Client(settings.base_url, settings.api_key)
