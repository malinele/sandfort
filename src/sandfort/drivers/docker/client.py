"""docker-py client factory, error translation and the blocking-call entry point.

``docker`` is imported lazily so importing this module never imports docker-py.
Every blocking docker-py call goes through ``run_blocking`` (architecture D6). The limiter
state and the runner live in ``lanes``; the names below delegate to it so call sites and
tests keep importing them from here.
"""

import atexit
import contextvars
import errno
import importlib
import logging
import os
import re
import shutil
import tempfile
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from types import ModuleType
from typing import Any

from sandfort.drivers.docker import lanes
from sandfort.drivers.errors import (
    DriverConflict,
    DriverError,
    DriverNotFound,
    DriverUnsupported,
)

logger = logging.getLogger(__name__)

DEFAULT_THREAD_LIMIT = lanes.DEFAULT_THREAD_LIMIT
# Opt-in to the server user's Docker config (registry logins); off by default.
USER_CONFIG_ENV = "SANDFORT_DOCKER_USER_CONFIG"
ISOLATED_CONFIG_PREFIX = "sandfort-docker-config-"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_config_lock = threading.RLock()
_isolated_dir: str | None = None
HTTP_CONFLICT = 409
# Lowercase marker of a full sandbox filesystem in daemon text; the raw text carries host paths.
_DISK_FULL_MARKER = "no space left on device"
DISK_FULL_MESSAGE = (
    "the sandbox disk is full (no space left on device): delete files in the sandbox "
    "or create it with a larger disk_gib"
)
# The daemon url docker-py embeds in error text (``http+docker://localhost/v1.43/...``), with an
# optional leading "for" and without a trailing colon, so "Error for URL: msg" becomes "Error: msg".
_INTERNAL_URL = re.compile(r"(?:\bfor\s+)?\b[a-z][a-z0-9+.-]*://[^\s'\"]*[^\s'\":]", re.IGNORECASE)
_FALLBACK_MESSAGE = "the Docker daemon rejected the request"
# The only text a tenant sees for a daemon failure that is not classified (not found, conflict,
# disk full, pull refusal): the daemon text can name host paths, sockets and runtime internals.
GENERIC_DRIVER_MESSAGE = "the sandbox runtime reported an error; the details are in the server log"
DEFAULT_OPERATION = "docker call"
# A write into a read-only mount: the daemon says "read-only file system" (or, for a volume,
# "mounted volume is marked read-only"), a local failure carries errno EROFS. Only the archive
# put is classified: elsewhere the same text can come from the runtime and names host paths.
_READ_ONLY_MARKERS = ("read-only file system", "marked read-only")
READ_ONLY_OPERATIONS = frozenset({"archive.put"})
READ_ONLY_MESSAGE = "the path is on a read-only mount"
MAX_PATH_ECHO = 200
_PATH_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
# A container id in daemon text: the 64-character form anywhere, or a short form (12 or more hex
# characters) directly after the word "container", with an optional colon. The "No such
# container: " prefix is captured so the replacement keeps it ("No such container: <placeholder>").
_CONTAINER_REFERENCE = re.compile(
    r"(\bNo such container:\s+)[0-9a-f]{12,}\b"
    r"|\bcontainer:?\s+[0-9a-f]{12,}\b"
    r"|\b[0-9a-f]{64}\b",
    re.IGNORECASE,
)
_CONTAINER_PHRASE = "the sandbox container"
# The daemon's pull-denial sentence ("pull access denied for X, repository does not exist or may
# require 'docker login'"); it leaks registry detail, so the whole sentence is replaced.
_PULL_DENIAL = re.compile(
    r"(?:\bpull access denied for\s+\S+?,?\s+)?"
    r"\brepository does not exist or may require\s+['\"]?docker login['\"]?",
    re.IGNORECASE,
)
PULL_DENIAL_PHRASE = "the image could not be pulled"
# The image operations whose failures may be read as a pull denial and whose daemon-text log
# line is routine (the classifiers log the outcome), so it is INFO instead of WARNING.
PULL_OPERATIONS = frozenset({"image.pull", "image.build"})
# The only tenant-facing text of a not-found or conflict failure that matches no whitelist entry;
# the daemon text (it can name host paths and runtime internals) stays in ``daemon_text``.
NOT_FOUND_MESSAGE = "the object does not exist"
CONFLICT_MESSAGE = "the operation conflicts with the current state"
# Daemon phrases that carry only object names the tenant supplied (matched against the whole
# cleaned text, so nothing else can ride along). ``clean_message`` turns a container id into
# "the sandbox container", which the container patterns accept. "No such exec instance" and
# "is not running" are the markers the exec module and the toolbox process route look for.
_OBJECT_NAME = r"[\w][\w.-]*"
_CONTAINER_NAME = rf"(?:the sandbox container|container {_OBJECT_NAME})"
# An exec id is 64 hex characters, which ``clean_message`` turns into the container placeholder;
# a short hex id or a plain word (letters, digits, dots, underscores, dashes) is kept as it is.
_EXEC_ID = rf"(?:{_CONTAINER_PHRASE}|[A-Za-z0-9._-]+)"
_SAFE_DAEMON_PHRASES = re.compile(
    "|".join(
        (
            rf"No such container: (?:{_CONTAINER_PHRASE}|{_OBJECT_NAME})",
            r"No such image: [\w][\w.:@/-]*",
            rf"No such volume: {_OBJECT_NAME}",
            rf"No such exec instance(?: '{_EXEC_ID}' found in daemon|: {_EXEC_ID})?",
            rf"(?:{_CONTAINER_NAME}|{_OBJECT_NAME}) is not running",
            rf"container name \"?/?{_OBJECT_NAME}\"? is already in use",
            rf"removal of {_CONTAINER_NAME} is already in progress",
            rf"{_CONTAINER_NAME} is paused",
        )
    ),
    re.IGNORECASE,
)
# Name of the tracing module's context variable holding the running job's org and sandbox ids.
JOB_IDS_CONTEXT_VAR = "sandfort_job_ids"
# The warning line keeps at most this much daemon text (an OCI error can echo a command line).
MAX_LOGGED_DAEMON_TEXT = 500
# The resolver address Go appends to a DNS failure ("lookup <host> on 127.0.0.53:53" or
# "on [::1]:53"); it names the host's resolver, so only "lookup <host>" is kept.
_RESOLVER_DETAIL = re.compile(
    r"(\blookup\s+\S+?)\s+on\s+(?:\d{1,3}(?:\.\d{1,3}){3}|\[[\w:.%-]+\]):\d+", re.IGNORECASE
)

# Control lane: one total token per call. Same name and signature as before the lanes existed.
run_blocking = lanes.run_blocking
# ``configure_thread_limit(limit, bulk)`` sizes both lanes; ``bulk`` has a default.
configure_thread_limit = lanes.configure_thread_limit
# The total limiter, unchanged for tests that read ``borrowed_tokens`` from it.
_get_limiter = lanes.total_limiter


def load_docker_module() -> ModuleType:
    """Import docker-py on demand; raise DriverUnsupported when it is missing."""
    try:
        return importlib.import_module("docker")
    except ImportError as exc:
        raise DriverUnsupported("docker-py is not installed") from exc


def docker_errors() -> ModuleType:
    """The ``docker.errors`` module, imported on demand."""
    load_docker_module()
    return importlib.import_module("docker.errors")


def _isolated_config_dir() -> str:
    """The private, empty Docker config directory (created once, removed at exit)."""
    global _isolated_dir
    with _config_lock:
        if _isolated_dir is None:
            directory = tempfile.mkdtemp(prefix=ISOLATED_CONFIG_PREFIX)  # mode 0700
            with open(os.path.join(directory, "config.json"), "w", encoding="utf-8") as handle:
                handle.write("{}")
            atexit.register(shutil.rmtree, directory, ignore_errors=True)
            _isolated_dir = directory
        return _isolated_dir


def user_docker_config_allowed(environ: Mapping[str, str] | None = None) -> bool:
    """True when the operator explicitly lets the client read the server user's Docker config."""
    value = (os.environ if environ is None else environ).get(USER_CONFIG_ENV, "")
    return value.strip().lower() in _TRUE_VALUES


@contextmanager
def _docker_config_env(use_user_config: bool) -> Iterator[None]:
    """Point ``DOCKER_CONFIG`` at the empty directory while docker-py reads its credential
    store (it does so when the client is built), then restore the previous value."""
    if use_user_config:
        yield
        return
    directory = _isolated_config_dir()
    with _config_lock:
        previous = os.environ.get("DOCKER_CONFIG")
        os.environ["DOCKER_CONFIG"] = directory
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop("DOCKER_CONFIG", None)
            else:
                os.environ["DOCKER_CONFIG"] = previous


def make_client(
    base_url: str | None = None,
    max_pool_size: int | None = None,
    use_user_config: bool | None = None,
) -> Any:
    """Build a docker-py client from ``base_url`` or the standard environment.

    ``max_pool_size`` is docker-py's connection pool width; ``None`` keeps its default. The
    client gets an empty credential store (an isolated ``DOCKER_CONFIG`` directory), so the
    operator's registry logins never serve tenant pulls. ``use_user_config`` lets it read the
    server user's Docker config instead; ``None`` follows ``SANDFORT_DOCKER_USER_CONFIG``.
    """
    docker = load_docker_module()
    errors = docker_errors()
    options: dict[str, Any] = {} if max_pool_size is None else {"max_pool_size": max_pool_size}
    allow_user = user_docker_config_allowed() if use_user_config is None else use_user_config
    try:
        with _docker_config_env(allow_user):
            if base_url is None:
                return docker.from_env(**options)
            return docker.DockerClient(base_url=base_url, **options)
    except errors.DockerException as exc:
        raise DriverError(f"cannot connect to the Docker daemon: {clean_message(exc)}") from exc


def _container_replacement(match: re.Match[str]) -> str:
    """The placeholder for a container id; the "No such container: " prefix is kept."""
    prefix = match.group(1)
    return _CONTAINER_PHRASE if prefix is None else f"{prefix}{_CONTAINER_PHRASE}"


def clean_message(exc: BaseException) -> str:
    """Customer-safe text for a docker-py / requests failure.

    Prefers the daemon's own explanation (docker ``APIError.explanation``). Otherwise the raw
    text is used. Either way every internal daemon url is removed, so no message carries the
    ``http+docker`` scheme, the host or the API version path. Container ids (64 hex characters,
    or a 12+ character short id after the word "container") become "the sandbox container".
    The pull-denial sentence ("... repository does not exist or may require 'docker login'")
    becomes "the image could not be pulled". A DNS failure's resolver address ("lookup host on
    127.0.0.53:53", IPv4 or bracketed IPv6) is dropped, leaving "lookup host".
    """
    explanation = getattr(exc, "explanation", None)
    if isinstance(explanation, str) and explanation.strip():
        raw = explanation.strip()
    else:
        raw = str(exc)
    unlinked = _PULL_DENIAL.sub(PULL_DENIAL_PHRASE, _INTERNAL_URL.sub("", raw))
    resolved = _RESOLVER_DETAIL.sub(r"\1", unlinked)
    redacted = _CONTAINER_REFERENCE.sub(_container_replacement, resolved)
    text = " ".join(redacted.split()).replace(" :", ":")
    return text or _FALLBACK_MESSAGE


def echo_path(path: str) -> str:
    """``path`` as it may be echoed in a message: control characters become ``?`` and a long
    path is cut at ``MAX_PATH_ECHO`` characters."""
    cleaned = _PATH_CONTROL_CHARS.sub("?", path)
    if len(cleaned) > MAX_PATH_ECHO:
        return cleaned[:MAX_PATH_ECHO] + "..."
    return cleaned


class DriverReadOnlyPath(DriverError):
    """A write landed on a read-only mount (the API answers 409 READ_ONLY_PATH).

    ``path`` is the directory the caller wrote into, as sent by the caller; ``None`` until the
    archive module, which knows it, fills it in.
    """

    def __init__(
        self,
        message: str = READ_ONLY_MESSAGE,
        *,
        ref: str | None = None,
        daemon_text: str | None = None,
        path: str | None = None,
    ) -> None:
        super().__init__(message, ref=ref, daemon_text=daemon_text)
        self.path = path

    @classmethod
    def for_path(cls, path: str, *, ref: str | None = None) -> "DriverReadOnlyPath":
        """The error for ``path``; the message names it in its sanitised form."""
        message = f"{echo_path(path)} is on a read-only mount; nothing was written"
        return cls(message, ref=ref, path=echo_path(path))


def _is_read_only_failure(exc: BaseException) -> bool:
    if isinstance(exc, OSError) and exc.errno == errno.EROFS:
        return True
    text = clean_message(exc).lower()
    return any(marker in text for marker in _READ_ONLY_MARKERS)


def _generic_error(exc: BaseException, ref: str | None) -> DriverError:
    """The driver error for an unclassified daemon failure: the fixed sentence for the tenant,
    the cleaned daemon text out of band in ``daemon_text`` (classifiers and the server log)."""
    return DriverError(GENERIC_DRIVER_MESSAGE, ref=ref, daemon_text=clean_message(exc))


def _safe_object_error(
    kind: type[DriverNotFound] | type[DriverConflict],
    fixed: str,
    exc: BaseException,
    ref: str | None,
) -> DriverError:
    """A not-found or conflict error: the cleaned daemon text only when it is a whitelisted
    phrase, else the fixed sentence ``fixed`` with the daemon text in ``daemon_text``."""
    text = clean_message(exc)
    if _SAFE_DAEMON_PHRASES.fullmatch(text) is not None:
        return kind(text, ref=ref)
    return kind(fixed, ref=ref, daemon_text=text)


def map_driver_error(
    exc: BaseException, ref: str | None = None, operation: str = DEFAULT_OPERATION
) -> DriverError | None:
    """Map a docker-py / requests failure to a driver error, without logging; ``None`` if
    unrelated.

    Not-found and conflict failures keep the cleaned daemon text only when it is a whitelisted
    phrase naming tenant-supplied objects; otherwise they get a fixed sentence. A disk-full
    conflict has its own fixed sentence. The pull-denial sentence maps to ``DriverNotFound``
    with its cleaned text only for ``image.pull`` and ``image.build``. Every other failure gets
    ``GENERIC_DRIVER_MESSAGE`` as its message. Wherever the message is a fixed sentence the
    cleaned daemon text is in ``daemon_text``.
    """
    errors = docker_errors()
    requests_exceptions = importlib.import_module("requests.exceptions")
    if operation in READ_ONLY_OPERATIONS and _is_read_only_failure(exc):
        # The destination is added by the caller that knows it; the daemon text is not kept.
        logger.debug("docker reported a read-only path: %s", clean_message(exc))
        return DriverReadOnlyPath(ref=ref)
    if isinstance(exc, errors.NotFound):
        return _safe_object_error(DriverNotFound, NOT_FOUND_MESSAGE, exc, ref)
    if isinstance(exc, errors.APIError):
        message = clean_message(exc)
        if _DISK_FULL_MARKER in message.lower():
            # The raw text names host storage paths; keep it at debug level only.
            logger.debug("docker reported a full disk: %s", message)
            return DriverConflict(DISK_FULL_MESSAGE, ref=ref)
        if exc.status_code == HTTP_CONFLICT:
            return _safe_object_error(DriverConflict, CONFLICT_MESSAGE, exc, ref)
        if PULL_DENIAL_PHRASE in message:  # a reference the daemon cannot pull is not found
            if operation in PULL_OPERATIONS:
                return DriverNotFound(message, ref=ref)
            return DriverNotFound(NOT_FOUND_MESSAGE, ref=ref, daemon_text=message)
        return _generic_error(exc, ref)
    if isinstance(exc, errors.DockerException | requests_exceptions.RequestException):
        return _generic_error(exc, ref)
    return None


def _job_ids() -> dict[str, str]:
    """Org and sandbox ids of the job being run, from the tracing context variable, if set.

    The variable is found by name in the current context: the tracing module sits above the
    driver layer (it imports workers), so drivers must not import it.
    """
    for variable, value in contextvars.copy_context().items():
        if variable.name == JOB_IDS_CONTEXT_VAR and isinstance(value, Mapping):
            return {str(key): str(item) for key, item in value.items()}
    return {}


def _log_generic(mapped: DriverError, operation: str) -> None:
    """Log with the operation, the ref, the job ids and the bounded daemon text: INFO for a pull
    or build (a tenant controls how many fail), WARNING for every other operation."""
    text = (mapped.daemon_text or "")[:MAX_LOGGED_DAEMON_TEXT]
    jobs = "".join(f", {key}={value}" for key, value in sorted(_job_ids().items()))
    level = logging.INFO if operation in PULL_OPERATIONS else logging.WARNING
    logger.log(level, "docker %s failed (ref=%s%s): %s", operation, mapped.ref, jobs, text)


def as_driver_error(
    exc: BaseException, ref: str | None = None, operation: str = DEFAULT_OPERATION
) -> DriverError | None:
    """``map_driver_error`` plus a log line (WARNING; INFO for pull and build) for a failure
    whose daemon text is kept out of band.

    The line carries ``operation``, ``ref``, the job ids of the enclosing job (when set) and the
    cleaned daemon text truncated to ``MAX_LOGGED_DAEMON_TEXT`` characters.
    """
    mapped = map_driver_error(exc, ref, operation)
    if mapped is not None and mapped.daemon_text is not None:
        _log_generic(mapped, operation)
    return mapped


@contextmanager
def translate_errors(ref: str | None, operation: str) -> Iterator[None]:
    """Re-raise docker-py failures as ``drivers.errors`` types; ``operation`` names the call
    (for example ``container.create``) in the server log."""
    try:
        yield
    except DriverError:
        raise
    except Exception as exc:
        mapped = as_driver_error(exc, ref, operation)
        if mapped is None:
            raise
        raise mapped from exc
