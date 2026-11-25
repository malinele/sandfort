"""Immutable value objects returned by the clients."""

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any

from sandfort_sdk.exceptions import InvalidResponseError

COMMAND_RUNNING = "running"
STREAM_EXIT = "exit"
DEFAULT_ISOLATION = "container"


def _as_dict(data: Any, what: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise InvalidResponseError(f"expected an object for {what}, got {type(data).__name__}")
    return data


def _as_list(data: Any, what: str) -> list[Any]:
    if not isinstance(data, list):
        raise InvalidResponseError(f"expected a list for {what}, got {type(data).__name__}")
    return data


def _required(raw: dict[str, Any], what: str, *keys: str) -> list[Any]:
    for key in keys:
        if key not in raw:
            raise InvalidResponseError(f"{what} payload is missing {key!r}")
    return [raw[key] for key in keys]


def _optional_str(value: Any, what: str) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise InvalidResponseError(f"expected a string or null for {what}, got {value!r}")


def _str(value: Any, what: str) -> str:
    if isinstance(value, str):
        return value
    raise InvalidResponseError(f"expected a string for {what}, got {value!r}")


def _int(value: Any, what: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise InvalidResponseError(f"expected an integer for {what}, got {value!r}")


def _egress_allowlist(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return None
    return tuple(
        _str(item, "sandbox egress_allowlist entry")
        for item in _as_list(value, "sandbox egress_allowlist")
    )


def _bool(value: Any, what: str) -> bool:
    if isinstance(value, bool):
        return value
    raise InvalidResponseError(f"expected a boolean for {what}, got {value!r}")


def _optional_bool(value: Any, what: str) -> bool | None:
    if value is None or isinstance(value, bool):
        return value
    raise InvalidResponseError(f"expected a boolean or null for {what}, got {value!r}")


def _freeze(value: Any) -> Any:
    """Mappings become read-only proxies and lists tuples, recursively (copies, no aliasing)."""
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def require_int_range(value: object, name: str, minimum: int, maximum: int) -> int:
    """``value`` if it is an ``int`` (not a ``bool``, not a float such as ``5.0``) in range.

    Raises ``ValueError`` naming ``name`` and the bounds. The audit facade's list ``limit``
    check only rejects ``bool`` today and so accepts ``5.0``; its next change should call
    this helper instead of the inline comparison.
    """
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(
            f"{name} must be an integer between {minimum} and {maximum}; got {value!r}"
        )
    return value


def _timestamp(value: Any, what: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidResponseError(f"expected an ISO timestamp for {what}, got {value!r}")
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise InvalidResponseError(f"invalid timestamp for {what}: {value!r}") from exc


def _required_timestamp(value: Any, what: str) -> datetime:
    parsed = _timestamp(value, what)
    if parsed is None:
        raise InvalidResponseError(f"{what} payload is missing a timestamp")
    return parsed


@dataclass(frozen=True, slots=True)
class Resources:
    cpu_millicores: int = 1000
    memory_mib: int = 512
    disk_gib: int = 3

    def to_payload(self) -> dict[str, int]:
        return {
            "cpu_millicores": self.cpu_millicores,
            "memory_mib": self.memory_mib,
            "disk_gib": self.disk_gib,
        }

    @classmethod
    def from_payload(cls, data: Any) -> "Resources":
        raw = _as_dict(data, "resources")
        return cls(
            cpu_millicores=raw.get("cpu_millicores", 1000),
            memory_mib=raw.get("memory_mib", 512),
            disk_gib=raw.get("disk_gib", 3),
        )


@dataclass(frozen=True, slots=True)
class MountInfo:
    """A volume mount of a sandbox as the server reports it."""

    volume_id: str
    mount_path: str
    read_only: bool = False  # servers before read-only mounts omit it

    @classmethod
    def from_payload(cls, data: Any) -> "MountInfo":
        raw = _as_dict(data, "mount")
        volume_id, mount_path = _required(raw, "mount", "volume_id", "mount_path")
        return cls(volume_id, mount_path, bool(raw.get("read_only", False)))


@dataclass(frozen=True, slots=True)
class SandboxInfo:
    id: str
    name: str
    state: str
    resources: Resources = field(default_factory=Resources)
    env: dict[str, str] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)
    block_network: bool = False
    public: bool = False
    auto_stop_minutes: int = 15
    auto_delete_minutes: int = -1
    error_reason: str | None = None
    job_id: str | None = None
    isolation: str = DEFAULT_ISOLATION  # servers before isolation tiers omit it
    snapshot: str | None = None  # None while the server does not report it
    created_at: datetime | None = None  # None while the server does not report it
    updated_at: datetime | None = None  # None while the server does not report it
    # Machine-readable code next to error_reason (e.g. "image_not_found", "timeout");
    # None when there is no error or the server does not report it. The known values are in
    # sandfort_sdk.error_codes (str on purpose, see there). Kept last so the
    # positional order of the fields before it stays stable.
    error_code: str | None = None
    # When the sandbox stopped; None unless the state is "stopped" or the server does not
    # report it. Appended after error_code so the fields before it keep their order.
    stopped_at: datetime | None = None
    # Why it stopped ("requested", "auto_stop", "container_exited", "oom_killed", "unknown");
    # None unless the state is "stopping" or "stopped" or the server does not report it.
    stop_cause: str | None = None
    # Volume mounts; empty when there are none or the server does not report them.
    volumes: tuple[MountInfo, ...] = ()
    # Paths the image declares as volumes (mounts the image brings); empty when it has none or
    # the server does not report them (older servers).
    image_mounts: tuple[str, ...] = ()
    # Version of the egress policy; 0 when the server does not report it (older servers, a
    # sandbox created without an allowlist). Appended last so earlier positions stay stable.
    egress_policy_generation: int = 0
    # Allowed egress entries; None when the sandbox has no allowlist or the server does not
    # report one, () when every connection is blocked.
    egress_allowlist: tuple[str, ...] | None = None

    @classmethod
    def from_payload(cls, data: Any) -> "SandboxInfo":
        raw = _as_dict(data, "sandbox")
        try:
            sandbox_id, name, state = raw["id"], raw["name"], raw["state"]
        except KeyError as exc:
            raise InvalidResponseError(f"sandbox payload is missing {exc}") from exc
        return cls(
            id=sandbox_id,
            name=name,
            state=state,
            resources=Resources.from_payload(raw.get("resources") or {}),
            env=dict(raw.get("env") or {}),
            labels=dict(raw.get("labels") or {}),
            block_network=bool((raw.get("network") or {}).get("block_all", False)),
            public=bool(raw.get("public", False)),
            auto_stop_minutes=raw.get("auto_stop_minutes", 15),
            auto_delete_minutes=raw.get("auto_delete_minutes", -1),
            error_reason=raw.get("error_reason"),
            job_id=raw.get("job_id"),
            isolation=raw.get("isolation") or DEFAULT_ISOLATION,
            error_code=_optional_str(raw.get("error_code"), "sandbox error_code"),
            snapshot=_optional_str(raw.get("snapshot"), "sandbox snapshot"),
            created_at=_timestamp(raw.get("created_at"), "sandbox created_at"),
            updated_at=_timestamp(raw.get("updated_at"), "sandbox updated_at"),
            stopped_at=_timestamp(raw.get("stopped_at"), "sandbox stopped_at"),
            stop_cause=_optional_str(raw.get("stop_cause"), "sandbox stop_cause"),
            volumes=tuple(
                MountInfo.from_payload(item)
                for item in _as_list(raw.get("volumes") or [], "sandbox volumes")
            ),
            image_mounts=tuple(
                _str(item, "sandbox image_mounts entry")
                for item in _as_list(raw.get("image_mounts") or [], "sandbox image_mounts")
            ),
            egress_policy_generation=(
                0
                if raw.get("egress_policy_generation") is None
                else _int(
                    raw.get("egress_policy_generation"), "sandbox egress_policy_generation"
                )
            ),
            egress_allowlist=_egress_allowlist(raw.get("egress_allowlist")),
        )


@dataclass(frozen=True, slots=True)
class PreviewInfo:
    """A minted preview token and the URL that reaches one port of a sandbox through the proxy."""

    url: str
    token: str
    port: int
    expires_at: datetime

    @classmethod
    def from_payload(cls, data: Any) -> "PreviewInfo":
        raw = _as_dict(data, "preview token")
        url, token, port = _required(raw, "preview token", "url", "token", "port")
        return cls(url, token, port, _required_timestamp(raw.get("expires_at"), "preview token"))


@dataclass(frozen=True, slots=True)
class IsolationInfo:
    """The isolation tiers a server offers and the one a create gets when it names none."""

    default: str
    available: tuple[str, ...]

    @classmethod
    def from_payload(cls, data: Any) -> "IsolationInfo":
        raw = _as_dict(data, "isolation")
        default, available = _required(raw, "isolation", "default", "available")
        tiers = _as_list(available, "isolation tiers")
        return cls(default=default, available=tuple(str(tier) for tier in tiers))


@dataclass(frozen=True, slots=True)
class StatusNotice:
    """The operator notice of ``client.status()`` and when its file last changed."""

    message: str
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class StatusInfo:
    """The public status document (``GET /v1/status``, no authentication needed)."""

    status: str  # "ok" | "degraded"
    version: str
    build_sha: str | None
    started_at: datetime
    notice: StatusNotice | None = None
    # The build baked into the image the server runs from; None on older servers or when the
    # image carries no build file.
    image_sha: str | None = None
    # True when ``build_sha`` equals ``image_sha``; None when either is unknown.
    build_matches_image: bool | None = None
    # The Ed25519 public key (urlsafe base64) that verifies signed audit heads; None unless
    # the server signs heads.
    audit_public_key: str | None = None
    # A fingerprint of that key, if the server reports one (current servers do not).
    audit_key_fingerprint: str | None = None

    @classmethod
    def from_payload(cls, data: Any) -> "StatusInfo":
        raw = _as_dict(data, "status")
        status, version = _required(raw, "status", "status", "version")
        notice: StatusNotice | None = None
        if raw.get("notice") is not None:
            fields = _as_dict(raw["notice"], "status notice")
            (message,) = _required(fields, "status notice", "message")
            updated = _required_timestamp(fields.get("updated_at"), "status notice")
            notice = StatusNotice(message, updated)
        return cls(
            status=status,
            version=version,
            build_sha=_optional_str(raw.get("build_sha"), "status build_sha"),
            started_at=_required_timestamp(raw.get("started_at"), "status"),
            notice=notice,
            image_sha=_optional_str(raw.get("image_sha"), "status image_sha"),
            build_matches_image=_optional_bool(
                raw.get("build_matches_image"), "status build_matches_image"
            ),
            audit_public_key=_optional_str(raw.get("audit_public_key"), "status audit_public_key"),
            audit_key_fingerprint=_optional_str(
                raw.get("audit_key_fingerprint"), "status audit_key_fingerprint"
            ),
        )


@dataclass(frozen=True, slots=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool
    duration_ms: int
    sandbox_stopped: bool = False  # older servers omit it
    # "timeout" | "output_limit" | "sandbox_stopped" | "sandbox_deleted" | "sandbox_reset" |
    # "oom_killed" | "killed"; None for a normal exit and on older servers that omit it.
    stop_reason: str | None = None
    # The ``x-request-id`` of the reply that produced this result; None when it had no such
    # header. Set by the SDK from the reply, never read from the response body.
    request_id: str | None = None
    # True when the server answered from a stored result for the same ``idempotency_key``
    # (``Idempotent-Replayed: true``) and the command did not run again. Set by the SDK from the
    # reply header, never read from the response body.
    replayed: bool = False

    @property
    def ok(self) -> bool:
        """True only for a run that finished on its own with exit code 0.

        A run the server stopped (``stop_reason`` set, e.g. ``output_limit``), that timed out,
        or whose output was ``truncated`` is not ok even when it reports exit code 0.
        """
        return (
            self.exit_code == 0
            and self.stop_reason is None
            and not self.timed_out
            and not self.truncated
        )

    @classmethod
    def from_payload(cls, data: Any, request_id: str | None = None) -> "ExecResult":
        raw = _as_dict(data, "exec result")
        try:
            return cls(
                exit_code=raw["exit_code"],
                stdout=raw["stdout"],
                stderr=raw["stderr"],
                timed_out=raw["timed_out"],
                truncated=raw["truncated"],
                duration_ms=raw["duration_ms"],
                sandbox_stopped=bool(raw.get("sandbox_stopped", False)),
                stop_reason=_optional_str(raw.get("stop_reason"), "exec result stop_reason"),
                request_id=request_id,
            )
        except KeyError as exc:
            raise InvalidResponseError(f"exec result is missing {exc}") from exc


@dataclass(frozen=True, slots=True)
class Page[T]:
    items: tuple[T, ...]
    next_cursor: str | None = None

    def __iter__(self) -> Iterator[T]:
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)


# --- filesystem ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FileEntry:
    name: str
    path: str
    kind: str  # "file" | "dir" | "symlink"
    size_bytes: int
    mode: str
    modified_at: datetime | None = None

    @property
    def is_dir(self) -> bool:
        return self.kind == "dir"

    @classmethod
    def from_payload(cls, data: Any) -> "FileEntry":
        raw = _as_dict(data, "file entry")
        name, path, kind, size, mode = _required(
            raw, "file entry", "name", "path", "kind", "size_bytes", "mode"
        )
        return cls(name, path, kind, size, mode, _timestamp(raw.get("modified_at"), "file entry"))


@dataclass(frozen=True, slots=True)
class DirListing:
    path: str
    entries: tuple[FileEntry, ...] = ()

    @classmethod
    def from_payload(cls, data: Any) -> "DirListing":
        raw = _as_dict(data, "directory listing")
        path, entries = _required(raw, "directory listing", "path", "entries")
        items = _as_list(entries, "directory entries")
        return cls(path, tuple(FileEntry.from_payload(item) for item in items))


@dataclass(frozen=True, slots=True)
class MkdirResult:
    path: str
    created: bool

    @classmethod
    def from_payload(cls, data: Any) -> "MkdirResult":
        return cls(*_required(_as_dict(data, "mkdir result"), "mkdir result", "path", "created"))


@dataclass(frozen=True, slots=True)
class MoveResult:
    source: str
    destination: str

    @classmethod
    def from_payload(cls, data: Any) -> "MoveResult":
        raw = _as_dict(data, "move result")
        return cls(*_required(raw, "move result", "source", "destination"))


@dataclass(frozen=True, slots=True)
class DeleteResult:
    path: str
    deleted: bool

    @classmethod
    def from_payload(cls, data: Any) -> "DeleteResult":
        return cls(*_required(_as_dict(data, "delete result"), "delete result", "path", "deleted"))


@dataclass(frozen=True, slots=True)
class UploadResult:
    path: str
    size_bytes: int

    @classmethod
    def from_payload(cls, data: Any) -> "UploadResult":
        raw = _as_dict(data, "upload result")
        return cls(*_required(raw, "upload result", "path", "size_bytes"))


# --- process sessions ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SessionInfo:
    id: str
    sandbox_id: str
    cwd: str | None
    env: dict[str, str]
    state: str
    created_at: datetime

    @classmethod
    def from_payload(cls, data: Any) -> "SessionInfo":
        raw = _as_dict(data, "session")
        session_id, sandbox_id, state = _required(raw, "session", "id", "sandbox_id", "state")
        created_at = _required_timestamp(raw.get("created_at"), "session")
        env = dict(raw.get("env") or {})
        return cls(session_id, sandbox_id, raw.get("cwd"), env, state, created_at)


@dataclass(frozen=True, slots=True)
class CommandInfo:
    id: str
    session_id: str | None
    state: str  # "running" | "exited" | "killed"
    exit_code: int | None
    stdout_bytes: int
    stderr_bytes: int
    created_at: datetime
    finished_at: datetime | None = None
    # "sandbox_stopped" when a sandbox stop ended the command (state "killed", exit_code None);
    # None otherwise and on older servers. Branch on ``COMMAND_STOP_CAUSE_SANDBOX_STOPPED``;
    # a string, so a value a newer server adds does not break this SDK (see ``stop_causes``).
    stop_cause: str | None = None

    @property
    def finished(self) -> bool:
        return self.state != COMMAND_RUNNING

    @classmethod
    def from_payload(cls, data: Any) -> "CommandInfo":
        raw = _as_dict(data, "command")
        command_id, state = _required(raw, "command", "id", "state")
        return cls(
            id=command_id,
            session_id=raw.get("session_id"),
            state=state,
            exit_code=raw.get("exit_code"),
            stdout_bytes=raw.get("stdout_bytes", 0),
            stderr_bytes=raw.get("stderr_bytes", 0),
            created_at=_required_timestamp(raw.get("created_at"), "command"),
            finished_at=_timestamp(raw.get("finished_at"), "command"),
            stop_cause=_optional_str(raw.get("stop_cause"), "command stop_cause"),
        )


@dataclass(frozen=True, slots=True)
class SessionExecResult:
    """Sync executions carry ``result``; async executions carry the running ``command``."""

    mode: str  # "sync" | "async"
    cwd: str | None = None
    result: ExecResult | None = None
    command: CommandInfo | None = None

    @classmethod
    def from_payload(cls, data: Any) -> "SessionExecResult":
        raw = _as_dict(data, "session exec")
        (mode,) = _required(raw, "session exec", "mode")
        result, command = raw.get("result"), raw.get("command")
        return cls(
            mode=mode,
            cwd=raw.get("cwd"),
            result=None if result is None else ExecResult.from_payload(result),
            command=None if command is None else CommandInfo.from_payload(command),
        )


@dataclass(frozen=True, slots=True)
class LogEvent:
    """One output line (``stdout``/``stderr``) or the final ``exit`` event of a followed command.

    ``line`` is exactly one line with its terminator (a last fragment has none); ``offset`` is
    where it starts (for ``exit``: the final log size); ``next_offset`` is where a resumed read
    starts, right after this line.
    """

    stream: str
    offset: int
    line: str = ""
    next_offset: int | None = None
    exit_code: int | None = None
    state: str | None = None
    truncated: bool = False
    stop_cause: str | None = None  # on the ``exit`` event: as ``CommandInfo.stop_cause``

    @property
    def is_exit(self) -> bool:
        return self.stream == STREAM_EXIT

    @classmethod
    def from_payload(cls, data: Any) -> "LogEvent":
        raw = _as_dict(data, "log event")
        return cls(*_required(raw, "log event", "stream", "offset", "line"))


@dataclass(frozen=True, slots=True)
class LogPage:
    events: tuple[LogEvent, ...]
    next_offset: int
    truncated: bool
    complete: bool
    state: str | None = None
    exit_code: int | None = None
    stop_cause: str | None = None  # as ``CommandInfo.stop_cause``; set once ``complete``

    @classmethod
    def from_payload(cls, data: Any) -> "LogPage":
        raw = _as_dict(data, "log page")
        events, next_offset, truncated, complete = _required(
            raw, "log page", "events", "next_offset", "truncated", "complete"
        )
        return cls(
            events=tuple(LogEvent.from_payload(item) for item in _as_list(events, "log events")),
            next_offset=next_offset,
            truncated=truncated,
            complete=complete,
            state=raw.get("state"),
            exit_code=raw.get("exit_code"),
            stop_cause=_optional_str(raw.get("stop_cause"), "log page stop_cause"),
        )


# --- pty -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PtyInfo:
    id: str
    sandbox_id: str
    state: str
    rows: int
    cols: int
    created_at: datetime

    @classmethod
    def from_payload(cls, data: Any) -> "PtyInfo":
        raw = _as_dict(data, "pty")
        pty_id, sandbox_id, state, rows, cols = _required(
            raw, "pty", "id", "sandbox_id", "state", "rows", "cols"
        )
        created_at = _required_timestamp(raw.get("created_at"), "pty")
        return cls(pty_id, sandbox_id, state, rows, cols, created_at)


# --- members and single sign-on --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Member:
    user_id: str
    email: str
    display_name: str
    role: str  # "admin" | "developer" | "viewer"
    created_at: datetime

    @classmethod
    def from_payload(cls, data: Any) -> "Member":
        raw = _as_dict(data, "member")
        user_id, email, display_name, role = _required(
            raw, "member", "user_id", "email", "display_name", "role"
        )
        created_at = _required_timestamp(raw.get("created_at"), "member")
        return cls(user_id, email, display_name, role, created_at)


@dataclass(frozen=True, slots=True)
class SsoSession:
    session_token: str = field(repr=False)  # a bearer credential: kept out of reprs and logs
    expires_at: datetime
    role: str

    @classmethod
    def from_payload(cls, data: Any) -> "SsoSession":
        raw = _as_dict(data, "sso session")
        token, role = _required(raw, "sso session", "session_token", "role")
        return cls(token, _required_timestamp(raw.get("expires_at"), "sso session"), role)


# --- audit events ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuditEvent:
    id: str
    org_id: str
    actor_type: str
    action: str
    occurred_at: datetime
    outcome: str = "success"  # "success" | "denied" | "error"
    actor_id: str | None = None
    target_type: str | None = None
    target_id: str | None = None
    request_id: str | None = None
    ip: str | None = None
    user_agent: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict, hash=False)

    @classmethod
    def from_payload(cls, data: Any) -> "AuditEvent":
        raw = _as_dict(data, "audit event")
        event_id, org_id, actor_type, action = _required(
            raw, "audit event", "id", "org_id", "actor_type", "action"
        )
        outcome = raw.get("outcome")
        details = raw.get("details")
        if details is None:
            details = {}
        elif not isinstance(details, dict):
            raise InvalidResponseError(f"expected an object for audit event details: {details!r}")
        return cls(
            id=_str(event_id, "audit event id"),
            org_id=_str(org_id, "audit event org_id"),
            actor_type=_str(actor_type, "audit event actor_type"),
            action=_str(action, "audit event action"),
            occurred_at=_required_timestamp(raw.get("occurred_at"), "audit event"),
            outcome="success" if outcome is None else _str(outcome, "audit event outcome"),
            actor_id=_optional_str(raw.get("actor_id"), "audit event actor_id"),
            target_type=_optional_str(raw.get("target_type"), "audit event target_type"),
            target_id=_optional_str(raw.get("target_id"), "audit event target_id"),
            request_id=_optional_str(raw.get("request_id"), "audit event request_id"),
            ip=_optional_str(raw.get("ip"), "audit event ip"),
            user_agent=_optional_str(raw.get("user_agent"), "audit event user_agent"),
            details=_freeze(details),
        )


@dataclass(frozen=True, slots=True)
class AuditPage:
    events: tuple[AuditEvent, ...]
    next_cursor: str | None = None


@dataclass(frozen=True, slots=True)
class AuditFinding:
    kind: str  # hash_mismatch | link_broken | missing_hash | head_missing | head_invalid
    event_id: str
    detail: str

    @classmethod
    def from_payload(cls, data: Any) -> "AuditFinding":
        raw = _as_dict(data, "audit finding")
        kind, event_id, detail = _required(raw, "audit finding", "kind", "event_id", "detail")
        return cls(
            _str(kind, "audit finding kind"),
            _str(event_id, "audit finding event_id"),
            _str(detail, "audit finding detail"),
        )


@dataclass(frozen=True, slots=True)
class AuditReanchor:
    event_id: str
    acknowledged_through: str
    occurred_at: datetime
    operator: str | None = None
    reason_code: str | None = None
    note: str | None = None
    findings: int | None = None

    @classmethod
    def from_payload(cls, data: Any) -> "AuditReanchor":
        raw = _as_dict(data, "audit reanchor")
        event_id, through = _required(raw, "audit reanchor", "event_id", "acknowledged_through")
        findings = raw.get("findings")
        return cls(
            event_id=_str(event_id, "audit reanchor event_id"),
            acknowledged_through=_str(through, "audit reanchor acknowledged_through"),
            occurred_at=_required_timestamp(raw.get("occurred_at"), "audit reanchor"),
            operator=_optional_str(raw.get("operator"), "audit reanchor operator"),
            reason_code=_optional_str(raw.get("reason_code"), "audit reanchor reason_code"),
            note=_optional_str(raw.get("note"), "audit reanchor note"),
            findings=None if findings is None else _int(findings, "audit reanchor findings"),
        )


@dataclass(frozen=True, slots=True)
class AuditVerifyResult:
    """Outcome of walking the org's audit hash chain.

    ``first_id``, ``last_id`` and ``last_hash`` are None when the org has no audit rows.
    ``anchor_id`` is set only for a walk from ``from_id``. ``findings`` lists only
    unacknowledged findings; ``acknowledged_findings`` counts those a re-anchor covers.
    """

    ok: bool
    checked: int
    first_id: str | None
    last_id: str | None
    last_hash: str | None
    findings: tuple[AuditFinding, ...]
    findings_truncated: bool
    anchor_id: str | None = None
    acknowledged_findings: int = 0
    reanchored_by: str | None = None
    reanchor: AuditReanchor | None = None

    @classmethod
    def from_payload(cls, data: Any) -> "AuditVerifyResult":
        raw = _as_dict(data, "audit verify result")
        ok, checked, truncated = _required(
            raw, "audit verify result", "ok", "checked", "findings_truncated"
        )
        findings, first_id, last_id, last_hash = _required(
            raw, "audit verify result", "findings", "first_id", "last_id", "last_hash"
        )
        reanchor = raw.get("reanchor")
        acknowledged = raw.get("acknowledged_findings")
        return cls(
            ok=_bool(ok, "audit verify ok"),
            checked=_int(checked, "audit verify checked"),
            first_id=_optional_str(first_id, "audit first_id"),
            last_id=_optional_str(last_id, "audit last_id"),
            last_hash=_optional_str(last_hash, "audit last_hash"),
            findings=tuple(AuditFinding.from_payload(f) for f in _as_list(findings, "findings")),
            findings_truncated=_bool(truncated, "audit verify findings_truncated"),
            anchor_id=_optional_str(raw.get("anchor_id"), "audit anchor_id"),
            acknowledged_findings=(
                0 if acknowledged is None else _int(acknowledged, "audit acknowledged_findings")
            ),
            reanchored_by=_optional_str(raw.get("reanchored_by"), "audit reanchored_by"),
            reanchor=None if reanchor is None else AuditReanchor.from_payload(reanchor),
        )
