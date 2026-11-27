"""FROZEN: driver Protocols and DTOs.

Packages must not change these signatures; they only implement them.
``SandboxDriver`` is composed from ``ComputeDriver``, ``ExecDriver`` (which
includes the archive and PTY primitives the host-side toolbox relies on),
``ImageDriver`` and ``VolumeDriver``. Drivers import nothing from ``db``,
``services`` or ``api``. All methods are async; errors are ``drivers.errors``.
"""

import json
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import NetworkPolicy
from sandfort.drivers.errors import DriverUnsupported

# Reserved label (container and sandbox row): JSON list of image-declared volume paths.
IMAGE_MOUNTS_LABEL = "sandfort.image_mounts"

# Image label of the temporary image a resize commits the old container to. A container created
# from it inherits the label, and the driver drops the image when that container is destroyed.
RESIZE_IMAGE_LABEL = "sandfort.resize_image"
RESIZE_IMAGE_PREFIX = "sf-resize-"


def resize_image_reference(sandbox_id: str) -> str:
    """Deterministic local name of the sandbox's temporary resize image (lower-case)."""
    return f"{RESIZE_IMAGE_PREFIX}{sandbox_id.lower()}"


def decode_image_mounts(raw: str | None) -> list[str]:
    """The sorted paths in an ``IMAGE_MOUNTS_LABEL`` value; unreadable input gives none."""
    try:
        items = json.loads(raw) if raw else []
    except ValueError:
        return []
    if not isinstance(items, list):
        return []
    return sorted({item for item in items if isinstance(item, str)})


class InstanceState(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    EXITED = "exited"


@dataclass(frozen=True, slots=True)
class VolumeBind:
    volume_ref: str
    mount_path: str
    read_only: bool = False


@dataclass(frozen=True, slots=True)
class SandboxSpec:
    """Everything a driver needs to create one instance; ``name`` is deterministic (sf-<id>)."""

    sandbox_id: str
    org_id: str
    name: str
    image: str
    resources: ResourceSpec
    env: Mapping[str, str] = field(default_factory=dict)
    labels: Mapping[str, str] = field(default_factory=dict)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    volumes: Sequence[VolumeBind] = ()
    isolation: str | None = None  # tier name (``domain.isolation``); None = deployment default


@dataclass(frozen=True, slots=True)
class InstanceInfo:
    ref: str
    name: str
    sandbox_id: str
    org_id: str
    state: InstanceState
    image: str
    resources: ResourceSpec
    labels: Mapping[str, str]
    created_at: datetime
    # image-declared volume paths backed by scratch volumes (sorted)
    image_mounts: Sequence[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ExecRequest:
    argv: Sequence[str]
    cwd: str | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    stdin: bytes | None = None
    timeout_s: float = 60.0
    max_output_bytes: int = 1024 * 1024
    user: str | None = None


@dataclass(frozen=True, slots=True)
class ExecResult:
    exit_code: int
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    truncated: bool = False
    duration_ms: int = 0
    sandbox_stopped: bool = False  # the sandbox itself died while the command ran
    # The driver saw the kernel OOM-kill a process of the sandbox during the exec (container
    # tier only; the other tiers cannot tell, and leave this False).
    oom_killed: bool = False


@dataclass(frozen=True, slots=True)
class OutputChunk:
    stream: str  # "stdout" | "stderr"
    data: bytes


@dataclass(frozen=True, slots=True)
class ExitEvent:
    exit_code: int
    timed_out: bool = False
    truncated: bool = False
    sandbox_stopped: bool = False  # the sandbox itself died while the command ran
    oom_killed: bool = False  # see ``ExecResult.oom_killed``


type ExecEvent = OutputChunk | ExitEvent


@dataclass(frozen=True, slots=True)
class PtyRequest:
    cols: int = 80
    rows: int = 24
    cwd: str | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    shell: str = "/bin/bash"


@dataclass(frozen=True, slots=True)
class ImageInfo:
    ref: str
    digest: str
    size_bytes: int
    layer_count: int


@dataclass(frozen=True, slots=True)
class VolumeInfo:
    ref: str
    name: str
    labels: Mapping[str, str] = field(default_factory=dict)


class PtyHandle(Protocol):
    """Bidirectional terminal stream. ``read`` returns ``b""`` at EOF."""

    @property
    def exit_code(self) -> int | None: ...

    async def read(self) -> bytes: ...

    async def write(self, data: bytes) -> None: ...

    async def resize(self, cols: int, rows: int) -> None: ...

    async def close(self) -> None: ...


class ComputeDriver(Protocol):
    @property
    def name(self) -> str: ...

    async def create(self, spec: SandboxSpec) -> InstanceInfo:
        """Create an instance; idempotent: an existing instance with the same name is adopted."""
        ...

    async def start(self, ref: str) -> None: ...

    async def stop(self, ref: str, *, timeout_s: float = 10.0) -> None: ...

    async def destroy(self, ref: str, *, remove_volumes: bool = True) -> None: ...

    async def inspect(self, ref: str) -> InstanceInfo: ...

    async def list_managed(self, *, org_id: str | None = None) -> list[InstanceInfo]: ...

    async def pause(self, ref: str) -> None: ...

    async def unpause(self, ref: str) -> None: ...


class ArchiveDriver(Protocol):
    async def put_archive(self, ref: str, dest_path: str, data: AsyncIterator[bytes]) -> None:
        """Stream a tar into ``dest_path``; the host never extracts it."""
        ...

    def get_archive(self, ref: str, path: str) -> AsyncIterator[bytes]:
        """Stream ``path`` as a tar."""
        ...


class PtyDriver(Protocol):
    async def open_pty(self, ref: str, request: PtyRequest) -> PtyHandle: ...


class ExecDriver(ArchiveDriver, PtyDriver, Protocol):
    async def exec(self, ref: str, request: ExecRequest) -> ExecResult: ...

    def exec_stream(self, ref: str, request: ExecRequest) -> AsyncIterator[ExecEvent]:
        """Demuxed output chunks followed by exactly one ``ExitEvent``."""
        ...


class ImageDriver(Protocol):
    async def pull_image(self, image: str) -> ImageInfo: ...

    async def inspect_image(self, ref: str) -> ImageInfo: ...

    async def commit_image(self, ref: str, tag: str) -> ImageInfo:
        """Commit an instance to an image."""
        ...

    async def remove_image(self, ref: str) -> None: ...

    async def build_image(
        self, tag: str, context: bytes, *, dockerfile: str = "Dockerfile", timeout_s: float = 600.0
    ) -> ImageInfo: ...

    async def flatten_image(self, ref: str, tag: str) -> ImageInfo: ...


class VolumeDriver(Protocol):
    async def create_volume(self, name: str, *, labels: Mapping[str, str]) -> VolumeInfo: ...

    async def remove_volume(self, ref: str) -> None: ...

    async def volume_usage_bytes(self, ref: str) -> int: ...

    async def list_volumes(self) -> list[VolumeInfo]: ...


class SandboxDriver(ComputeDriver, ExecDriver, ImageDriver, VolumeDriver, Protocol):
    """The full driver surface."""


# -- phase 2 capabilities ------------------------------------------------------
# Separate capability protocols (not part of ``SandboxDriver``) so the existing
# drivers keep satisfying the phase-1 surface; the toolbox requires these explicitly.


@dataclass(frozen=True, slots=True)
class PtySessionHandle:
    """Opaque reference to a driver-side terminal; only the driver interprets ``handle_id``."""

    handle_id: str


@dataclass(frozen=True, slots=True)
class LogEntry:
    timestamp: datetime
    stream: str  # "stdout" | "stderr"
    line: str


@runtime_checkable
class InstanceSizeDriver(Protocol):
    """Optional capability: the bytes an instance holds on disk, ``None`` when not cheap."""

    async def instance_size_bytes(self, provider_id: str) -> int | None: ...


@runtime_checkable
class ArchiveStreamDriver(Protocol):
    async def put_archive(self, ref: str, dest_path: str, data: AsyncIterator[bytes]) -> None:
        """Stream a tar into the directory ``dest_path``; never buffered whole."""
        ...

    async def get_archive_with_stat(
        self, ref: str, path: str
    ) -> tuple[Mapping[str, Any], AsyncIterator[bytes]]:
        """Return ``(stat, tar_stream)`` for ``path``.

        Named ``get_archive_with_stat`` because the frozen phase-1
        ``ArchiveDriver.get_archive`` already exists with a different return type.
        """
        ...


@runtime_checkable
class PtySessionDriver(Protocol):
    async def create_pty(
        self,
        ref: str,
        argv: Sequence[str],
        env: Mapping[str, str],
        rows: int,
        cols: int,
    ) -> PtySessionHandle: ...

    async def resize_pty(self, handle: PtySessionHandle, rows: int, cols: int) -> None: ...

    async def write_pty(self, handle: PtySessionHandle, data: bytes) -> None: ...

    async def read_pty(self, handle: PtySessionHandle) -> bytes:
        """Next output chunk; ``b""`` at EOF."""
        ...

    async def close_pty(self, handle: PtySessionHandle) -> None: ...


# -- phase 3 capabilities ------------------------------------------------------
# Same pattern: separate protocols so existing drivers keep satisfying the phase-1
# surface. Where the phase-1 ``ImageDriver`` already owns a method name with another
# signature (``pull_image``, ``build_image``) the phase-3 method gets a distinct name.


@dataclass(frozen=True, slots=True)
class CommitResult:
    digest: str
    layer_count: int


@runtime_checkable
class BuildHandle(Protocol):
    """A running image build: stream its log, then await the resulting digest."""

    def logs(self) -> AsyncIterator[str]:
        """Build log lines, without trailing newlines."""
        ...

    async def result(self) -> str:
        """Wait for the build to finish and return the image digest."""
        ...


@runtime_checkable
class ImageRegistryDriver(Protocol):
    async def pull_image_digest(self, reference: str) -> str:
        """Pull ``reference`` and return its digest (phase-1 ``pull_image`` returns ImageInfo)."""
        ...

    async def image_exists(self, reference: str) -> bool: ...

    async def commit_container(
        self,
        provider_id: str,
        image_reference: str,
        *,
        labels: Mapping[str, str] | None = None,
    ) -> CommitResult:
        """Commit the instance ``provider_id`` to a new image ``image_reference``.

        ``labels`` are written into the image config (a resize commit marks its image so the
        driver can drop it with the last container that uses it).
        """
        ...

    async def remove_image(self, ref: str, *, force: bool = False) -> None:
        """Remove (untag) an image; ``force`` also drops it while a container still uses it."""
        ...


@runtime_checkable
class ImageBuildDriver(Protocol):
    async def start_build(
        self,
        context: Mapping[str, bytes],
        tag: str,
        *,
        cpu_millicores: int,
        memory_mib: int,
        timeout_s: float,
    ) -> BuildHandle:
        """Build ``context`` (file name to bytes) into ``tag``.

        Named ``start_build`` because phase-1 ``ImageDriver.build_image`` already
        exists with a different signature and return type.
        """
        ...


@runtime_checkable
class NamedVolumeDriver(Protocol):
    async def create_volume(self, name: str, *, labels: Mapping[str, str]) -> VolumeInfo: ...

    async def remove_volume(self, ref: str) -> None: ...

    async def inspect_volume(self, ref: str) -> Mapping[str, Any]:
        """At least ``{"name": str}``; ``"size_bytes": int`` when cheaply available."""
        ...


@runtime_checkable
class VolumeTransferDriver(Protocol):
    """Optional: stream a named volume out as a gzipped tar and replace it from a tar.

    ``export_volume`` reads the volume read-only; ``restore_volume`` empties it and extracts an
    uncompressed tar; ``clear_volume`` only empties it (the clean-up after a failed restore).
    """

    def export_volume(self, ref: str) -> AsyncIterator[bytes]:
        """The volume's files as a gzipped tar in chunks; a missing volume raises
        ``DriverNotFound`` before the first byte."""
        ...

    async def restore_volume(self, ref: str, tar: AsyncIterator[bytes]) -> None:
        """Empty the volume, then extract ``tar``. An unreadable archive raises
        ``DriverInvalidArchive``; on any failure the volume may hold part of the archive."""
        ...

    async def clear_volume(self, ref: str) -> None: ...


@dataclass(frozen=True, slots=True)
class InventoryInstance:
    """One platform-labelled container as the provider reports it, with no database view."""

    provider_id: str
    labels: Mapping[str, str]
    state: InstanceState


@runtime_checkable
class InventoryDriver(Protocol):
    """What the reconciler and the garbage collector read to compare the provider with the db.

    Every method lists platform-owned objects only (platform labels or platform tags). The
    defaults keep drivers that predate the protocol source-compatible: listing instances is
    unsupported (a reconciler must skip, never read it as "nothing exists"), volumes and
    images default to empty (nothing is collected).
    """

    async def list_instances(self) -> list[InventoryInstance]:
        """Every container carrying the platform labels, whatever its runtime state."""
        raise DriverUnsupported("this driver cannot list its instances")

    async def list_volumes(self) -> list[VolumeInfo]:
        """Every platform-labelled volume."""
        return []

    async def list_images(self) -> list[ImageInfo]:
        """Every platform-tagged image; ``ref`` is the tag."""
        return []


@runtime_checkable
class OomObservableDriver(Protocol):
    """Optional: tell whether a dead instance was killed for exceeding its memory limit.

    Only where the runtime records it (the Docker container and gvisor tiers: the daemon's
    ``State.OOMKilled`` with exit code 137, measured 2026-11-27, not Kata, where the daemon does
    not set it). Drivers whose tiers cannot see it answer ``False`` there, which callers read
    as "not known", never as "not an OOM". A container that survived an earlier OOM kill and is
    later SIGKILLed by something else still reads as OOM-killed.
    """

    async def container_oom_killed(self, ref: str) -> bool:
        """``True`` when ``ref`` is not running and its runtime says it was OOM-killed."""
        ...


@runtime_checkable
class EndpointDriver(Protocol):
    """Where the preview proxy connects to reach a port inside an instance; the default keeps
    older drivers source-compatible (unsupported, which the proxy answers with 502)."""

    async def get_endpoint(self, provider_id: str, port: int) -> tuple[str, int]:
        """``(host, port)`` that reaches ``port`` of the instance ``provider_id``."""
        raise DriverUnsupported("this driver cannot expose instance ports")


@runtime_checkable
class LogsDriver(Protocol):
    def stream_logs(
        self,
        ref: str,
        *,
        follow: bool = False,
        tail: int | None = None,
        since: datetime | None = None,
    ) -> AsyncIterator[LogEntry]:
        """Timestamped lines; ``tail=None`` means all lines."""
        ...


@runtime_checkable
class ImageExportDriver(Protocol):
    """Optional: stream a local image as a tar archive, as ``docker save`` produces it."""

    def export_image(self, reference: str) -> AsyncIterator[bytes]:
        """The image tar in chunks; a missing image raises ``DriverNotFound``."""
        ...
