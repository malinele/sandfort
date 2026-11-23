"""In-memory FakeDriver implementing every driver Protocol, for unit tests."""

import asyncio
import hashlib
import io
import posixpath
import tarfile
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sandfort.clock import Clock, SystemClock
from sandfort.domain.resources import ResourceSpec
from sandfort.drivers.base import (
    CommitResult,
    ExecEvent,
    ExecRequest,
    ExecResult,
    ExitEvent,
    ImageInfo,
    InstanceInfo,
    InstanceState,
    InventoryInstance,
    LogEntry,
    OutputChunk,
    PtyRequest,
    PtySessionHandle,
    SandboxSpec,
    VolumeInfo,
    resize_image_reference,
)
from sandfort.drivers.docker.capabilities import PLATFORM_IMAGE_PREFIX
from sandfort.drivers.docker.exec import with_timeout_note
from sandfort.drivers.docker.labels import LABEL_MANAGED, build_labels
from sandfort.drivers.docker.tar_policy import checked_tar
from sandfort.drivers.errors import (
    DriverConflict,
    DriverError,
    DriverInvalidArchive,
    DriverNotFound,
    DriverTimeout,
)

ExecHandler = Callable[[Mapping[str, str], ExecRequest], ExecResult]

FAKE_MODE_DIR = 1 << 31


@dataclass
class _Instance:
    info: InstanceInfo
    env: Mapping[str, str]
    files: dict[str, bytes] = field(default_factory=dict)
    mounts: tuple[tuple[str, str], ...] = ()  # (mount path, volume ref)
    platform_labels: Mapping[str, str] = field(default_factory=dict)  # what the inventory reports

    def mount_for(self, path: str) -> tuple[str, str] | None:
        """``(volume ref, path inside the volume)`` when ``path`` lies under a mount."""
        for mount_path, volume_ref in self.mounts:
            if path == mount_path or path.startswith(mount_path + "/"):
                return volume_ref, path[len(mount_path) :]
        return None


def default_exec_handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
    """Tiny shell simulation: echo, cat, env and ``sh -c 'exit N'``."""
    argv = list(request.argv)
    stdout = b""
    exit_code = 0
    if argv[:1] == ["echo"]:
        stdout = (" ".join(argv[1:]) + "\n").encode()
    elif argv[:1] == ["cat"]:
        stdout = request.stdin or b""
    elif argv[:1] == ["env"]:
        merged = {**env, **request.env}
        stdout = "".join(f"{key}={value}\n" for key, value in merged.items()).encode()
    elif len(argv) == 3 and argv[:2] == ["sh", "-c"] and argv[2].startswith("exit "):
        exit_code = int(argv[2].split()[1])
    truncated = len(stdout) > request.max_output_bytes
    return ExecResult(
        exit_code=exit_code, stdout=stdout[: request.max_output_bytes], truncated=truncated
    )


TIMED_OUT_EXIT_CODE = 124


def timed_out_result(
    request: ExecRequest, *, stdout: bytes = b"", stderr: bytes = b""
) -> ExecResult:
    """A scripted timed-out exec as the Docker driver reports it.

    The driver's note follows ``stderr`` on its own line (``with_timeout_note``), so CLI and SDK
    tests see the same text as a real run. Handlers that script a timeout use this helper.
    """
    return ExecResult(
        exit_code=TIMED_OUT_EXIT_CODE,
        stdout=stdout,
        stderr=with_timeout_note(stderr, request.timeout_s),
        timed_out=True,
    )


class FakePty:
    """Echoing terminal."""

    def __init__(self, request: PtyRequest) -> None:
        self.cols = request.cols
        self.rows = request.rows
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._exit_code: int | None = None

    @property
    def exit_code(self) -> int | None:
        return self._exit_code

    async def read(self) -> bytes:
        return await self._queue.get()

    async def write(self, data: bytes) -> None:
        if self._exit_code is not None:
            raise DriverConflict("pty is closed")
        await self._queue.put(data)

    async def resize(self, cols: int, rows: int) -> None:
        self.cols = cols
        self.rows = rows

    async def close(self) -> None:
        if self._exit_code is None:
            self._exit_code = 0
            await self._queue.put(b"")


class FakeBuildHandle:
    """Finished build whose log replays the build context, one line per file."""

    def __init__(
        self, lines: Sequence[str], digest: str, failure: DriverError | None = None
    ) -> None:
        self._lines = list(lines)
        self._digest = digest
        self._failure = failure

    async def logs(self) -> AsyncIterator[str]:
        for line in self._lines:
            yield line

    async def result(self) -> str:
        if self._failure is not None:
            raise self._failure
        return self._digest


_LIVE_STATES = (InstanceState.RUNNING, InstanceState.PAUSED)


_TRANSFER_CHUNK = 64 * 1024


class FakeDriver:
    """Complete in-memory driver; ``exec_handler`` can be replaced per test."""

    def __init__(self, clock: Clock | None = None, exec_handler: ExecHandler | None = None) -> None:
        self._clock: Clock = clock or SystemClock()
        self.exec_handler: ExecHandler = exec_handler or default_exec_handler
        self._instances: dict[str, _Instance] = {}
        self._images: dict[str, ImageInfo] = {}
        self._image_files: dict[str, dict[str, bytes]] = {}  # committed tag -> root filesystem
        self._dangling: dict[str, ImageInfo] = {}  # digest -> image whose tag moved on
        self._image_gone: set[str] = set()  # instances whose image was deleted from under them
        self._commits = 0
        # Classic overlay2 (the beta): ``rmi -f`` of an image that only stopped containers use
        # deletes the image record, so a later commit of such a container finds no image config.
        # Docker Desktop's containerd store only untags; set False to model that.
        self.overlay2_images = True
        self._volumes: dict[str, VolumeInfo] = {}
        self._volume_files: dict[str, dict[str, bytes]] = {}  # volume ref -> path -> bytes
        self._logs: dict[str, list[LogEntry]] = {}
        self._log_wakers: dict[str, asyncio.Event] = {}
        self._open_log_streams = 0
        self._ptys: dict[str, FakePty] = {}
        self._endpoints: dict[str, tuple[str, int]] = {}  # instance ref -> (host, port)
        self._oom_killed: set[str] = set()  # exited instances the runtime flags as OOM-killed
        self.commit_layer_count: int | None = None  # test hook: layers a commit reports
        self.flattened: list[str] = []  # test record: references produced by a flatten
        self.build_contexts: list[Mapping[str, bytes]] = []  # test record: one per start_build
        self.build_timeout = False  # test hook: builds hang until their timeout fires

    @property
    def name(self) -> str:
        return "fake"

    # -- compute -------------------------------------------------------------

    def _get(self, ref: str) -> _Instance:
        try:
            return self._instances[ref]
        except KeyError:
            raise DriverNotFound(f"no such instance: {ref}", ref=ref) from None

    def _set_state(self, ref: str, state: InstanceState) -> None:
        instance = self._get(ref)
        instance.info = InstanceInfo(
            ref=instance.info.ref,
            name=instance.info.name,
            sandbox_id=instance.info.sandbox_id,
            org_id=instance.info.org_id,
            state=state,
            image=instance.info.image,
            resources=instance.info.resources,
            labels=instance.info.labels,
            created_at=instance.info.created_at,
        )

    def _require_running(self, ref: str) -> _Instance:
        instance = self._get(ref)
        if instance.info.state is not InstanceState.RUNNING:
            raise DriverConflict(f"instance {ref} is not running", ref=ref)
        return instance

    async def create(self, spec: SandboxSpec) -> InstanceInfo:
        ref = f"fake-{spec.name}"
        existing = self._instances.get(ref)
        if existing is not None:
            return existing.info
        for bind in spec.volumes:
            self._require_volume(bind.volume_ref)
        mounts = tuple((bind.mount_path.rstrip("/"), bind.volume_ref) for bind in spec.volumes)
        info = InstanceInfo(
            ref=ref,
            name=spec.name,
            sandbox_id=spec.sandbox_id,
            org_id=spec.org_id,
            state=InstanceState.CREATED,
            image=spec.image,
            resources=spec.resources,
            labels=dict(spec.labels),
            created_at=self._clock.now(),
        )
        self._image_gone.discard(ref)
        self._instances[ref] = _Instance(
            info=info,
            env=dict(spec.env),
            files=dict(self._image_files.get(spec.image, {})),  # a committed image carries files
            mounts=mounts,
            platform_labels=build_labels(spec.sandbox_id, spec.org_id, {}),
        )
        return info

    async def start(self, ref: str) -> None:
        self._set_state(ref, InstanceState.RUNNING)
        self._oom_killed.discard(ref)  # a start clears the runtime's verdict, as docker does

    async def container_oom_killed(self, ref: str) -> bool:
        """``OomObservableDriver``: exited, and ``kill_instance(..., oom=True)`` flagged it."""
        instance = self._instances.get(ref)
        return (
            instance is not None
            and ref in self._oom_killed
            and instance.info.state is InstanceState.EXITED
        )

    async def stop(self, ref: str, *, timeout_s: float = 10.0) -> None:
        self._set_state(ref, InstanceState.EXITED)

    async def destroy(self, ref: str, *, remove_volumes: bool = True) -> None:
        instance = self._get(ref)
        del self._instances[ref]
        self._image_gone.discard(ref)
        if remove_volumes:  # the end of the sandbox: its resize image goes with it, as in docker
            tag = resize_image_reference(instance.info.sandbox_id)
            self._images.pop(tag, None)
            self._image_files.pop(tag, None)

    async def inspect(self, ref: str) -> InstanceInfo:
        return self._get(ref).info

    async def list_managed(self, *, org_id: str | None = None) -> list[InstanceInfo]:
        return [
            item.info
            for item in self._instances.values()
            if org_id is None or item.info.org_id == org_id
        ]

    async def pause(self, ref: str) -> None:
        self._require_running(ref)
        self._set_state(ref, InstanceState.PAUSED)

    async def unpause(self, ref: str) -> None:
        if self._get(ref).info.state is not InstanceState.PAUSED:
            raise DriverConflict(f"instance {ref} is not paused", ref=ref)
        self._set_state(ref, InstanceState.RUNNING)

    # -- endpoints (EndpointDriver) --------------------------------------------

    def register_endpoint(self, ref: str, host: str, port: int) -> None:
        """Test hook: every port of instance ``ref`` is served at ``host:port``."""
        self._get(ref)
        self._endpoints[ref] = (host, port)

    async def get_endpoint(self, provider_id: str, port: int) -> tuple[str, int]:
        self._require_running(provider_id)
        endpoint = self._endpoints.get(provider_id)
        if endpoint is None:
            raise DriverNotFound(f"no endpoint registered for {provider_id}", ref=provider_id)
        return endpoint

    # -- inventory (InventoryDriver) -------------------------------------------

    async def list_instances(self) -> list[InventoryInstance]:
        return [
            InventoryInstance(item.info.ref, dict(item.platform_labels), item.info.state)
            for item in self._instances.values()
            if item.platform_labels.get(LABEL_MANAGED) == "true"
        ]

    async def list_images(self) -> list[ImageInfo]:
        return [info for ref, info in self._images.items() if ref.startswith(PLATFORM_IMAGE_PREFIX)]

    def kill_instance(self, ref: str, *, vanish: bool = True, oom: bool = False) -> None:
        """Test helper: the container dies behind the platform's back.

        ``vanish`` removes it entirely (as ``docker rm -f`` would); otherwise it stays, exited.
        ``oom`` makes an exited instance read as OOM-killed (``container_oom_killed``).
        """
        self._get(ref)
        if vanish:
            del self._instances[ref]
        else:
            self._set_state(ref, InstanceState.EXITED)
            if oom:
                self._oom_killed.add(ref)

    def plant_instance(
        self, sandbox_id: str, org_id: str, *, state: InstanceState = InstanceState.RUNNING
    ) -> str:
        """Test helper: a platform-labelled container no database row knows; returns its ref."""
        ref = f"fake-planted-{sandbox_id}"
        info = InstanceInfo(
            ref=ref,
            name=f"sf-{sandbox_id}",
            sandbox_id=sandbox_id,
            org_id=org_id,
            state=state,
            image="planted",
            resources=ResourceSpec(),
            labels={},
            created_at=self._clock.now(),
        )
        self._image_gone.discard(ref)
        self._instances[ref] = _Instance(
            info=info, env={}, platform_labels=build_labels(sandbox_id, org_id, {})
        )
        return ref

    # -- exec, archive, pty --------------------------------------------------

    async def exec(self, ref: str, request: ExecRequest) -> ExecResult:
        instance = self._require_running(ref)
        return self.exec_handler(instance.env, request)

    async def exec_stream(self, ref: str, request: ExecRequest) -> AsyncIterator[ExecEvent]:
        result = await self.exec(ref, request)
        if result.stdout:
            yield OutputChunk("stdout", result.stdout)
        if result.stderr:
            yield OutputChunk("stderr", result.stderr)
        yield ExitEvent(
            result.exit_code,
            timed_out=result.timed_out,
            truncated=result.truncated,
            sandbox_stopped=result.sandbox_stopped,
            oom_killed=result.oom_killed,
        )

    async def put_archive(self, ref: str, dest_path: str, data: AsyncIterator[bytes]) -> None:
        instance = self._require_running(ref)
        payload = b"".join([chunk async for chunk in data])
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
            for member in archive.getmembers():
                handle = archive.extractfile(member) if member.isfile() else None
                if handle is not None:
                    self._store(instance, posixpath.join(dest_path, member.name), handle.read())

    def _store(self, instance: _Instance, path: str, content: bytes) -> None:
        """Write to the mounted volume when ``path`` lies under a mount, else to the instance."""
        mounted = instance.mount_for(path)
        if mounted is None:
            instance.files[path] = content
            return
        volume_ref, inner = mounted
        self._volume_files.setdefault(volume_ref, {})[inner] = content

    def _view(self, instance: _Instance) -> dict[str, bytes]:
        """The instance filesystem as seen from inside: mounts shadow what lies beneath."""
        view = {
            name: content
            for name, content in instance.files.items()
            if instance.mount_for(name) is None
        }
        for mount_path, volume_ref in instance.mounts:
            for inner, content in self._volume_files.get(volume_ref, {}).items():
                view[mount_path + inner] = content
        return view

    def _build_archive(self, ref: str, path: str) -> tuple[dict[str, Any], bytes]:
        instance = self._require_running(ref)
        base = path.rstrip("/")
        matches = {
            name: content
            for name, content in self._view(instance).items()
            if name == base or name.startswith(base + "/")
        }
        if not matches:
            raise DriverNotFound(f"no such path: {path}", ref=ref)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, content in matches.items():
                arcname = posixpath.basename(base) + name[len(base) :]
                member = tarfile.TarInfo(arcname)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        is_dir = base not in matches
        stat = {
            "name": posixpath.basename(base),
            "size": sum(len(content) for content in matches.values()),
            "is_dir": is_dir,
            # docker reports a Go os.FileMode: bit 31 marks a directory
            "mode": (FAKE_MODE_DIR | 0o755) if is_dir else 0o644,
        }
        return stat, buffer.getvalue()

    async def get_archive(self, ref: str, path: str) -> AsyncIterator[bytes]:
        _, payload = self._build_archive(ref, path)
        yield payload

    async def get_archive_with_stat(
        self, ref: str, path: str
    ) -> tuple[Mapping[str, Any], AsyncIterator[bytes]]:
        stat, payload = self._build_archive(ref, path)

        async def stream() -> AsyncIterator[bytes]:
            yield payload

        return stat, stream()

    async def open_pty(self, ref: str, request: PtyRequest) -> FakePty:
        self._require_running(ref)
        return FakePty(request)

    # -- pty sessions (PtySessionDriver) ---------------------------------------

    def _get_pty(self, handle: PtySessionHandle) -> FakePty:
        pty_id = handle.handle_id
        try:
            return self._ptys[pty_id]
        except KeyError:
            raise DriverNotFound(f"no such pty: {pty_id}", ref=pty_id) from None

    async def create_pty(
        self,
        ref: str,
        argv: Sequence[str],
        env: Mapping[str, str],
        rows: int,
        cols: int,
    ) -> PtySessionHandle:
        self._require_running(ref)
        handle = PtySessionHandle(handle_id=f"fakepty-{len(self._ptys) + 1}")
        self._ptys[handle.handle_id] = FakePty(PtyRequest(cols=cols, rows=rows, env=dict(env)))
        return handle

    async def resize_pty(self, handle: PtySessionHandle, rows: int, cols: int) -> None:
        await self._get_pty(handle).resize(cols, rows)

    async def write_pty(self, handle: PtySessionHandle, data: bytes) -> None:
        await self._get_pty(handle).write(data)

    async def read_pty(self, handle: PtySessionHandle) -> bytes:
        return await self._get_pty(handle).read()

    async def close_pty(self, handle: PtySessionHandle) -> None:
        await self._get_pty(handle).close()

    # -- logs (LogsDriver) -----------------------------------------------------

    @property
    def open_log_streams(self) -> int:
        """Test helper: ``stream_logs`` iterators started and not yet closed or cancelled."""
        return self._open_log_streams

    def append_log(self, ref: str, line: str, stream: str = "stdout") -> LogEntry:
        """Test helper: record one log line for ``ref`` stamped with the driver clock."""
        self._get(ref)
        entry = LogEntry(timestamp=self._clock.now(), stream=stream, line=line)
        self._logs.setdefault(ref, []).append(entry)
        waker = self._log_wakers.pop(ref, None)
        if waker is not None:
            waker.set()
        return entry

    async def stream_logs(
        self,
        ref: str,
        *,
        follow: bool = False,
        tail: int | None = None,
        since: datetime | None = None,
    ) -> AsyncIterator[LogEntry]:
        """Replay, then with ``follow`` wait for appended lines until the consumer stops."""
        self._get(ref)
        self._open_log_streams += 1
        try:
            seen = len(self._logs.get(ref, []))
            entries = [
                entry
                for entry in self._logs.get(ref, [])
                if since is None or entry.timestamp >= since
            ]
            if tail is not None:
                entries = entries[-tail:] if tail > 0 else []
            for entry in entries:
                yield entry
            while follow:
                fresh = self._logs.get(ref, [])[seen:]
                seen += len(fresh)
                for entry in fresh:
                    if since is None or entry.timestamp >= since:
                        yield entry
                if not fresh:
                    await self._log_wakers.setdefault(ref, asyncio.Event()).wait()
        finally:
            self._open_log_streams -= 1

    # -- images --------------------------------------------------------------

    async def pull_image(self, image: str) -> ImageInfo:
        info = self._images.get(image)
        if info is None:
            digest = "sha256:" + hashlib.sha256(image.encode()).hexdigest()
            info = ImageInfo(ref=image, digest=digest, size_bytes=1, layer_count=1)
            self._images[image] = info
        return info

    async def inspect_image(self, ref: str) -> ImageInfo:
        try:
            return self._images[ref]
        except KeyError:
            raise DriverNotFound(f"no such image: {ref}", ref=ref) from None

    async def commit_image(self, ref: str, tag: str) -> ImageInfo:
        instance = self._get(ref)
        if ref in self._image_gone:
            raise DriverNotFound(
                f"No such image: sha256:{hashlib.sha256(instance.info.image.encode()).hexdigest()}",
                ref=ref,
            )
        base = self._images.get(instance.info.image)
        layers = (base.layer_count if base else 0) + 1
        self._image_files[tag] = dict(instance.files)
        previous = self._images.get(tag)
        if previous is None:
            return self._register_image(tag, layers)
        self._dangling[previous.digest] = previous  # the tag moves; the old image stays by id
        self._commits += 1
        return self._register_image(tag, layers, seed=str(self._commits).encode())

    async def remove_image(self, ref: str, *, force: bool = False) -> None:
        dangling = self._dangling.pop(ref, None)
        if dangling is not None:  # removal by image id of an image that lost its tag
            return
        await self.inspect_image(ref)
        if force and self.overlay2_images:
            users = [i for i in self._instances.values() if i.info.image == ref]
            if any(i.info.state in _LIVE_STATES for i in users):
                raise DriverConflict(f"image {ref} is used by a running container", ref=ref)
            self._image_gone.update(i.info.ref for i in users)
        del self._images[ref]
        self._image_files.pop(ref, None)

    async def build_image(
        self, tag: str, context: bytes, *, dockerfile: str = "Dockerfile", timeout_s: float = 600.0
    ) -> ImageInfo:
        return self._register_image(tag, 1, seed=context)

    async def flatten_image(self, ref: str, tag: str) -> ImageInfo:
        await self.inspect_image(ref)
        return self._register_image(tag, 1)

    def _register_image(self, tag: str, layers: int, *, seed: bytes = b"") -> ImageInfo:
        digest = "sha256:" + hashlib.sha256(tag.encode() + seed).hexdigest()
        info = ImageInfo(ref=tag, digest=digest, size_bytes=1, layer_count=layers)
        self._images[tag] = info
        return info

    # -- phase 3 images (ImageRegistryDriver, ImageBuildDriver) ----------------

    async def pull_image_digest(self, reference: str) -> str:
        return (await self.pull_image(reference)).digest

    async def image_exists(self, reference: str) -> bool:
        return reference in self._images

    async def commit_container(
        self,
        provider_id: str,
        image_reference: str,
        *,
        labels: Mapping[str, str] | None = None,
    ) -> CommitResult:
        info = await self.commit_image(provider_id, image_reference)
        if self.commit_layer_count is not None:
            info = self._register_image(image_reference, self.commit_layer_count)
        return CommitResult(digest=info.digest, layer_count=info.layer_count)

    async def flatten_container(self, provider_id: str, image_reference: str) -> CommitResult:
        self._get(provider_id)
        info = self._register_image(image_reference, 1)
        self.flattened.append(image_reference)
        return CommitResult(digest=info.digest, layer_count=info.layer_count)

    async def start_build(
        self,
        context: Mapping[str, bytes],
        tag: str,
        *,
        cpu_millicores: int,
        memory_mib: int,
        timeout_s: float,
    ) -> FakeBuildHandle:
        self.build_contexts.append(dict(context))
        lines = [f"COPY {name} ({len(context[name])} bytes)" for name in sorted(context)]
        if self.build_timeout:
            lines.append("build hung")
            failure = DriverTimeout(f"image build timed out after {timeout_s:g}s", ref=tag)
            return FakeBuildHandle(lines, "", failure)
        seed = b"".join(name.encode() + b"\0" + context[name] for name in sorted(context))
        info = self._register_image(tag, 1, seed=seed)
        lines.append(f"Successfully tagged {tag}")
        return FakeBuildHandle(lines, info.digest)

    # -- volumes -------------------------------------------------------------

    # Like docker, a volume's name is its reference; files written under a mount path are
    # shared by every instance mounting the volume and outlive the instances.

    def _require_volume(self, ref: str) -> VolumeInfo:
        info = self._volumes.get(ref)
        if info is None:
            raise DriverNotFound(f"no such volume: {ref}", ref=ref)
        return info

    def _volume_size(self, ref: str) -> int:
        return sum(len(content) for content in self._volume_files.get(ref, {}).values())

    async def inspect_volume(self, ref: str) -> Mapping[str, Any]:
        info = self._require_volume(ref)
        return {"name": info.name, "ref": info.ref, "size_bytes": self._volume_size(ref)}

    async def create_volume(self, name: str, *, labels: Mapping[str, str]) -> VolumeInfo:
        existing = self._volumes.get(name)
        if existing is not None:
            return existing
        info = VolumeInfo(ref=name, name=name, labels=dict(labels))
        self._volumes[name] = info
        return info

    async def remove_volume(self, ref: str) -> None:
        self._require_volume(ref)
        mounted = (volume for item in self._instances.values() for _, volume in item.mounts)
        if ref in mounted:
            raise DriverConflict(f"volume {ref} is in use", ref=ref)
        del self._volumes[ref]
        self._volume_files.pop(ref, None)

    async def volume_usage_bytes(self, ref: str) -> int:
        self._require_volume(ref)
        return self._volume_size(ref)

    async def list_volumes(self) -> list[VolumeInfo]:
        return list(self._volumes.values())

    # -- volume transfer -----------------------------------------------------
    # Export and restore of a volume's files. Restore applies the docker driver's archive policy
    # (``tar_policy.checked_tar``) to the incoming tar, so both refuse the same members; this
    # fake keeps regular files only (directories and symlinks pass the policy but are not kept).

    async def export_volume(self, ref: str) -> AsyncIterator[bytes]:
        self._require_volume(ref)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for inner, content in sorted(self._volume_files.get(ref, {}).items()):
                info = tarfile.TarInfo(inner.lstrip("/"))
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        payload = buffer.getvalue()
        for start in range(0, len(payload), _TRANSFER_CHUNK):
            yield payload[start : start + _TRANSFER_CHUNK]

    async def restore_volume(self, ref: str, tar: AsyncIterator[bytes]) -> None:
        self._require_volume(ref)
        self._volume_files[ref] = {}
        payload = b"".join([chunk async for chunk in tar])
        restored: dict[str, bytes] = {}
        rebuilt = b"".join(checked_tar([payload]))  # DriverForbiddenEntry / DriverInvalidArchive
        try:
            with tarfile.open(fileobj=io.BytesIO(rebuilt), mode="r:") as archive:
                for member in archive.getmembers():
                    handle = archive.extractfile(member) if member.isfile() else None
                    if handle is not None:
                        restored[posixpath.normpath("/" + member.name)] = handle.read()
        except tarfile.TarError as exc:
            raise DriverInvalidArchive("the archive is not a readable tar") from exc
        self._volume_files[ref] = restored

    async def clear_volume(self, ref: str) -> None:
        self._require_volume(ref)
        self._volume_files[ref] = {}
