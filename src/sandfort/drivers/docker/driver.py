"""DockerDriver composes the docker modules and implements ``SandboxDriver``.

Compute lifecycle is implemented here (WP 1.1). Exec delegates to ``exec.py`` (WP 1.2),
archive streaming to ``archive.py``, pty sessions to ``pty.py`` (WP 2.4) and container log
streaming to ``logs.py`` (WP 2.5), image pull/commit/flatten/remove to ``images.py``
(WP 3.2), named volumes to ``volumes.py`` (WP 3.4), volume export and restore to
``volume_transfer.py`` and the reconciler inventory to
``capabilities.py`` (WP 3.6); the remaining methods are filled by later work packages.
"""

import asyncio
import logging
from collections.abc import AsyncIterator, Mapping, Sequence
from datetime import datetime
from typing import Any

import anyio
import anyio.to_thread

from sandfort.config import FAULT_RESTORE_EXTRACT_HOLD, Settings
from sandfort.drivers.base import (
    BuildHandle,
    CommitResult,
    ExecEvent,
    ExecRequest,
    ExecResult,
    ImageInfo,
    InstanceInfo,
    InventoryInstance,
    LogEntry,
    PtyHandle,
    PtyRequest,
    PtySessionHandle,
    SandboxSpec,
    VolumeInfo,
)
from sandfort.drivers.docker import (
    archive,
    build,
    capabilities,
    containers,
    image_export,
    images,
    lanes,
    logs,
    oom,
    pid_files,
    pty,
    volume_helper,
    volume_transfer,
    volumes,
)
from sandfort.drivers.docker.capabilities import DockerCapabilities
from sandfort.drivers.docker.client import configure_thread_limit, make_client, run_blocking
from sandfort.drivers.docker.exec import exec_run, exec_stream
from sandfort.drivers.docker.hardening import HardeningOptions, options_from_settings

logger = logging.getLogger(__name__)


class DockerDriver:
    def __init__(
        self,
        settings: Settings,
        client: Any | None = None,
        options: HardeningOptions | None = None,
    ) -> None:
        """Explicit ``options`` win; otherwise runtime and seccomp come from ``settings``."""
        configure_thread_limit(settings.docker_thread_limit, settings.docker_bulk_threads)
        self._settings = settings
        self._client = (
            client
            if client is not None
            else make_client(max_pool_size=settings.docker_thread_limit)
        )
        self._options = options or options_from_settings(settings)
        self._ptys = pty.DockerPtyRegistry()
        self._close_lock = asyncio.Lock()
        self._closed = False

    @property
    def name(self) -> str:
        return "docker"

    async def aclose(self) -> None:
        """Shut the driver down (offload design, "Shutdown"); idempotent.

        Kills every live terminal, refuses new calls with ``DriverError``, waits up to
        ``lanes.CLOSE_TIMEOUT_S`` for running calls to return their tokens and closes the
        docker-py client. An optional extra found by ``getattr``, not a protocol member.
        """
        async with self._close_lock:
            if self._closed:
                return
            try:
                with anyio.CancelScope(shield=True):  # a shutdown is not abandoned half way
                    await self._shutdown()
            finally:
                self._closed = True

    async def _shutdown(self) -> None:
        try:
            await pty.close_all(self._ptys)
        finally:
            lanes.close_lanes()
        await lanes.drain()
        await self._close_client()

    async def _close_client(self) -> None:
        """Close the docker-py client in a worker thread outside the lanes (they are closed)."""
        close = getattr(self._client, "close", None)
        if close is None:
            return
        try:
            await anyio.to_thread.run_sync(close)
        except Exception:
            logger.warning("failed to close the docker client", exc_info=True)

    async def create(self, spec: SandboxSpec) -> InstanceInfo:
        return await containers.create_container(self._client, spec, self._settings, self._options)

    async def start(self, ref: str) -> None:
        await containers.start_container(self._client, ref, self._options.gvisor_nameservers)
        # a stop SIGKILLed any running wrapper and a stopped container runs no exec, so its
        # pid files are removed now
        await run_blocking(pid_files.remove_stale_pid_files_blocking, self._client, ref)

    async def stop(self, ref: str, *, timeout_s: float = 10.0) -> None:
        await containers.stop_container(self._client, ref, timeout_s)

    async def destroy(self, ref: str, *, remove_volumes: bool = True) -> None:
        await containers.remove_container(self._client, ref, remove_volumes)

    async def inspect(self, ref: str) -> InstanceInfo:
        return await containers.inspect_container(self._client, ref)

    async def container_oom_killed(self, ref: str) -> bool:
        return await oom.container_oom_killed(self._client, ref)

    async def list_managed(self, *, org_id: str | None = None) -> list[InstanceInfo]:
        return await containers.list_managed_containers(self._client, org_id)

    async def get_endpoint(self, provider_id: str, port: int) -> tuple[str, int]:
        return await containers.container_endpoint(self._client, provider_id, port)

    async def pause(self, ref: str) -> None:
        await containers.pause_container(self._client, ref)

    async def unpause(self, ref: str) -> None:
        await containers.unpause_container(self._client, ref)

    async def exec(self, ref: str, request: ExecRequest) -> ExecResult:
        return await exec_run(self._client, ref, request)

    def exec_stream(self, ref: str, request: ExecRequest) -> AsyncIterator[ExecEvent]:
        return exec_stream(self._client, ref, request)

    async def put_archive(self, ref: str, dest_path: str, data: AsyncIterator[bytes]) -> None:
        await archive.put_archive(self._client, ref, dest_path, data)

    async def get_archive(self, ref: str, path: str) -> AsyncIterator[bytes]:
        _, chunks = await archive.get_archive_with_stat(self._client, ref, path)
        async for chunk in chunks:
            yield chunk

    async def get_archive_with_stat(
        self, ref: str, path: str
    ) -> tuple[Mapping[str, Any], AsyncIterator[bytes]]:
        return await archive.get_archive_with_stat(self._client, ref, path)

    async def open_pty(self, ref: str, request: PtyRequest) -> PtyHandle:
        raise NotImplementedError

    async def create_pty(
        self,
        ref: str,
        argv: Sequence[str],
        env: Mapping[str, str],
        rows: int,
        cols: int,
    ) -> PtySessionHandle:
        return await pty.create_pty(self._client, self._ptys, ref, argv, env, rows, cols)

    async def resize_pty(self, handle: PtySessionHandle, rows: int, cols: int) -> None:
        await pty.resize_pty(self._ptys, handle, rows, cols)

    async def write_pty(self, handle: PtySessionHandle, data: bytes) -> None:
        await pty.write_pty(self._ptys, handle, data)

    async def read_pty(self, handle: PtySessionHandle) -> bytes:
        return await pty.read_pty(self._ptys, handle)

    async def pty_exit_code(self, handle: PtySessionHandle) -> int | None:
        return await pty.pty_exit_code(self._ptys, handle)

    async def close_pty(self, handle: PtySessionHandle) -> None:
        await pty.close_pty(self._ptys, handle)

    def stream_logs(
        self,
        ref: str,
        *,
        follow: bool = False,
        tail: int | None = None,
        since: datetime | None = None,
    ) -> AsyncIterator[LogEntry]:
        return logs.stream_logs(self._client, ref, follow=follow, tail=tail, since=since)

    async def pull_image(self, image: str) -> ImageInfo:
        return await images.pull_image(self._client, image)

    async def inspect_image(self, ref: str) -> ImageInfo:
        return await images.inspect_image(self._client, ref)

    async def commit_image(self, ref: str, tag: str) -> ImageInfo:
        raise NotImplementedError

    async def remove_image(self, ref: str, *, force: bool = False) -> None:
        await images.remove_image(self._client, ref, force)

    async def pull_image_digest(self, reference: str) -> str:
        return await images.pull_image_digest(self._client, reference)

    async def image_exists(self, reference: str) -> bool:
        return await images.image_exists(self._client, reference)

    async def commit_container(
        self,
        provider_id: str,
        image_reference: str,
        *,
        labels: Mapping[str, str] | None = None,
    ) -> CommitResult:
        return await images.commit_container(self._client, provider_id, image_reference, labels)

    def export_image(self, reference: str) -> AsyncIterator[bytes]:
        """The image as a ``docker save`` tar (optional ``ImageExportDriver``)."""
        return image_export.export_image(self._client, reference)

    async def flatten_container(self, provider_id: str, image_reference: str) -> CommitResult:
        return await images.flatten_container(self._client, provider_id, image_reference)

    async def build_image(
        self, tag: str, context: bytes, *, dockerfile: str = "Dockerfile", timeout_s: float = 600.0
    ) -> ImageInfo:
        raise NotImplementedError

    async def start_build(
        self,
        context: Mapping[str, bytes],
        tag: str,
        *,
        cpu_millicores: int,
        memory_mib: int,
        timeout_s: float,
    ) -> BuildHandle:
        return await build.start_build(
            self._client,
            context,
            tag,
            cpu_millicores=cpu_millicores,
            memory_mib=memory_mib,
            timeout_s=timeout_s,
        )

    async def flatten_image(self, ref: str, tag: str) -> ImageInfo:
        raise NotImplementedError

    async def create_volume(self, name: str, *, labels: Mapping[str, str]) -> VolumeInfo:
        return await volumes.create_volume(self._client, name, labels=labels)

    async def remove_volume(self, ref: str) -> None:
        # A killed export leaves a read-only helper that makes the daemon refuse the removal.
        await volume_helper.remove_orphan_helpers(self._client, ref)
        await volumes.remove_volume(self._client, ref)

    async def inspect_volume(self, ref: str) -> Mapping[str, Any]:
        return await volumes.inspect_volume(self._client, ref)

    def export_volume(self, ref: str) -> AsyncIterator[bytes]:
        """The volume as a gzipped tar (optional ``VolumeTransferDriver``)."""
        return volume_transfer.export_volume(self._client, self._settings.egress_probe_image, ref)

    async def restore_volume(self, ref: str, tar: AsyncIterator[bytes]) -> None:
        await volume_transfer.restore_volume(
            self._client,
            self._settings.egress_probe_image,
            ref,
            tar,
            hold=FAULT_RESTORE_EXTRACT_HOLD in self._settings.fault_injection,
        )

    async def clear_volume(self, ref: str) -> None:
        await volume_transfer.clear_volume(self._client, ref)

    async def volume_usage_bytes(self, ref: str) -> int:
        return int((await self.inspect_volume(ref)).get("size_bytes", 0))

    async def instance_size_bytes(self, provider_id: str) -> int | None:
        """Writable-layer bytes for the metering sampler (optional ``InstanceSizeDriver``)."""
        return await containers.container_size_rw(self._client, provider_id)

    async def list_volumes(self) -> list[VolumeInfo]:
        return await capabilities.list_volumes(self._client)

    async def list_instances(self) -> list[InventoryInstance]:
        return await capabilities.list_instances(self._client)

    async def list_images(self) -> list[ImageInfo]:
        return await capabilities.list_images(self._client)

    async def capability_report(self) -> DockerCapabilities:
        return await capabilities.capability_report(
            self._client, runtime=self._options.runtime or ""
        )

    async def isolation_gaps(self) -> list[str]:
        """Startup self-check: one finding per isolation capability this host lacks."""
        report = await self.capability_report()
        for finding in capabilities.advisory_findings(report, self._settings):
            logger.warning("isolation advisory (does not refuse startup): %s", finding)
        return capabilities.missing_isolation(report, settings=self._settings)
