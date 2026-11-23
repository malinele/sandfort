"""Docker ``ImageBuildDriver``: build an in-memory context through the docker build api.

The context mapping becomes a tar that is sent to ``/build`` with intermediate containers
removed (``rm`` and ``forcerm``). Limits go through docker's ``container_limits``: memory (swap
disabled) and CPU as ``cpushares``, the only CPU key the build api accepts (a relative weight,
not a hard cap). Opening the build and the final inspect run through ``run_blocking`` (control
lane); each progress read (``_next_chunk``) runs through ``run_bulk`` (bulk lane).

The build network is the daemon default unless ``SANDFORT_BUILD_NETWORK`` (or the
``network_mode`` argument) names one; it goes to the build call as ``network_mode``.

What the build API cannot restrict: ``container_limits`` accepts only ``memory``, ``memswap``,
``cpushares`` and ``cpusetcpus`` (docker-py rejects other keys), so there is no pids limit, no
capability drop, no seccomp profile, no ``no-new-privileges`` and no runtime choice for build
steps. RUN steps run on the daemon default runtime with docker's default capabilities. The
startup gate (``SANDFORT_REQUIRE_BUILD_RUNTIME``) therefore requires that default runtime to be
a runsc or kata runtime in prod.

The handle pumps the decoded progress stream into a replayable log. A wall-clock deadline covers
the whole build: when it passes the build is aborted and ``result`` raises ``DriverTimeout``.
A worker thread blocked on the daemon cannot be interrupted, so the abandoned stream is closed
once that read returns; the build call's own read timeout bounds how long that takes.

A build error never reaches the log or the exception verbatim: a base-image pull failure (the
Dockerfile's first ``FROM``) is classified like a pull, anything else gets a fixed sentence, and
the daemon text (it can quote the host's registry identity) goes to the debug log.
"""

import asyncio
import io
import logging
import os
import re
import tarfile
from collections.abc import AsyncIterator, Awaitable, Iterator, Mapping
from functools import partial
from typing import Any

from sandfort.config import BUILD_NETWORK_ENV
from sandfort.drivers.base import BuildHandle
from sandfort.drivers.docker.client import run_blocking, translate_errors
from sandfort.drivers.docker.images import classify_known_pull_failure
from sandfort.drivers.docker.lanes import run_bulk
from sandfort.drivers.errors import DriverError, DriverNotFound, DriverTimeout

logger = logging.getLogger(__name__)

MILLICORES_PER_CORE = 1000
DEFAULT_CPU_SHARES = 1024
MIN_CPU_SHARES = 2
BYTES_PER_MIB = 1024 * 1024
CONTEXT_FILE_MODE = 0o644
MAX_LOG_LINES = 20_000
MAX_LOG_LINE_CHARS = 2_000
TRUNCATION_NOTICE = "[build log truncated]"
DOCKERFILE_NAME = "Dockerfile"
BASE_IMAGE_FALLBACK = "the base image"
BUILD_FAILED_PREFIX = "image build failed: "
STEP_FAILED_SENTENCE = "a build step exited with a non-zero code"
DAEMON_FAILED_SENTENCE = "the Docker daemon could not complete the build"
# The first ``FROM`` image, after any ``--platform=...`` style flags.
_FROM_LINE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)", re.IGNORECASE | re.MULTILINE)
# A failed RUN step: the classic builder's "The command '...' returned a non-zero code: 1" or
# BuildKit's "process \"...\" did not complete successfully: exit code: 1". The command text is
# the tenant's, so it must not be read as a pull failure.
_STEP_FAILURE = re.compile(
    r"returned a non-zero code|did not complete successfully", re.IGNORECASE
)
# The numeric exit code of a failed step (digits only, so no tenant text is carried over):
# BuildKit's "exit code: 1" or the classic builder's "returned a non-zero code: 6". The last
# match wins, since the quoted command before it is the tenant's and can contain the phrase.
_EXIT_CODE = re.compile(r"(?:exit|non-zero) code:?\s*(\d+)", re.IGNORECASE)


def make_tar(context: Mapping[str, bytes]) -> bytes:
    """A deterministic tar of ``context``; names must be plain relative paths."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name in sorted(context):
            if name.startswith("/") or ".." in name.split("/"):
                raise DriverError(f"invalid build context entry name: {name!r}")
            info = tarfile.TarInfo(name)
            info.size = len(context[name])
            info.mode = CONTEXT_FILE_MODE
            archive.addfile(info, io.BytesIO(context[name]))
    return buffer.getvalue()


def container_limits(cpu_millicores: int, memory_mib: int) -> dict[str, int]:
    memory = memory_mib * BYTES_PER_MIB
    shares = cpu_millicores * DEFAULT_CPU_SHARES // MILLICORES_PER_CORE
    return {"memory": memory, "memswap": memory, "cpushares": max(shares, MIN_CPU_SHARES)}


def configured_build_network() -> str:
    """The build network from ``SANDFORT_BUILD_NETWORK`` ("" = the daemon default network).

    Read from the environment because the docker driver does not hand its settings to this
    module; the value is validated by ``Settings.from_env`` at startup.
    """
    return os.environ.get(BUILD_NETWORK_ENV, "").strip()


def base_image(context: Mapping[str, bytes]) -> str:
    """The image of the Dockerfile's first ``FROM``, or a fixed phrase when there is none."""
    dockerfile = context.get(DOCKERFILE_NAME, b"").decode("utf-8", "replace")
    match = _FROM_LINE.search(dockerfile)
    return match.group(1) if match else BASE_IMAGE_FALLBACK


def build_failure(daemon_text: str, base: str, tag: str) -> DriverError:
    """The tenant-safe error for a build error ``daemon_text`` (debug log only): a classified
    base-image pull failure in its own type, else a plain ``DriverError`` with a fixed sentence."""
    logger.debug("image build of %s failed: %s", tag, daemon_text)
    if _STEP_FAILURE.search(daemon_text) is not None:
        codes = _EXIT_CODE.findall(daemon_text)
        suffix = f" (exit code {codes[-1]})" if codes else ""
        return DriverError(BUILD_FAILED_PREFIX + STEP_FAILED_SENTENCE + suffix, ref=tag)
    known = classify_known_pull_failure(DriverError(daemon_text), base)
    if known is None:
        return DriverError(BUILD_FAILED_PREFIX + DAEMON_FAILED_SENTENCE, ref=tag)
    return type(known)(BUILD_FAILED_PREFIX + known.message, ref=tag)


def http_build_failure(exc: DriverError, base: str, tag: str) -> DriverError:
    """``build_failure`` for an error the build call itself raised (an HTTP error status or a
    transport failure). It reads the translated error's out-of-band ``daemon_text``, else its
    cleaned message, so the same text classifies as it would in the progress stream. A
    ``DriverNotFound`` keeps its type, so a 404 "No such image" ends as "no such image or
    snapshot"."""
    failure = build_failure(exc.classification_text, base, tag)
    if isinstance(exc, DriverNotFound) and not isinstance(failure, DriverNotFound):
        known = classify_known_pull_failure(exc, base)
        if known is not None and _STEP_FAILURE.search(exc.classification_text) is None:
            return type(known)(BUILD_FAILED_PREFIX + known.message, ref=tag)
    return failure


def _next_chunk(stream: Iterator[Any]) -> Any:
    """Blocking: the next progress object, or ``None`` at the end of the stream."""
    return next(stream, None)


def _ignore_outcome(task: asyncio.Future[Any]) -> None:
    if not task.cancelled():
        task.exception()  # retrieved so an abandoned read never logs as unhandled


class DockerBuildHandle:
    """A running build: replayable decoded log lines and the digest of the tagged image."""

    def __init__(
        self,
        client: Any,
        tar: bytes,
        tag: str,
        limits: Mapping[str, int],
        timeout_s: float,
        *,
        base: str = BASE_IMAGE_FALLBACK,
        network_mode: str = "",
    ) -> None:
        self._client = client
        self._network_mode = network_mode
        self._base = base
        self._tar = tar
        self._tag = tag
        self._limits = dict(limits)
        self._timeout_s = timeout_s
        self._lines: list[str] = []
        self._finished = False
        self._failure: DriverError | None = None
        self._changed = asyncio.Condition()
        self._task = asyncio.get_running_loop().create_task(self._run())

    # -- BuildHandle -------------------------------------------------------------

    def _has_more(self, index: int) -> bool:
        return index < len(self._lines) or self._finished

    async def logs(self) -> AsyncIterator[str]:
        index = 0
        while True:
            async with self._changed:
                await self._changed.wait_for(partial(self._has_more, index))
                batch = self._lines[index:]
                done = self._finished
            for line in batch:
                yield line
            index += len(batch)
            if done and not batch:
                return

    async def result(self) -> str:
        return await asyncio.shield(self._task)

    # -- pump --------------------------------------------------------------------

    async def _run(self) -> str:
        deadline = asyncio.get_running_loop().time() + self._timeout_s
        try:
            try:
                return await self._build(deadline)
            except DriverTimeout:
                raise
            except DriverError as exc:
                if exc is self._failure:  # already classified from a progress error chunk
                    raise
                # An HTTP error from the build call (or a requests failure) carries daemon text.
                failure = http_build_failure(exc, self._base, self._tag)
                await self._append(failure.message)
                raise failure from None
        finally:
            async with self._changed:
                self._finished = True
                self._changed.notify_all()

    async def _build(self, deadline: float) -> str:
        with translate_errors(self._tag, "image.build"):
            stream = await self._within(run_blocking(self._open), deadline)
            try:
                await self._consume(stream, deadline)
            except BaseException:
                self._abandon(stream)
                raise
            attrs = await self._within(
                run_blocking(self._client.api.inspect_image, self._tag), deadline
            )
        return str(attrs["Id"])

    def _open(self) -> Iterator[Any]:
        network = self._network_mode
        options: dict[str, Any] = {"network_mode": network} if network else {}
        stream: Iterator[Any] = self._client.api.build(
            fileobj=io.BytesIO(self._tar),
            custom_context=True,
            tag=self._tag,
            rm=True,
            forcerm=True,
            decode=True,
            container_limits=self._limits,
            timeout=self._timeout_s,
            **options,
        )
        return stream

    async def _consume(self, stream: Iterator[Any], deadline: float) -> None:
        while True:
            chunk = await self._within(run_bulk(_next_chunk, stream), deadline)
            if chunk is None:
                return
            if isinstance(chunk, Mapping):
                await self._handle(chunk)

    async def _handle(self, chunk: Mapping[str, Any]) -> None:
        for line in str(chunk.get("stream") or "").splitlines():
            if line.strip():
                await self._append(line.rstrip())
        error = chunk.get("error")
        if error:
            failure = build_failure(str(error).strip(), self._base, self._tag)
            self._failure = failure
            await self._append(failure.message)
            raise failure

    async def _append(self, line: str) -> None:
        async with self._changed:
            if len(self._lines) < MAX_LOG_LINES:
                self._lines.append(line[:MAX_LOG_LINE_CHARS])
            elif len(self._lines) == MAX_LOG_LINES:
                self._lines.append(TRUNCATION_NOTICE)
            self._changed.notify_all()

    async def _within[T](self, work: Awaitable[T], deadline: float) -> T:
        """Await ``work`` until the wall-clock ``deadline``; past it, abort with a timeout."""
        task = asyncio.ensure_future(work)
        remaining = max(deadline - asyncio.get_running_loop().time(), 0.0)
        done, _ = await asyncio.wait({task}, timeout=remaining)
        if not done:
            task.add_done_callback(_ignore_outcome)
            raise DriverTimeout(f"image build timed out after {self._timeout_s:g}s", ref=self._tag)
        return task.result()

    @staticmethod
    def _abandon(stream: Any) -> None:
        closer = getattr(stream, "close", None)
        if closer is not None:
            try:
                closer()
            except (ValueError, RuntimeError):  # a worker thread is still inside the stream
                pass


async def start_build(
    client: Any,
    context: Mapping[str, bytes],
    tag: str,
    *,
    cpu_millicores: int,
    memory_mib: int,
    timeout_s: float,
    network_mode: str | None = None,
) -> BuildHandle:
    """Open a build; ``network_mode`` None reads ``SANDFORT_BUILD_NETWORK``."""
    tar = make_tar(context)
    limits = container_limits(cpu_millicores, memory_mib)
    network = configured_build_network() if network_mode is None else network_mode
    return DockerBuildHandle(
        client, tar, tag, limits, timeout_s, base=base_image(context), network_mode=network
    )
