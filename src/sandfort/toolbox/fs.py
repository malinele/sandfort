"""Filesystem toolbox facade used by the ``/fs`` routes.

Every operation validates its paths, loads the sandbox in a short unit of work (org
scoping, started check, activity touch), writes the audit row in that same unit of work,
closes it, and only then talks to the driver (intent-then-act). Listing, stat, mkdir,
move and delete are exec invocations with argv lists (never a shell string); upload and
download stream tar archives through the archive driver. Audit details carry paths and
sizes, never file contents.
"""

import posixpath
import re
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType
from sandfort.domain.sandbox import Sandbox, visible_stop_cause
from sandfort.drivers.base import ArchiveStreamDriver, ExecRequest, ExecResult, SandboxDriver
from sandfort.drivers.docker.client import DriverReadOnlyPath
from sandfort.drivers.errors import (
    DriverConflict,
    DriverError,
    DriverNotFound,
    DriverTimeout,
    DriverUnsupported,
)
from sandfort.errors import (
    ALREADY_EXISTS,
    CONFLICT_REASON,
    OPERATION_FAILED,
    Conflict,
    NotFound,
    PayloadTooLarge,
    Unprocessable,
    no_container_conflict,
)
from sandfort.toolbox.fs_parse import (
    VARIANTS,
    FsEntry,
    FsParseError,
    StatVariant,
    list_argv,
    looks_unsupported,
    parse_stat_output,
    sorted_entries,
    stat_argv,
)
from sandfort.toolbox.fs_range import upload_limit_error
from sandfort.toolbox.fs_transfer import (
    archive_kind,
    close_stream,
    extract_file,
    read_limited,
    tar_upload_stream,
)
from sandfort.toolbox.guards import load_started_sandbox
from sandfort.toolbox.paths import (
    ROOT,
    normalize_path,
    refuse_pseudo_filesystem,
    split_parent,
    under_pseudo_filesystem,
)

EXEC_TIMEOUT_S = 30.0
STAT_OUTPUT_BYTES = 64 * 1024
LIST_OUTPUT_BYTES = 8 * 1024 * 1024
ERROR_EXCERPT_CHARS = 200
READ_ONLY_STDERR = "read-only file system"  # what mkdir, rm and mv print on a read-only mount
_MODE = re.compile(r"[0-7]{3,4}")


class AuditSink(Protocol):
    """The part of ``services.audit.AuditRecorder`` the toolbox needs."""

    async def record(
        self,
        uow: UnitOfWorkPort,
        *,
        org_id: str,
        actor_type: ActorType,
        actor_id: str | None,
        action: str,
        target_type: str | None = None,
        target_id: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class Actor:
    org_id: str
    key_id: str | None


@dataclass(slots=True)
class FileDownload:
    """An opened download; ``stream`` is a tar for directories, raw bytes for files."""

    path: str
    name: str
    kind: Literal["file", "dir"]
    size_bytes: int
    stream: AsyncIterator[bytes]
    raw: AsyncIterator[bytes]  # the driver's tar stream underneath ``stream``
    mtime: float | None = None  # epoch seconds from the stat; None when it gave none

    async def close(self) -> None:
        await close_stream(self.stream)
        await close_stream(self.raw)


AUDITED_RANGE_CHARS = 100  # a Range header is client text: only its start goes to the audit row


def _download_details(target: str, method: str, range_header: str | None) -> dict[str, Any]:
    """Audit details of a plain download: GET and HEAD are told apart, a ranged one names it."""
    details: dict[str, Any] = {"path": target, "inline": False, "method": method}
    if range_header is not None:
        details["range"] = range_header[:AUDITED_RANGE_CHARS]
    return details


def _symlink_conflict(target: str) -> Conflict:
    return Conflict("cannot download a symlink", reason=CONFLICT_REASON, details={"path": target})


async def _no_bytes() -> AsyncIterator[bytes]:
    """The stream of a download that was never opened (HEAD)."""
    return
    yield b""


def parse_stat_mtime(stat: Mapping[str, Any]) -> float | None:
    """Epoch seconds of the stat's ``mtime`` (docker gives RFC 3339), None when absent or bad."""
    value = stat.get("mtime")
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.timestamp()
    except (ValueError, OverflowError, OSError):
        return None


@dataclass(frozen=True, slots=True)
class InlineRead:
    path: str
    size_bytes: int
    content: bytes
    truncated: bool


def parse_mode(text: str) -> int:
    if not _MODE.fullmatch(text):
        raise Unprocessable("mode must be 3 or 4 octal digits", details={"mode": text})
    return int(text, 8)


def _excerpt(data: bytes) -> str:
    return data.decode(errors="replace").strip()[:ERROR_EXCERPT_CHARS]


def _read_only_path(lowered: str, paths: Sequence[str]) -> str:
    """The path of ``paths`` the tool named last (``mv`` names the destination after the
    source); the first one when the tool named none."""
    named = [(lowered.rfind(path.lower()), path) for path in paths]
    best, chosen = max(named, key=lambda pair: pair[0])
    return chosen if best >= 0 else paths[0]


def _raise_failure(
    result: ExecResult, action: str, path: str, candidates: Sequence[str] = ()
) -> None:
    message = _excerpt(result.stderr)
    lowered = message.lower()
    whole = result.stderr.decode(errors="replace").lower()  # the excerpt may cut the sentence
    if READ_ONLY_STDERR in whole:
        raise DriverReadOnlyPath.for_path(_read_only_path(whole, candidates or (path,)))
    if "no such file" in lowered:
        raise NotFound(f"no such path: {path}", details={"path": path})
    if any(text in lowered for text in ("not a directory", "file exists", "is a directory")):
        raise Conflict(
            message or f"{action} failed", reason=OPERATION_FAILED, details={"path": path}
        )
    raise DriverError(f"fs {action} failed: {message}")


class FsToolbox:
    def __init__(self, driver: SandboxDriver, recorder: AuditSink, clock: Clock) -> None:
        self._driver = driver
        self._recorder = recorder
        self._clock = clock

    # -- plumbing -------------------------------------------------------------------

    async def _begin(
        self,
        uow: UnitOfWorkPort,
        actor: Actor,
        sandbox_id: str,
        action: str,
        details: Mapping[str, Any],
    ) -> Sandbox:
        """Guard the sandbox, then audit the call before the driver is touched."""
        async with uow:
            sandbox = await load_started_sandbox(uow, actor.org_id, sandbox_id, self._clock)
            await self._recorder.record(
                uow,
                org_id=actor.org_id,
                actor_type=ActorType.API_KEY,
                actor_id=actor.key_id,
                action=action,
                target_type="sandbox",
                target_id=sandbox_id,
                details=details,
            )
            await uow.commit()
            return sandbox

    @staticmethod
    def _ref(sandbox: Sandbox) -> str:
        if sandbox.driver_ref is None:
            raise no_container_conflict(sandbox.state.value, visible_stop_cause(sandbox))
        return sandbox.driver_ref

    def _archive_driver(self) -> ArchiveStreamDriver:
        if not isinstance(self._driver, ArchiveStreamDriver):
            raise DriverUnsupported("the driver does not support archive streaming")
        return self._driver

    async def _run(
        self, sandbox: Sandbox, argv: Sequence[str], max_output: int = STAT_OUTPUT_BYTES
    ) -> ExecResult:
        request = ExecRequest(
            argv=list(argv), timeout_s=EXEC_TIMEOUT_S, max_output_bytes=max_output
        )
        result = await self._driver.exec(self._ref(sandbox), request)
        if result.timed_out:
            raise DriverTimeout(f"fs {argv[0]} timed out", ref=sandbox.driver_ref)
        return result

    async def _exists(self, sandbox: Sandbox, path: str) -> bool:
        return (await self._run(sandbox, ["test", "-e", path])).exit_code == 0

    async def _mutate(
        self,
        sandbox: Sandbox,
        argv: Sequence[str],
        action: str,
        path: str,
        candidates: Sequence[str] = (),
    ) -> None:
        result = await self._run(sandbox, argv)
        if result.exit_code != 0:
            _raise_failure(result, action, path, candidates)

    async def _probe(
        self,
        sandbox: Sandbox,
        argv_for: Callable[[StatVariant], list[str]],
        path: str,
        *,
        directory: str | None = None,
        max_output: int = STAT_OUTPUT_BYTES,
    ) -> list[FsEntry]:
        """Run a stat-based command, falling back to the next format variant if needed."""
        last_problem = "no stat variant worked"
        for variant in VARIANTS:
            result = await self._run(sandbox, argv_for(variant), max_output)
            if result.truncated:
                raise PayloadTooLarge("directory listing is too large", details={"path": path})
            if result.exit_code != 0:
                last_problem = _excerpt(result.stderr)
                if looks_unsupported(last_problem):
                    continue
                _raise_failure(result, "stat", path)
            try:
                return parse_stat_output(result.stdout, variant, directory=directory)
            except FsParseError as exc:
                last_problem = str(exc)
        raise DriverError(f"stat is not usable in this sandbox: {last_problem}")

    async def _stat(self, sandbox: Sandbox, path: str) -> FsEntry:
        entries = await self._probe(sandbox, lambda variant: stat_argv(path, variant), path)
        if len(entries) != 1:
            raise DriverError(f"stat returned {len(entries)} records for {path}")
        return entries[0]

    async def _is_directory(self, sandbox: Sandbox, path: str) -> bool:
        """True only when a stat confirms a directory; a missing or unreadable path is not."""
        try:
            return (await self._stat(sandbox, path)).kind == "dir"
        except (NotFound, DriverError):
            return False  # the upload itself reports a broken sandbox or parent

    # -- queries --------------------------------------------------------------------

    async def stat_path(
        self, uow: UnitOfWorkPort, actor: Actor, sandbox_id: str, path: str
    ) -> FsEntry:
        target = normalize_path(path)
        sandbox = await self._begin(uow, actor, sandbox_id, "toolbox.fs.stat", {"path": target})
        return await self._stat(sandbox, target)

    async def list_dir(
        self, uow: UnitOfWorkPort, actor: Actor, sandbox_id: str, path: str
    ) -> tuple[str, list[FsEntry]]:
        target = normalize_path(path)
        sandbox = await self._begin(uow, actor, sandbox_id, "toolbox.fs.list", {"path": target})
        if (await self._stat(sandbox, target)).kind == "file":
            raise Conflict("not a directory", reason=CONFLICT_REASON, details={"path": target})
        entries = await self._probe(
            sandbox,
            lambda variant: list_argv(target, variant),
            target,
            directory=target,
            max_output=LIST_OUTPUT_BYTES,
        )
        return target, sorted_entries(entries)

    # -- mutations ------------------------------------------------------------------

    async def mkdir(
        self,
        uow: UnitOfWorkPort,
        actor: Actor,
        sandbox_id: str,
        path: str,
        *,
        mode: str = "755",
        parents: bool = True,
    ) -> tuple[str, bool]:
        target = normalize_path(path)
        refuse_pseudo_filesystem(target)
        parse_mode(mode)
        details = {"path": target, "mode": mode, "parents": parents}
        sandbox = await self._begin(uow, actor, sandbox_id, "toolbox.fs.mkdir", details)
        existed = await self._exists(sandbox, target)
        argv = ["mkdir", "-m", mode, *(["-p"] if parents else []), target]
        await self._mutate(sandbox, argv, "mkdir", target)
        return target, not existed

    async def move(
        self,
        uow: UnitOfWorkPort,
        actor: Actor,
        sandbox_id: str,
        source: str,
        destination: str,
        *,
        overwrite: bool = False,
    ) -> tuple[str, str]:
        src = normalize_path(source)
        dst = normalize_path(destination)
        if ROOT in (src, dst) or src == dst:
            raise Unprocessable("source and destination must differ and not be the root")
        refuse_pseudo_filesystem(dst)
        details = {"source": src, "destination": dst, "overwrite": overwrite}
        sandbox = await self._begin(uow, actor, sandbox_id, "toolbox.fs.move", details)
        if not overwrite and await self._exists(sandbox, dst):
            raise Conflict(
                "destination already exists", reason=ALREADY_EXISTS, details={"path": dst}
            )
        parent, _ = split_parent(dst)
        if not await self._exists(sandbox, parent):
            raise NotFound(
                f"no such directory: {parent}; create it first", details={"path": parent}
            )
        argv = ["mv", *(["-f"] if overwrite else []), src, dst]
        await self._mutate(sandbox, argv, "move", src, (dst, src))
        return src, dst

    async def delete(
        self,
        uow: UnitOfWorkPort,
        actor: Actor,
        sandbox_id: str,
        path: str,
        *,
        recursive: bool = False,
    ) -> str:
        target = normalize_path(path)
        if target == ROOT:
            raise Unprocessable("refusing to delete the filesystem root")
        details = {"path": target, "recursive": recursive}
        sandbox = await self._begin(uow, actor, sandbox_id, "toolbox.fs.delete", details)
        argv = ["rm", *(["-r"] if recursive else []), target]
        await self._mutate(sandbox, argv, "delete", target)
        return target

    # -- transfers ------------------------------------------------------------------

    async def upload_file(
        self,
        uow: UnitOfWorkPort,
        actor: Actor,
        sandbox_id: str,
        path: str,
        body: AsyncIterator[bytes],
        *,
        size: int,
        max_bytes: int,
        mode: str = "644",
        overwrite: bool = True,
    ) -> tuple[str, int]:
        target = normalize_path(path)
        refuse_pseudo_filesystem(target)
        parent, name = split_parent(target)
        file_mode = parse_mode(mode)
        details = {"path": target, "size_bytes": size, "mode": mode, "overwrite": overwrite}
        sandbox = await self._begin(uow, actor, sandbox_id, "toolbox.fs.upload", details)
        if size > max_bytes:
            raise upload_limit_error(max_bytes, size)
        archive = self._archive_driver()
        if await self._is_directory(sandbox, target):
            raise Conflict(
                f"is a directory: {target}; upload to a file path inside it",
                reason=CONFLICT_REASON,
                details={"path": target},
            )
        if not overwrite and await self._exists(sandbox, target):
            raise Conflict("file already exists", reason=ALREADY_EXISTS, details={"path": target})
        stream = tar_upload_stream(
            body,
            name=name,
            size=size,
            mode=file_mode,
            mtime=int(self._clock.now().timestamp()),
            max_bytes=max_bytes,
        )
        try:
            await archive.put_archive(self._ref(sandbox), parent, stream)
        except (PayloadTooLarge, Unprocessable, DriverConflict):
            # DriverConflict covers the driver's disk-full error: the partial file would
            # otherwise keep holding the last free space.
            await self._discard_partial(sandbox, target)
            raise
        except DriverNotFound as exc:
            raise NotFound(
                f"no such directory: {parent}; create it first", details={"path": parent}
            ) from exc
        finally:
            await close_stream(stream)
        await self._verify_written(sandbox, target, size)
        return target, size

    async def _verify_written(self, sandbox: Sandbox, path: str, size: int) -> None:
        """Answer an error, not a success, when the archive left no file or a short one.

        One stat after the write. A stat that cannot run or be read (unsupported format, a
        driver hiccup) proves nothing, so only a confirmed missing file or a confirmed other
        size fails the upload.
        """
        try:
            entry = await self._stat(sandbox, path)
        except NotFound:
            raise DriverError(f"upload to {path} was not written", ref=sandbox.driver_ref) from None
        except DriverError:
            return
        if entry.kind == "file" and entry.size_bytes != size:
            raise DriverError(
                f"upload to {path} wrote {entry.size_bytes} of {size} bytes",
                ref=sandbox.driver_ref,
            )

    async def _discard_partial(self, sandbox: Sandbox, path: str) -> None:
        try:
            await self._run(sandbox, ["rm", "-f", path])
        except DriverError:
            pass  # best effort; the upload failure is what the caller needs

    async def _open_download(self, sandbox: Sandbox, target: str) -> FileDownload:
        try:
            stat, chunks = await self._archive_driver().get_archive_with_stat(
                self._ref(sandbox), target
            )
        except DriverNotFound:
            # The same answer HEAD gives from its stat, so the two error bodies are alike.
            raise NotFound(f"no such path: {target}", details={"path": target}) from None
        kind = archive_kind(stat)
        name = posixpath.basename(target) or "root"
        size = int(stat.get("size", 0))
        if kind == "symlink":
            await close_stream(chunks)
            raise _symlink_conflict(target)
        if kind == "dir":
            return FileDownload(target, name, "dir", size, chunks, chunks)
        mtime = parse_stat_mtime(stat)
        return FileDownload(target, name, "file", size, extract_file(chunks), chunks, mtime)

    async def download_path(
        self,
        uow: UnitOfWorkPort,
        actor: Actor,
        sandbox_id: str,
        path: str,
        *,
        range_header: str | None = None,
    ) -> FileDownload:
        target = normalize_path(path)
        details = _download_details(target, "GET", range_header)
        sandbox = await self._begin(uow, actor, sandbox_id, "toolbox.fs.download", details)
        return await self._open_download(sandbox, target)

    async def head_path(
        self,
        uow: UnitOfWorkPort,
        actor: Actor,
        sandbox_id: str,
        path: str,
        *,
        range_header: str | None = None,
    ) -> FileDownload:
        """The download's metadata from a stat: no archive is opened, so its streams are empty.

        Under /proc, /sys and /dev a stat succeeds where the archive does not (docker answers
        404 for most files there), so those paths ask the archive exactly as GET does and
        HEAD answers whatever GET would.
        """
        target = normalize_path(path)
        details = _download_details(target, "HEAD", range_header)
        sandbox = await self._begin(uow, actor, sandbox_id, "toolbox.fs.download", details)
        if under_pseudo_filesystem(target):
            return await self._open_download(sandbox, target)
        entry = await self._stat(sandbox, target)
        if entry.kind == "symlink":
            raise _symlink_conflict(target)
        name = posixpath.basename(target) or "root"
        if entry.kind == "dir":
            return FileDownload(target, name, "dir", entry.size_bytes, _no_bytes(), _no_bytes())
        return FileDownload(
            target, name, "file", entry.size_bytes, _no_bytes(), _no_bytes(), float(entry.mtime)
        )

    async def read_inline(
        self,
        uow: UnitOfWorkPort,
        actor: Actor,
        sandbox_id: str,
        path: str,
        *,
        max_bytes: int,
        cap: int,
    ) -> InlineRead:
        target = normalize_path(path)
        details = {"path": target, "inline": True, "max_bytes": max_bytes, "method": "GET"}
        sandbox = await self._begin(uow, actor, sandbox_id, "toolbox.fs.download", details)
        if max_bytes > cap:
            raise PayloadTooLarge(
                f"inline reads are limited to {cap} bytes", details={"max_bytes": cap}
            )
        download = await self._open_download(sandbox, target)
        if download.kind == "dir" or download.size_bytes > cap:
            await download.close()
            if download.kind == "dir":
                raise Unprocessable("inline reads need a file", details={"path": target})
            raise PayloadTooLarge(
                f"file is larger than the {cap} byte inline limit", details={"max_bytes": cap}
            )
        try:
            content, truncated = await read_limited(download.stream, max_bytes)
        finally:
            await download.close()
        return InlineRead(target, download.size_bytes, content, truncated)
