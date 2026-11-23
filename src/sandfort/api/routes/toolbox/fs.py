"""``/fs`` toolbox routes: list, stat, mkdir, move, delete, streamed upload and download.

Authentication, org scoping and the error envelope are the same as the process routes;
the work (path validation, guard, audit, driver calls) lives in ``toolbox.fs.FsToolbox``.
Upload bodies are streamed into the driver; downloads are streamed out and never
use the envelope, except inline reads which return a JSON envelope.
"""

import logging
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BeforeValidator
from pydantic_core import PydanticCustomError

from sandfort.api.deps import get_audit_recorder, get_driver, get_uow
from sandfort.api.envelope import Envelope, fail, ok
from sandfort.api.errors import REQUEST_ID_ATTR
from sandfort.api.middleware.request_id import DeferredAudit, audit_before_write
from sandfort.api.query_guard import KnownQuery, single_valued
from sandfort.api.routes.toolbox.scope_guard import require_visible_sandbox
from sandfort.api.safe_json import SafeJSONResponse
from sandfort.api.schemas import toolbox_fs as schemas
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.clock import SystemClock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.org import Scope
from sandfort.drivers.base import SandboxDriver
from sandfort.errors import Unprocessable
from sandfort.services.audit import AuditRecorder
from sandfort.toolbox.fs import Actor, AuditSink, FileDownload, FsToolbox
from sandfort.toolbox.fs_parse import FsEntry
from sandfort.toolbox.fs_range import (
    ByteWindow,
    RangeNotSatisfiable,
    parse_range,
    upload_limit_error,
    window_stream,
)

router = APIRouter(
    prefix="/v1/sandboxes/{sandbox_id}/toolbox/fs",
    tags=["toolbox"],
    dependencies=[Depends(require_visible_sandbox)],
)

logger = logging.getLogger(__name__)
_CLOCK = SystemClock()
TAR_MEDIA_TYPE = "application/x-tar"
FILE_MEDIA_TYPE = "application/octet-stream"
ACCEPT_RANGES = "bytes"

ToolboxUser = Annotated[Principal, Depends(require_scopes(Scope.TOOLBOX))]
Uow = Annotated[UnitOfWorkPort, Depends(get_uow)]
Driver = Annotated[SandboxDriver, Depends(get_driver)]
Recorder = Annotated[AuditRecorder, Depends(get_audit_recorder)]
PathQuery = Annotated[str, Query()]
PathOnce = Annotated[None, Depends(single_valued("path"))]
DownloadOnce = Annotated[None, Depends(single_valued("path", "inline", "max_bytes"))]
UploadOnce = Annotated[None, Depends(single_valued("path", "overwrite", "mode", "size_bytes"))]
_SIZE_BYTES_DOC = (
    "Upload size in bytes; required when the body is sent without Content-Length. "
    "Plain decimal digits only (no sign, decimal point, exponent or surrounding spaces), "
    f"at most {schemas.MAX_UPLOAD_BYTES}: a larger plain number answers 413 before the body "
    "is read, any other form is 422. "
    "When both are sent they must match, else 422 UNPROCESSABLE and nothing is written; "
    "a body whose length differs from the declared size is also 422."
)
_DIGITS = re.compile(r"[0-9]+")
_MAX_DIGITS = 4000  # int() refuses longer digit strings; those stay a 422


def _strict_digits(value: object) -> object:
    """Refuse a size that is not plain decimal digits before lax int parsing (round 54).

    Lax parsing read ``"10.0"`` and ``" 10 "`` as 10; the declared size goes into a tar header,
    so only the plain form is taken.
    """
    if isinstance(value, str) and _DIGITS.fullmatch(value) is None:
        raise PydanticCustomError(
            "int_parsing", "Input should be a non-negative integer written as plain digits"
        )
    return value


def _refuse_oversize(value: object) -> object:
    """413 for a plain-digit ``size_bytes`` above the upload limit, before the body (round 64).

    Checked here rather than as ``Query(le=...)`` alone so the answer is the same 413 as an
    oversize ``Content-Length``, not a 422 on the parameter. The ``le`` stays in the schema.
    """
    if isinstance(value, str) and _DIGITS.fullmatch(value) and len(value) <= _MAX_DIGITS:
        size = int(value)
        if size > schemas.MAX_UPLOAD_BYTES:  # read at call time so the cap can be tuned
            raise upload_limit_error(schemas.MAX_UPLOAD_BYTES, size)
    return value


SizeBytesQuery = Annotated[
    int | None,
    Query(ge=0, le=schemas.MAX_UPLOAD_BYTES, description=_SIZE_BYTES_DOC),
    BeforeValidator(_strict_digits),
    BeforeValidator(_refuse_oversize),
]


_MIN_INLINE_BYTES = 1
_SIGNED_DIGITS = re.compile(r"-[0-9]+|[0-9]+")
_INLINE_BOUND_MESSAGE = "Input should be an integer from {ge} to {le}"


def _inline_bound_error(kind: str) -> PydanticCustomError:
    """The one bound message for every out-of-range inline limit (round 57)."""
    cap = schemas.MAX_INLINE_READ_BYTES  # read at call time so the cap can be tuned
    return PydanticCustomError(kind, _INLINE_BOUND_MESSAGE, {"ge": _MIN_INLINE_BYTES, "le": cap})


def _inline_limit(value: object) -> object:
    """Refuse an inline limit outside 1 to the cap with one bound message (rounds 56, 57).

    Plain digits, optionally after a single ``-``, are range-checked here; every other form
    keeps the ``int_parsing`` message. Error types stay as before: ``greater_than_equal``
    for 0, ``less_than_equal`` above the cap (a 20-digit value included) and ``int_parsing``
    for a negative value; only the message is shared. The bound is checked here rather than
    as ``Query(le=...)`` so the published query schema stays as exported.
    """
    if isinstance(value, bool) or not isinstance(value, str | int):
        return value
    if isinstance(value, str):
        if _SIGNED_DIGITS.fullmatch(value) is None:
            return _strict_digits(value)  # raises the parsing message
        if value.startswith("-"):
            raise _inline_bound_error("int_parsing")
        if len(value.lstrip("0")) > len(str(schemas.MAX_INLINE_READ_BYTES)):
            raise _inline_bound_error("less_than_equal")  # before int(): no digit-limit error
        number = int(value)
    else:
        number = value
    if number < _MIN_INLINE_BYTES:
        raise _inline_bound_error("greater_than_equal")
    if number > schemas.MAX_INLINE_READ_BYTES:
        raise _inline_bound_error("less_than_equal")
    return value


# The inline read limit: plain digits only (``"5.0"``, ``" 5"``, ``"+5"`` are 422
# ``int_parsing`` with the parsing message), at least 1 and at most the handler's default cap
# (0, negative and above-cap values share the bound message naming that range).
MaxBytesQuery = Annotated[
    int | None,
    Query(ge=_MIN_INLINE_BYTES),
    BeforeValidator(_inline_limit),
]


def _toolbox(driver: SandboxDriver, recorder: AuditSink) -> FsToolbox:
    return FsToolbox(driver, recorder, _CLOCK)


def _actor(principal: Principal) -> Actor:
    return Actor(org_id=principal.org_id, key_id=principal.key_id)


def _file_entry(entry: FsEntry) -> schemas.FileEntry:
    try:
        modified: datetime | None = datetime.fromtimestamp(entry.mtime, UTC)
    except (OverflowError, OSError, ValueError):
        modified = None
    return schemas.FileEntry(
        name=entry.name,
        path=entry.path,
        kind=entry.kind,
        size_bytes=max(entry.size_bytes, 0),
        mode=format(entry.mode, "03o"),
        modified_at=modified,
    )


@router.get("/list")
async def list_directory(
    sandbox_id: str,
    principal: ToolboxUser,
    _known: KnownQuery,
    _once: PathOnce,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
    path: PathQuery = "/",
) -> Envelope[schemas.FsListResponse]:
    resolved, entries = await _toolbox(driver, recorder).list_dir(
        uow, _actor(principal), sandbox_id, path
    )
    return ok(
        schemas.FsListResponse(path=resolved, entries=[_file_entry(entry) for entry in entries])
    )


@router.get("/stat")
async def stat_path(
    sandbox_id: str,
    path: PathQuery,
    principal: ToolboxUser,
    _known: KnownQuery,
    _once: PathOnce,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
) -> Envelope[schemas.FsStatResponse]:
    entry = await _toolbox(driver, recorder).stat_path(uow, _actor(principal), sandbox_id, path)
    return ok(schemas.FsStatResponse(entry=_file_entry(entry)))


@router.post("/mkdir")
async def make_directory(
    sandbox_id: str,
    body: schemas.FsMkdirRequest,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
) -> Envelope[schemas.FsMkdirResponse]:
    path, created = await _toolbox(driver, recorder).mkdir(
        uow, _actor(principal), sandbox_id, body.path, mode=body.mode, parents=body.parents
    )
    return ok(schemas.FsMkdirResponse(path=path, created=created))


@router.post("/move")
async def move_path(
    sandbox_id: str,
    body: schemas.FsMoveRequest,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
) -> Envelope[schemas.FsMoveResponse]:
    source, destination = await _toolbox(driver, recorder).move(
        uow,
        _actor(principal),
        sandbox_id,
        body.source,
        body.destination,
        overwrite=body.overwrite,
    )
    return ok(schemas.FsMoveResponse(source=source, destination=destination))


@router.post("/delete")
async def delete_path(
    sandbox_id: str,
    body: schemas.FsDeleteRequest,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
) -> Envelope[schemas.FsDeleteResponse]:
    path = await _toolbox(driver, recorder).delete(
        uow, _actor(principal), sandbox_id, body.path, recursive=body.recursive
    )
    return ok(schemas.FsDeleteResponse(path=path, deleted=True))


def _declared_size(request: Request, size_bytes: int | None) -> int:
    """The tar header needs the size up front: Content-Length, else ``size_bytes``."""
    header = request.headers.get("content-length")
    if header is None:
        if size_bytes is None:
            raise Unprocessable("Content-Length or the size_bytes query parameter is required")
        return size_bytes
    try:
        declared = int(header)
    except ValueError:
        raise Unprocessable("invalid Content-Length header") from None
    if declared < 0:
        raise Unprocessable("invalid Content-Length header")
    limit = schemas.MAX_UPLOAD_BYTES  # read at call time so the cap can be tuned
    if declared > limit:  # refuse before the body is read
        raise upload_limit_error(limit, declared)
    if size_bytes is not None and size_bytes != declared:  # refuse before the body is read
        raise Unprocessable(
            f"size_bytes declares {size_bytes} bytes but the request body has {declared} bytes",
            details={"declared_bytes": size_bytes, "received_bytes": declared},
        )
    return declared


@router.put("/upload")
async def upload_file(
    request: Request,
    sandbox_id: str,
    path: PathQuery,
    principal: ToolboxUser,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
    _once: UploadOnce,
    overwrite: bool = True,
    mode: str = "644",
    size_bytes: SizeBytesQuery = None,
) -> Envelope[schemas.FsUploadResponse]:
    """Stream the request body into a file of the sandbox."""
    # Audit trade-off (intent-then-act): the ``success`` row is committed right before the
    # archive is written, so a file that reaches the sandbox is always auditable, even when the
    # audit write after the driver call would have failed. The cost is that a refusal found
    # while the body streams (a short or long body, a full disk) follows a row that already
    # says ``success``. That later ``denied`` or ``error`` row carries ``details.supersedes``,
    # the id of the first row, so a reader can pair the two. A refusal found before the write
    # (path, existing file, size limits) leaves a single ``denied`` row.
    declared = _declared_size(request, size_bytes)
    audit = DeferredAudit(recorder)  # held through the checks, committed before the write
    writer = audit_before_write(driver, audit, uow)  # put_archive commits the row first
    try:
        resolved, written = await _toolbox(writer, audit).upload_file(
            uow,
            _actor(principal),
            sandbox_id,
            path,
            request.stream(),
            size=declared,
            max_bytes=schemas.MAX_UPLOAD_BYTES,  # read at call time so the cap can be tuned
            mode=mode,
            overwrite=overwrite,
        )
    except Exception as exc:
        await _settle_refused(audit, uow, exc)
        raise
    return ok(schemas.FsUploadResponse(path=resolved, size_bytes=written))


async def _settle_refused(audit: DeferredAudit, uow: UnitOfWorkPort, error: Exception) -> None:
    """Write the upload's refusal row as denied or error; never masks the error being answered."""
    try:
        await audit.settle(uow, error)
    except Exception:
        logger.exception("failed to audit a refused upload")


async def _stream_download(
    download: FileDownload, window: ByteWindow | None = None
) -> AsyncIterator[bytes]:
    source = download.stream if window is None else window_stream(download.stream, window)
    try:
        async for chunk in source:
            yield chunk
    finally:
        await download.close()


def _file_headers(download: FileDownload) -> dict[str, str]:
    """Content-Length and a weak ETag for a file whose size the stat before the stream gave.

    A directory is streamed as a tar whose length is not the stat size, so it gets neither.
    A size of 0 is treated as unknown (the stat mapping defaults to 0 when it has no size), as
    a wrong Content-Length would break the response; an empty file is simply sent chunked. The
    ETag needs the modification time too; it is sent only when the stat gave ``mtime``.
    """
    size = download.size_bytes
    if download.kind != "file" or size <= 0:
        return {}
    headers = {"Content-Length": str(size)}
    if download.mtime is not None:
        headers["ETag"] = f'W/"{size:x}-{int(download.mtime):x}"'
    return headers


def _range_refused(request: Request, size: int) -> SafeJSONResponse:
    body = fail(
        "RANGE_NOT_SATISFIABLE",
        f"the requested range lies outside the file ({size} bytes)",
        details={"size_bytes": size},
        request_id=getattr(request.state, REQUEST_ID_ATTR, None),
    )
    return SafeJSONResponse(
        status_code=416,
        content=body.model_dump(mode="json"),
        headers={"Content-Range": f"bytes */{size}", "Accept-Ranges": ACCEPT_RANGES},
    )


def _ranged(download: FileDownload, window: ByteWindow | None) -> StreamingResponse:
    """The file response: 200 whole, or 206 with the window's bytes cut out of the stream."""
    filename = download.name
    headers = {
        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}",
        "Accept-Ranges": ACCEPT_RANGES,
        **_file_headers(download),
    }
    if window is None:
        return StreamingResponse(
            _stream_download(download), media_type=FILE_MEDIA_TYPE, headers=headers
        )
    headers["Content-Length"] = str(window.length)
    headers["Content-Range"] = window.content_range
    return StreamingResponse(
        _stream_download(download, window),
        status_code=206,
        media_type=FILE_MEDIA_TYPE,
        headers=headers,
    )


def _download_response(download: FileDownload) -> StreamingResponse:
    """The whole download: a directory as a tar, a file as raw bytes."""
    return _tar_response(download) if download.kind == "dir" else _ranged(download, None)


def _tar_response(download: FileDownload) -> StreamingResponse:
    return StreamingResponse(
        _stream_download(download),
        media_type=TAR_MEDIA_TYPE,
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(download.name + '.tar')}",
            "Accept-Ranges": "none",
        },
    )


def _if_range_matches(request: Request, download: FileDownload) -> bool:
    """True when the request has no ``If-Range`` or it names the file's current ETag.

    The ETag is weak, so the comparison ignores the ``W/`` prefix on either side. A date form
    never matches: no ``Last-Modified`` is sent. A file without an ETag matches nothing.
    """
    validator = request.headers.get("if-range")
    if validator is None:
        return True
    etag = _file_headers(download).get("ETag")
    return etag is not None and validator.strip().removeprefix("W/") == etag.removeprefix("W/")


def _download_answer(request: Request, download: FileDownload) -> Response:
    """The response for a download: a directory's tar, a file whole, or a 206 window of it.

    Raises :class:`RangeNotSatisfiable`; the caller owns closing the download on any failure.
    """
    if download.kind == "dir":
        return _download_response(download)
    header = request.headers.get("range") if _if_range_matches(request, download) else None
    return _ranged(download, parse_range(header, download.size_bytes))


async def _serve_download(request: Request, download: FileDownload, *, head: bool) -> Response:
    """A download answer; for ``head`` the same status and headers with no body.

    Whatever goes wrong before the response owns the stream (an unsatisfiable range, a bug), the
    opened driver archive is closed.
    """
    try:
        response = _download_answer(request, download)
    except RangeNotSatisfiable as refused:
        await download.close()
        return _range_refused(request, refused.size)
    except BaseException:
        await download.close()
        raise
    if not head:
        return response
    await download.close()  # the stream was never started; release the driver archive
    bodiless = Response(
        status_code=response.status_code,
        headers=dict(response.headers),
        media_type=response.media_type,
    )
    if "content-length" not in response.headers:
        del bodiless.headers["content-length"]  # an unknown length is not 0
    return bodiless


_DOWNLOAD_DESCRIPTION = (
    "Stream a file as `application/octet-stream`, or a directory as a tar. A file whose size "
    "is known carries `Content-Length` and, when its modification time is known too, a weak "
    "`ETag`. A file answers `Accept-Ranges: bytes` and honours one `Range` (206, or 416 when "
    "the range lies outside the file); a directory tar answers `Accept-Ranges: none`. "
    "`HEAD` on the same path answers the same status and headers without a body."
)


@router.get("/download", response_model=None, description=_DOWNLOAD_DESCRIPTION)
async def download_path(
    request: Request,
    sandbox_id: str,
    path: PathQuery,
    principal: ToolboxUser,
    _known: KnownQuery,
    _once: DownloadOnce,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
    inline: bool = False,
    max_bytes: MaxBytesQuery = None,
) -> Response:
    toolbox = _toolbox(driver, recorder)
    if not inline:
        download = await toolbox.download_path(
            uow, _actor(principal), sandbox_id, path, range_header=request.headers.get("range")
        )
        return await _serve_download(request, download, head=False)
    cap = schemas.MAX_INLINE_READ_BYTES  # read at call time so the cap can be tuned
    result = await toolbox.read_inline(
        uow,
        _actor(principal),
        sandbox_id,
        path,
        max_bytes=cap if max_bytes is None else max_bytes,
        cap=cap,
    )
    body = schemas.FsDownloadResponse(
        path=result.path,
        size_bytes=result.size_bytes,
        content=result.content.decode(errors="replace"),
        truncated=result.truncated,
    )
    return SafeJSONResponse(ok(body).model_dump(mode="json"))


@router.head("/download")
async def head_download(
    request: Request,
    sandbox_id: str,
    path: PathQuery,
    principal: ToolboxUser,
    _known: KnownQuery,
    _once: DownloadOnce,
    uow: Uow,
    driver: Driver,
    recorder: Recorder,
    inline: bool = False,  # accepted and ignored: the headers are those of the plain download
    max_bytes: MaxBytesQuery = None,  # accepted and ignored, as ``inline``
) -> Response:
    """The headers of the download (and of its ranged form) without the body.

    Answered from a stat; the archive is never opened.
    """
    download = await _toolbox(driver, recorder).head_path(
        uow, _actor(principal), sandbox_id, path, range_header=request.headers.get("range")
    )
    return await _serve_download(request, download, head=True)
