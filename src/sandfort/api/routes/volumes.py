"""``/v1/volumes`` create/list/get/delete.

Creating answers 201 with a ready volume. Reads report the last sampled size. Deleting
answers 409 while a non-deleted sandbox mounts the volume.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse

from sandfort.api.envelope import Envelope, ok
from sandfort.api.label_query import parse_label_filter
from sandfort.api.pagination import VOLUMES, decode_cursor, encode_cursor
from sandfort.api.query_guard import KnownQuery, single_valued
from sandfort.api.schemas import toolbox_fs
from sandfort.api.schemas.common import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, Meta
from sandfort.api.schemas.volumes import (
    CreateVolumeRequest,
    RestoreResponse,
    VolumeResponse,
    volume_response,
)
from sandfort.api.wiring import (
    VOLUME_SERVICE_ATTR,
    VOLUME_TRANSFER_ATTR,
    IdempotencyGuard,
    idempotency_guard,
)
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.domain.org import Scope
from sandfort.errors import InternalError, Unprocessable
from sandfort.services.volume_transfer import VolumeTransfer
from sandfort.services.volumes import VolumeService
from sandfort.toolbox.fs_range import upload_limit_error

router = APIRouter(prefix="/v1/volumes", tags=["volumes"])


def get_volume_service(request: Request) -> VolumeService:
    value = getattr(request.app.state, VOLUME_SERVICE_ATTR, None)
    if not isinstance(value, VolumeService):
        raise InternalError("volume service is misconfigured")
    return value


def get_volume_transfer(request: Request) -> VolumeTransfer:
    value = getattr(request.app.state, VOLUME_TRANSFER_ATTR, None)
    if not isinstance(value, VolumeTransfer):
        raise InternalError("volume transfer is misconfigured")
    return value


Reader = Annotated[Principal, Depends(require_scopes(Scope.VOLUMES_READ))]
Writer = Annotated[Principal, Depends(require_scopes(Scope.VOLUMES_WRITE))]
Service = Annotated[VolumeService, Depends(get_volume_service)]
Transfer = Annotated[VolumeTransfer, Depends(get_volume_transfer)]
Idempotent = Annotated[IdempotencyGuard, Depends(idempotency_guard)]
ListOnce = Annotated[None, Depends(single_valued("limit", "cursor"))]
CREATED = 201
ARCHIVE_MEDIA_TYPE = "application/gzip"


@router.post("", status_code=CREATED, response_model=Envelope[VolumeResponse])
async def create_volume(
    body: CreateVolumeRequest, principal: Writer, service: Service, idempotent: Idempotent
) -> Envelope[VolumeResponse] | JSONResponse:
    async def create() -> Envelope[VolumeResponse]:
        volume = await service.create(principal.org_id, principal.key_id, body.name, body.labels)
        return ok(volume_response(volume))

    return await idempotent.run(principal.org_id, CREATED, create, request_model=body)


@router.get("")
async def list_volumes(
    principal: Reader,
    service: Service,
    _known: KnownQuery,
    _once: ListOnce,
    label: Annotated[
        list[str] | None,
        Query(
            description=(
                "k=v, repeatable; all must match; "
                "a key given twice with different values is refused (422)"
            )
        ),
    ] = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
) -> Envelope[list[VolumeResponse]]:
    """List volumes; ``label`` is ``k=v`` and may repeat, a volume must carry every pair.

    ``label`` is ``k=v, repeatable; all must match; a key given twice with different values
    is refused (422)``.
    """
    labels = parse_label_filter(label or [])
    bound = {"labels": labels}  # a cursor is bound to this list and to the label filter
    after = None if cursor is None else decode_cursor(cursor, bound, resource=VOLUMES)
    # Fetch one extra row to learn whether another page exists.
    rows = await service.list(principal.org_id, labels=labels, cursor=after, limit=limit + 1)
    page = rows[:limit]
    last = page[-1].id if len(rows) > limit else None
    next_cursor = None if last is None else encode_cursor(last, bound, resource=VOLUMES)
    return ok([volume_response(item) for item in page], meta=Meta(next_cursor=next_cursor))


@router.get("/{volume_id}")
async def get_volume(
    volume_id: str, principal: Reader, service: Service
) -> Envelope[VolumeResponse]:
    volume = await service.get(principal.org_id, volume_id)
    return ok(volume_response(volume))


@router.delete("/{volume_id}")
async def delete_volume(
    volume_id: str, principal: Writer, service: Service
) -> Envelope[VolumeResponse]:
    volume = await service.delete(principal.org_id, principal.key_id, volume_id)
    return ok(volume_response(volume))


_EXPORT_DESCRIPTION = (
    "Download the contents of a volume as a gzipped tar (`application/gzip`), streamed with a "
    "`Content-Disposition: attachment` file name taken from the volume name (`<name>.tar.gz`). "
    "The Docker daemon reads the volume through a helper container that is created but never "
    "started (no process runs, no network), with the volume mounted read-only; the tar it "
    "returns is gzipped as it streams. "
    "A volume that a running sandbox mounts can be exported too: it is read while the sandbox "
    "may still write, so files can change during the read and the archive is not a point in "
    "time snapshot. Stop the sandboxes first when you need a consistent copy. A read that "
    "fails after the first bytes were sent ends the body early, so the download is incomplete. "
    "The key must own the volume through its labels: a volume reached only through "
    "`shared_volume_labels` answers 403, an unseen one 404. A driver without volume transfer "
    "answers 409 `CONFLICT` with reason `unsupported_mode`, and a volume being restored 409 "
    "with reason `restore_in_progress`. At most `SANDFORT_MAX_VOLUME_TRANSFERS_PER_ORG` (2) "
    "exports and restores per organization and `SANDFORT_MAX_VOLUME_TRANSFERS` (8) per server "
    "process run at once; over it answers 409 with reason `org_transfer_limit` or "
    "`transfer_limit` (restore shares these caps). The export is audited as `volume.export` "
    "before the first byte; the row names the volume, and the byte count is not known at "
    "that point."
)
_RESTORE_DESCRIPTION = (
    "Replace the contents of a volume with a gzipped tar sent as the raw request body. The "
    "volume is emptied first (removed and created again, same name and labels) and then the "
    "Docker daemon extracts the archive through a helper container that is created but never "
    "started (no process runs, no network), so a restore is not atomic: "
    "a restore that fails after it began leaves the volume EMPTY, and the error says so "
    "(`error.details.volume_emptied`). Refused with 409 `CONFLICT` (reason `in_use`) while any "
    "sandbox that is not deleted mounts the volume, and with reason `restore_in_progress` "
    "while another restore of the volume runs. The body may be up to 256 MiB compressed: a "
    "`Content-Length` above that answers 413 before the body is read. The restored data is "
    "counted as it is extracted and must stay within the volume size limit "
    "(`SANDFORT_VOLUME_MAX_BYTES`, when one is set); over it answers 413 and leaves the volume "
    "empty. A body that is not gzip or is empty answers 422 and changes nothing; a gzip body "
    "that is corrupt, cut short or not a tar answers 422 and leaves the volume empty. Without "
    "a size limit the decompressed size is still capped at 64 times the compressed size "
    "(never below 16 MiB; the declared `Content-Length`, or the bytes received so far when the "
    "body is chunked): over it answers 413 with `details.max_expansion_ratio` and leaves the "
    "volume empty. Only regular files, directories and "
    "symlinks with a relative target inside the volume are accepted; modes (setuid and sticky "
    "bits included), uid, gid and modification times are restored as the tar records them, "
    "extended attributes are not. Any other member answers 422 with `error.details.reason` "
    "`forbidden_entry`, `details.violation` naming the rule (`path_traversal`, `absolute_path`, "
    "`invalid_name`, `invalid_link_target`, `hardlink`, `symlink_absolute`, `symlink_escape`, "
    "`symlink_through`, `duplicate_entry` (a second member whose normalised path equals an "
    "earlier member's, whatever the types), `special_file`, `unsupported_entry`, "
    "`header_too_large`, `too_many_entries`) and `details.entry` the member, "
    "and leaves the volume empty. The key must own the volume through "
    "its labels (403 for a volume reached only through `shared_volume_labels`, 404 for an "
    "unseen one). The result is audited as `volume.restore` with the restored bytes, or with "
    "the failure and whether the volume was emptied."
)


@router.get("/{volume_id}/export", response_model=None, description=_EXPORT_DESCRIPTION)
async def export_volume(
    volume_id: str, principal: Reader, transfer: Transfer, _known: KnownQuery
) -> StreamingResponse:
    opened = await transfer.open_export(principal.org_id, principal.key_id, volume_id)
    return StreamingResponse(
        opened.body,
        media_type=ARCHIVE_MEDIA_TYPE,
        headers={"Content-Disposition": f'attachment; filename="{opened.file_name}"'},
    )


def _refuse_declared_oversize(request: Request) -> int | None:
    """413 for a ``Content-Length`` above the upload limit, before the body is read; 422 for
    one that is not a plain non-negative number. The declared length, or ``None``."""
    header = request.headers.get("content-length")
    if header is None:
        return None
    if not header.isdigit():
        raise Unprocessable("invalid Content-Length header")
    limit = toolbox_fs.MAX_UPLOAD_BYTES  # read at call time so the cap can be tuned
    if int(header) > limit:
        raise upload_limit_error(limit, int(header))
    return int(header)


@router.post(
    "/{volume_id}/restore",
    response_model=Envelope[RestoreResponse],
    description=_RESTORE_DESCRIPTION,
)
async def restore_volume(
    volume_id: str, request: Request, principal: Writer, transfer: Transfer
) -> Envelope[RestoreResponse]:
    declared = _refuse_declared_oversize(request)
    result = await transfer.restore(
        principal.org_id,
        principal.key_id,
        volume_id,
        request.stream(),
        max_upload_bytes=toolbox_fs.MAX_UPLOAD_BYTES,
        declared_length=declared,
    )
    return ok(
        RestoreResponse(
            volume_id=result.volume.id,
            name=result.volume.name,
            restored_bytes=result.restored_bytes,
        )
    )
