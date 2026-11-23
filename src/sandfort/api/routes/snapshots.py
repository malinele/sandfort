"""``/v1/snapshots`` register/create-from-sandbox/list/get/export/delete.

Registering pulls inline and answers 201 with a ready snapshot. Creating from a sandbox
answers 202 with the pending row; the ``snapshot.create`` job commits the container and the
row turns ``ready`` (or ``error``). Deleting answers 409 while a sandbox uses the snapshot.
"""

import re
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse

from sandfort.api.deps import get_audit_recorder, get_driver, get_uow
from sandfort.api.envelope import Envelope, ok
from sandfort.api.label_query import parse_label_filter
from sandfort.api.pagination import SNAPSHOTS, decode_cursor, encode_cursor
from sandfort.api.query_guard import KnownQuery, single_valued
from sandfort.api.schemas.common import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, Meta
from sandfort.api.schemas.snapshots import (
    CreateSnapshotFromSandboxRequest,
    RegisterSnapshotRequest,
    SnapshotResponse,
    snapshot_response,
)
from sandfort.api.wiring import SNAPSHOT_SERVICE_ATTR, IdempotencyGuard, idempotency_guard
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType
from sandfort.domain.org import Scope
from sandfort.domain.snapshot import Snapshot, SnapshotState
from sandfort.drivers.base import ImageExportDriver, SandboxDriver
from sandfort.errors import UNSUPPORTED_MODE, Conflict, InternalError, InvalidState
from sandfort.services.audit import AuditRecorder
from sandfort.services.snapshots import SnapshotService

router = APIRouter(prefix="/v1/snapshots", tags=["snapshots"])


def get_snapshot_service(request: Request) -> SnapshotService:
    value = getattr(request.app.state, SNAPSHOT_SERVICE_ATTR, None)
    if not isinstance(value, SnapshotService):
        raise InternalError("snapshot service is misconfigured")
    return value


Reader = Annotated[Principal, Depends(require_scopes(Scope.SNAPSHOTS_READ))]
Writer = Annotated[Principal, Depends(require_scopes(Scope.SNAPSHOTS_WRITE))]
Service = Annotated[SnapshotService, Depends(get_snapshot_service)]
Idempotent = Annotated[IdempotencyGuard, Depends(idempotency_guard)]
Driver = Annotated[SandboxDriver, Depends(get_driver)]
Uow = Annotated[UnitOfWorkPort, Depends(get_uow)]
Recorder = Annotated[AuditRecorder, Depends(get_audit_recorder)]
ListOnce = Annotated[None, Depends(single_valued("limit", "cursor"))]
CREATED = 201
ACCEPTED = 202
EXPORT_AUDIT_ACTION = "snapshot.exported"
EXPORT_MEDIA_TYPE = "application/x-tar"
MAX_EXPORT_NAME_CHARS = 100
_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


@router.post("", status_code=CREATED, response_model=Envelope[SnapshotResponse])
async def register_snapshot(
    body: RegisterSnapshotRequest, principal: Writer, service: Service, idempotent: Idempotent
) -> Envelope[SnapshotResponse] | JSONResponse:
    async def create() -> Envelope[SnapshotResponse]:
        snapshot = await service.register(
            principal.org_id, principal.key_id, body.image, body.name, body.labels
        )
        return ok(snapshot_response(snapshot))

    return await idempotent.run(principal.org_id, CREATED, create, request_model=body)


@router.post("/from-sandbox", status_code=ACCEPTED, response_model=Envelope[SnapshotResponse])
async def create_snapshot_from_sandbox(
    body: CreateSnapshotFromSandboxRequest,
    principal: Writer,
    service: Service,
    idempotent: Idempotent,
) -> Envelope[SnapshotResponse] | JSONResponse:
    async def create() -> Envelope[SnapshotResponse]:
        snapshot = await service.create_from_sandbox(
            principal.org_id, principal.key_id, body.sandbox_id, body.name, body.labels
        )
        return ok(snapshot_response(snapshot))

    return await idempotent.run(principal.org_id, ACCEPTED, create, request_model=body)


@router.get("")
async def list_snapshots(
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
) -> Envelope[list[SnapshotResponse]]:
    """List snapshots; ``label`` is ``k=v`` and may repeat, a snapshot must carry every pair."""
    labels = parse_label_filter(label or [])
    bound = {"labels": labels}  # a cursor is bound to this list and to the label filter
    after = None if cursor is None else decode_cursor(cursor, bound, resource=SNAPSHOTS)
    # Fetch one extra row to learn whether another page exists.
    rows = await service.list(principal.org_id, labels=labels, cursor=after, limit=limit + 1)
    page = rows[:limit]
    last = page[-1].id if len(rows) > limit else None
    next_cursor = None if last is None else encode_cursor(last, bound, resource=SNAPSHOTS)
    return ok([snapshot_response(item) for item in page], meta=Meta(next_cursor=next_cursor))


@router.get("/{snapshot_id}")
async def get_snapshot(
    snapshot_id: str, principal: Reader, service: Service
) -> Envelope[SnapshotResponse]:
    snapshot = await service.get(principal.org_id, snapshot_id)
    return ok(snapshot_response(snapshot))


def export_file_name(snapshot: Snapshot) -> str:
    """``<snapshot name>.tar`` with only ``[A-Za-z0-9._-]``; the snapshot id when none is left."""
    stem = _UNSAFE_NAME_CHARS.sub("-", snapshot.name).strip("-.")[:MAX_EXPORT_NAME_CHARS]
    return f"{stem or snapshot.id}.tar"


async def _export_body(first: bytes, rest: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    """The already-read first chunk, then the rest; the driver stream is closed on any exit."""
    try:
        if first:
            yield first
        async for chunk in rest:
            yield chunk
    finally:
        close = getattr(rest, "aclose", None)
        if close is not None:
            await close()


async def _record_export(
    uow: UnitOfWorkPort, recorder: AuditRecorder, principal: Principal, snapshot: Snapshot
) -> None:
    async with uow:
        await recorder.record(
            uow,
            org_id=principal.org_id,
            actor_type=ActorType.API_KEY,
            actor_id=principal.key_id,
            action=EXPORT_AUDIT_ACTION,
            target_type="snapshot",
            target_id=snapshot.id,
            details={"name": snapshot.name},
        )
        await uow.commit()


@router.get("/{snapshot_id}/export", response_model=None)
async def export_snapshot(
    snapshot_id: str,
    principal: Reader,
    service: Service,
    driver: Driver,
    uow: Uow,
    recorder: Recorder,
) -> StreamingResponse:
    """Download a ready snapshot as an image tar (``application/x-tar``).

    The body is the archive ``docker save`` produces, streamed in chunks and never held in
    memory. Load it on any Docker host with ``docker load < <name>.tar`` (or
    ``docker load -i <name>.tar``). The tar names no repository: ``docker load`` prints the
    image id, so tag it yourself. The image carries the filesystem plus a safe config (no
    sandbox env values, labels or secrets). Only ``ready`` snapshots can be exported (409
    ``INVALID_STATE``, ``error.details.state`` names the state); a driver without image
    export answers 409 ``CONFLICT`` with reason ``unsupported_mode``. The export is audited
    as ``snapshot.exported`` before streaming.
    """
    snapshot = await service.get(principal.org_id, snapshot_id)
    if snapshot.state is not SnapshotState.READY:
        raise InvalidState(
            f"snapshot {snapshot.id} is {snapshot.state.value}, not ready",
            details={"state": snapshot.state.value},
        )
    if not isinstance(driver, ImageExportDriver):
        raise Conflict("this driver cannot export images", reason=UNSUPPORTED_MODE)
    await _record_export(uow, recorder, principal, snapshot)
    chunks = driver.export_image(snapshot.image_ref)
    # Read one chunk before answering, so a missing image is a 404 rather than a broken body.
    first = await anext(chunks, b"")
    return StreamingResponse(
        _export_body(first, chunks),
        media_type=EXPORT_MEDIA_TYPE,
        headers={"Content-Disposition": f'attachment; filename="{export_file_name(snapshot)}"'},
    )


@router.delete("/{snapshot_id}")
async def delete_snapshot(
    snapshot_id: str, principal: Writer, service: Service
) -> Envelope[SnapshotResponse]:
    snapshot = await service.delete(principal.org_id, principal.key_id, snapshot_id)
    return ok(snapshot_response(snapshot))
