"""``/v1/sandboxes`` create/list/get/patch/start/stop/reset/delete, and ``GET /v1/isolation``.

P1 runs lifecycle inline (no job runner), so every response already carries the
settled state: create answers 201, the other operations 200. The module exports one
``router`` (the app includes only that); it carries the sandbox routes and the read-only
isolation tier listing that creates choose from.
"""

import json
import logging
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.exceptions import RequestValidationError

from sandfort.api.dead_sandbox import settle_if_dead
from sandfort.api.deps import get_driver, get_sandbox_service, get_settings
from sandfort.api.envelope import Envelope, ok
from sandfort.api.label_query import parse_label_filter
from sandfort.api.pagination import decode_cursor, encode_cursor
from sandfort.api.query_guard import KnownQuery, single_valued
from sandfort.api.safe_json import SafeJSONResponse
from sandfort.api.schemas.common import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, Meta
from sandfort.api.schemas.sandboxes import (
    CreateSandboxRequest,
    IsolationResponse,
    SandboxResponse,
    UpdateSandboxRequest,
    sandbox_response,
)
from sandfort.api.wiring import REPLAY_HEADER, IdempotencyGuard, idempotency_guard
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import check_scopes, require_scopes
from sandfort.config import Settings
from sandfort.db.repositories.ports import SortOrder
from sandfort.domain.org import Scope
from sandfort.domain.sandbox import SandboxState
from sandfort.errors import NotFound
from sandfort.services.sandboxes import CreateSandboxCommand, SandboxService
from sandfort.services.volumes import MountRequest, mount_scopes

logger = logging.getLogger(__name__)

sandboxes_router = APIRouter(prefix="/v1/sandboxes", tags=["sandboxes"])
isolation_router = APIRouter(prefix="/v1/isolation", tags=["sandboxes"])

MAX_WAIT_TIMEOUT_S = 60.0
DEFAULT_WAIT_TIMEOUT_S = 30.0

Reader = Annotated[Principal, Depends(require_scopes(Scope.SANDBOXES_READ))]
Writer = Annotated[Principal, Depends(require_scopes(Scope.SANDBOXES_WRITE))]
Service = Annotated[SandboxService, Depends(get_sandbox_service)]
Config = Annotated[Settings, Depends(get_settings)]
Idempotent = Annotated[IdempotencyGuard, Depends(idempotency_guard)]
GetOnce = Annotated[None, Depends(single_valued("wait_for", "timeout_s"))]
CREATED = 201

# List query parameters that take one value; repeating one answers 422 (``label`` may repeat).
SINGLE_VALUE_FILTERS = (
    "state",
    "stop_cause",
    "order",
    "limit",
    "include_destroyed",
    "cursor",
)
# The values of ``domain.sandbox.STOP_CAUSES`` (a test keeps the two in step), spelled out so the
# query parameter is an enum in the OpenAPI spec and an unknown value answers 422.
StopCauseFilter = Literal["requested", "auto_stop", "container_exited", "oom_killed", "unknown"]


REPLAY_DESCRIPTION = (
    "Create a sandbox. With an `Idempotency-Key` header the same key and body replays the first "
    "response for one day (24 hours) after it was stored; after that the key is forgotten and "
    "the request creates a new sandbox. A replay answers the stored status code with the "
    "sandbox's current representation, not the stored body: a sandbox deleted in the meantime "
    "replays as state `destroyed`. If its row no longer exists, the stored body is replayed "
    "unchanged. Replays carry the `Idempotent-Replayed: true` header."
)


def _stored_sandbox_id(body: bytes) -> str | None:
    """The sandbox id in a stored create response, or ``None`` when it has none."""
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    data = parsed.get("data") if isinstance(parsed, dict) else None
    sandbox_id = data.get("id") if isinstance(data, dict) else None
    return sandbox_id if isinstance(sandbox_id, str) else None


async def _current_replay(
    replay: SafeJSONResponse, org_id: str, service: SandboxService, default_isolation: str
) -> SafeJSONResponse:
    """The replayed create answered with the sandbox's current state (stored status code)."""
    sandbox_id = _stored_sandbox_id(bytes(replay.body))
    if sandbox_id is None:
        return replay
    try:
        sandbox = await service.get(org_id, sandbox_id)
    except NotFound:
        return replay
    envelope = ok(sandbox_response(sandbox, default_isolation))
    return SafeJSONResponse(
        status_code=replay.status_code,
        content=envelope.model_dump(mode="json"),
        headers={REPLAY_HEADER: "true"},
    )


def _require_mount_access(principal: Principal, body: CreateSandboxRequest) -> None:
    """403 unless the key holds the scope each requested mount needs.

    A read-only mount needs ``volumes:read``, a read-write one ``volumes:write``. Checked
    before the idempotency guard, so a refused create stores nothing. Whether a label-scoped
    key may mount a given volume depends on the volume's labels and is decided when the
    mounts are resolved (``services.volumes.resolve_mounts``).
    """
    requests = [
        MountRequest(item.volume_id, item.mount_path, item.read_only) for item in body.volumes
    ]
    check_scopes(principal, mount_scopes(requests))


@sandboxes_router.post(
    "",
    status_code=CREATED,
    response_model=Envelope[SandboxResponse],
    description=REPLAY_DESCRIPTION,
)
async def create_sandbox(
    body: CreateSandboxRequest,
    principal: Writer,
    service: Service,
    settings: Config,
    idempotent: Idempotent,
) -> Envelope[SandboxResponse] | SafeJSONResponse:
    _require_mount_access(principal, body)
    command = CreateSandboxCommand(
        name=body.name,
        snapshot=body.snapshot,
        resources=body.resources,
        inherit_resources=body.inherit_resources,
        env=body.env,
        labels=body.labels,
        network=body.network,
        auto_stop_minutes=body.auto_stop_minutes,
        auto_delete_minutes=body.auto_delete_minutes,
        public=body.public,
        isolation=body.isolation,
    )

    async def create() -> Envelope[SandboxResponse]:
        sandbox = await service.create(principal.org_id, principal.key_id, command)
        return ok(sandbox_response(sandbox, settings.default_isolation))

    result = await idempotent.run(principal.org_id, CREATED, create, request_model=body)
    if isinstance(result, SafeJSONResponse):
        return await _current_replay(result, principal.org_id, service, settings.default_isolation)
    return result


@sandboxes_router.get("")
async def list_sandboxes(
    request: Request,
    principal: Reader,
    service: Service,
    settings: Config,
    _known: KnownQuery,
    state: Annotated[
        SandboxState | None,
        Query(
            description=(
                "Only sandboxes in this state. Give it once: a repeated value answers 422."
            )
        ),
    ] = None,
    stop_cause: Annotated[
        StopCauseFilter | None,
        Query(
            description=(
                "Only sandboxes showing this stop cause (the `stop_cause` field of the sandbox: "
                "set while `stopping` or `stopped`, `unknown` for a stop recorded without one). "
                "Combines with `state`, `label`, `order` and `cursor`. "
                "Give it once: a repeated value answers 422."
            )
        ),
    ] = None,
    label: Annotated[
        list[str] | None,
        Query(
            description=(
                "k=v, repeatable; all must match; "
                "a key given twice with different values is refused (422)"
            )
        ),
    ] = None,
    include_destroyed: Annotated[
        bool,
        Query(
            description=(
                "Without a `state` filter, include `destroyed` tombstones in the list. "
                "By default they are hidden; `state=destroyed` always returns them. "
                "Give it once: a repeated value answers 422."
            )
        ),
    ] = False,
    order: Annotated[
        SortOrder,
        Query(
            description=(
                "Sort by creation time: `asc` (default) lists the oldest first, `desc` the newest "
                "first. `next_cursor` continues in the chosen order, so page through with the "
                "same `order` on every request. Give it once: a repeated value answers 422."
            )
        ),
    ] = "asc",
    cursor: Annotated[
        str | None,
        Query(
            description=(
                "The `next_cursor` of the previous page. It is refused with 422 when the filter "
                "(`state`, `stop_cause`, `label`, `include_destroyed`) or the `order` differs "
                "from the one that issued it; `ctx.fields` of the error names each differing field "
                "and `ctx.reason` says how. Give it once: a repeated value answers 422."
            )
        ),
    ] = None,
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=MAX_PAGE_SIZE,
            description="Page size. Give it once: a repeated value answers 422.",
        ),
    ] = DEFAULT_PAGE_SIZE,
) -> Envelope[list[SandboxResponse]]:
    """
    List sandboxes.

    ``label`` is ``k=v`` and may repeat; a sandbox must carry every pair. A pair without ``=``,
    or with an empty key, is refused with 422, and so is a key that is blank or has control
    characters. Both refusals have one ``details.errors`` entry: ``type``, ``loc``, ``msg``.
    ``label=k=`` is accepted as the key ``k`` with an empty value, and ``label=a=b=c`` as the
    key ``a`` with the value ``b=c``; neither is an error, they simply match nothing unless a
    sandbox carries exactly that label. One key given twice with different values is refused
    with 422 at ``query.label``; the exact same pair repeated counts once.
    """
    _require_single_values(request, SINGLE_VALUE_FILTERS)
    labels = parse_label_filter(label or [])
    bound = {
        "state": state,
        "stop_cause": stop_cause,
        "labels": labels,
        "order": order,
        "include_destroyed": include_destroyed,
    }
    after = None if cursor is None else decode_cursor(cursor, bound)
    # Fetch one extra row to learn whether another page exists.
    rows = await service.list(
        principal.org_id,
        state=state,
        labels=labels,
        cursor=after,
        limit=limit + 1,
        include_destroyed=include_destroyed,
        order=order,
        stop_cause=stop_cause,
    )
    page = rows[:limit]
    next_cursor = encode_cursor(page[-1].id, bound) if len(rows) > limit else None
    default = settings.default_isolation
    data = [sandbox_response(item, default) for item in page]
    return ok(data, meta=Meta(next_cursor=next_cursor))


@sandboxes_router.get("/{sandbox_id}")
async def get_sandbox(
    sandbox_id: str,
    principal: Reader,
    service: Service,
    settings: Config,
    _known: KnownQuery,
    _once: GetOnce,
    wait_for: SandboxState | None = None,
    timeout_s: Annotated[float, Query(ge=0, le=MAX_WAIT_TIMEOUT_S)] = DEFAULT_WAIT_TIMEOUT_S,
) -> Envelope[SandboxResponse]:
    sandbox = await service.get(
        principal.org_id, sandbox_id, wait_for=wait_for, timeout_s=timeout_s
    )
    return ok(sandbox_response(sandbox, settings.default_isolation))


@sandboxes_router.patch("/{sandbox_id}")
async def update_sandbox(
    sandbox_id: str,
    body: UpdateSandboxRequest,
    principal: Writer,
    service: Service,
    settings: Config,
) -> Envelope[SandboxResponse]:
    sandbox = await service.update(
        principal.org_id,
        principal.key_id,
        sandbox_id,
        labels=body.labels,
        auto_stop_minutes=body.auto_stop_minutes,
        auto_delete_minutes=body.auto_delete_minutes,
        public=body.public,
    )
    return ok(sandbox_response(sandbox, settings.default_isolation))


async def _settle_if_dead_before_start(
    request: Request, service: SandboxService, org_id: str, sandbox_id: str
) -> None:
    """Mark a ``started`` row whose container is already dead stopped, so start really starts.

    Without this the service treats ``started`` as reached and answers a silent no-op for the
    seconds before a reconciler pass sees the dead container. The row is loaded through the
    service (same org, label-scoped like every route); a sandbox the key cannot see is left to
    the start to answer. Any other failure is logged and the start proceeds as it would anyway.
    """
    try:
        sandbox = await service.get(org_id, sandbox_id)
        if sandbox.state is not SandboxState.STARTED or not sandbox.driver_ref:
            return
        # One inspect (``instance_is_dead``) inside ``settle_if_dead``; it never waits.
        await settle_if_dead(request, get_driver(request), sandbox)
    except NotFound:
        return
    except Exception:
        logger.exception("dead-container check before starting sandbox %s failed", sandbox_id)


@sandboxes_router.post("/{sandbox_id}/start")
async def start_sandbox(
    sandbox_id: str, request: Request, principal: Writer, service: Service, settings: Config
) -> Envelope[SandboxResponse]:
    # A started row whose container already died is marked stopped first, so it really starts.
    await _settle_if_dead_before_start(request, service, principal.org_id, sandbox_id)
    sandbox = await service.start(principal.org_id, principal.key_id, sandbox_id)
    return ok(sandbox_response(sandbox, settings.default_isolation))


@sandboxes_router.post("/{sandbox_id}/stop")
async def stop_sandbox(
    sandbox_id: str, principal: Writer, service: Service, settings: Config
) -> Envelope[SandboxResponse]:
    sandbox = await service.stop(principal.org_id, principal.key_id, sandbox_id)
    return ok(sandbox_response(sandbox, settings.default_isolation))


@sandboxes_router.post("/{sandbox_id}/reset")
async def reset_sandbox(
    sandbox_id: str, principal: Writer, service: Service, settings: Config
) -> Envelope[SandboxResponse]:
    """Replace the container with a fresh one from the same image and spec.

    Keeps the sandbox id, name, labels, resources, env, network policy, isolation tier, volume
    mounts and auto timers. Everything written to the old container is gone; volumes are kept.
    Allowed from `started` (ends `started`) and `stopped` (ends `stopped`); other states answer
    409. Refused with 409 while a snapshot of the sandbox is in progress and when sandbox
    lifecycle runs as jobs.
    """
    sandbox = await service.reset(principal.org_id, principal.key_id, sandbox_id)
    return ok(sandbox_response(sandbox, settings.default_isolation))


@sandboxes_router.delete("/{sandbox_id}")
async def delete_sandbox(
    sandbox_id: str, principal: Writer, service: Service, settings: Config
) -> Envelope[SandboxResponse]:
    sandbox = await service.delete(principal.org_id, principal.key_id, sandbox_id)
    return ok(sandbox_response(sandbox, settings.default_isolation))


@isolation_router.get("")
async def list_isolation(
    principal: Reader, settings: Config, _known: KnownQuery
) -> Envelope[IsolationResponse]:
    """The isolation tiers a create may request here, and the one it gets when it names none."""
    del principal  # authorization only: any caller that can read sandboxes
    available = list(settings.isolation_tiers())
    return ok(IsolationResponse(default=settings.default_isolation, available=available))


def _require_single_values(request: Request, names: tuple[str, ...]) -> None:
    """Answer 422 when a single-value query parameter is given more than once."""
    issues = [
        {"type": "value_error", "loc": ("query", name), "msg": f"{name} must be given once"}
        for name in names
        if len(request.query_params.getlist(name)) > 1
    ]
    if issues:
        raise RequestValidationError(issues)


router = APIRouter()
router.include_router(sandboxes_router)
router.include_router(isolation_router)
