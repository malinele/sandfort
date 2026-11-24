"""``/v1/images/builds``: declarative image builds.

``POST`` answers 202 with the pending snapshot, or 200 with the ready snapshot when the same spec
was built before. ``GET /{snapshot_id}/logs`` streams the build log as server-sent events: one
``log`` event per line (replayed from the first line for a late subscriber) and a final ``state``
event carrying the terminal state, after which the stream ends. Audit events are recorded by the
service and never contain log content. For a label-scoped caller the builder's own image
identifiers (internal tag, ``Successfully built`` id, the classic builder's step ``---> <id>``,
``Running in <id>`` and ``Removing/Removed intermediate container <id>`` ids, ``sha256:`` digest,
``writing image`` target) are replaced by a placeholder in the log lines and in the final
event's ``reason``; tenant output is left alone.
"""

import re
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import StreamingResponse

from sandfort.api.envelope import Envelope, ok
from sandfort.api.held_stream import capped_body
from sandfort.api.routes.sandbox_logs import LogSlots
from sandfort.api.schemas.image_builds import BuildImageRequest, BuildImageResponse, build_response
from sandfort.api.sse import DEFAULT_KEEPALIVE_INTERVAL_S, format_event, with_keepalive
from sandfort.api.wiring import IMAGE_BUILD_SERVICE_ATTR
from sandfort.auth.label_scope import current_label_scope
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.domain.org import Scope
from sandfort.errors import InternalError
from sandfort.services.image_builds import ImageBuildService

router = APIRouter(prefix="/v1/images/builds", tags=["image-builds"])

HTTP_OK = 200
HTTP_ACCEPTED = 202

REDACTED_IMAGE = "the built image"
# Only the shapes the builder itself prints, so a tenant's own output (git SHAs, `sha256sum`
# lines, `pip --hash=sha256:<hex>`) is left alone. Case-insensitive.
_BUILDER_IMAGE_SHAPE = re.compile(
    r"sandfort-snapshot:[\w.-]+"  # the internal image tag
    r"|(?<=Successfully built )[0-9a-f]{12}\b"  # the classic builder's image id
    r"|(?<=---> )[0-9a-f]{12}\b"  # a classic builder step's image id
    r"|(?<=Running in )[0-9a-f]{12}\b"  # a classic builder step's container id
    r"|(?<=Removing intermediate container )[0-9a-f]{12}\b"  # the same container, removed
    r"|(?<=Removed intermediate container )[0-9a-f]{12}\b"  # the live builder's past tense
    r"|(?<![\w=])sha256:[0-9a-f]{64}\b"  # an image digest, not a `--hash=` value
    r"|(?<=writing image )\S+",  # the BuildKit export line names the image
    re.IGNORECASE,
)


def _redact_image_details(line: str) -> str:
    """Replace the builder's own image identifiers in ``line`` with a fixed placeholder.

    These are the internal tag ``sandfort-snapshot:<id>``, the 12-hex id after ``Successfully
    built``, ``---> ``, ``Running in `` and ``Removing/Removed intermediate container `` (the
    classic builder's step lines), ``sha256:<64 hex>`` (not when it follows ``=`` or a word
    character) and what follows ``writing image``. Every other text is returned unchanged.
    """
    return _BUILDER_IMAGE_SHAPE.sub(REDACTED_IMAGE, line)


def get_image_build_service(request: Request) -> ImageBuildService:
    value = getattr(request.app.state, IMAGE_BUILD_SERVICE_ATTR, None)
    if not isinstance(value, ImageBuildService):
        raise InternalError("image build service is misconfigured")
    return value


Reader = Annotated[Principal, Depends(require_scopes(Scope.SNAPSHOTS_READ))]
Writer = Annotated[Principal, Depends(require_scopes(Scope.SNAPSHOTS_WRITE))]
Service = Annotated[ImageBuildService, Depends(get_image_build_service)]


@router.post("", status_code=HTTP_ACCEPTED)
async def build_image(
    body: BuildImageRequest, principal: Writer, service: Service, response: Response
) -> Envelope[BuildImageResponse]:
    snapshot = await service.build(principal.org_id, principal.key_id, body.spec, body.name)
    result = build_response(snapshot)
    if result.reused:
        response.status_code = HTTP_OK
    return ok(result)


async def _frames(
    service: ImageBuildService, org_id: str, snapshot_id: str, lines: AsyncIterator[str]
) -> AsyncIterator[str]:
    index = 0
    label_scoped = current_label_scope() is not None
    try:
        async for line in lines:
            shown = _redact_image_details(line) if label_scoped else line
            yield format_event({"line": shown}, event="log", event_id=str(index))
            index += 1
    finally:
        aclose = getattr(lines, "aclose", None)
        if aclose is not None:
            await aclose()
    snapshot = await service.get(org_id, snapshot_id)
    reason = service.failure_reason(snapshot_id)
    final = {
        "state": snapshot.state.value,
        "snapshot_id": snapshot.id,
        "digest": None if label_scoped else (snapshot.digest or None),
        "reason": _redact_image_details(reason) if label_scoped and reason else reason,
    }
    yield format_event(final, event="state")


_LOGS_DESCRIPTION = (
    "Stream the build log as server-sent events: one `log` event per line (replayed from the "
    "first line for a late subscriber), then a final `state` event with the terminal state, "
    "after which the stream ends.\n\n"
    "A label-scoped caller sees the image identifiers the builder prints replaced by the "
    "placeholder `the built image`: the internal tag `sandfort-snapshot:<id>`, the id after "
    "`Successfully built`, the classic builder's step ids after `---> `, `Running in ` and "
    "`Removing intermediate container ` or `Removed intermediate container ` (12 hex), a "
    "`sha256:<64 hex>` digest (any case) and "
    "the image named on a `writing image` line. The same replacement applies to `reason` of "
    "the final event, whose `digest` is `null`. Other lines, including the build's own output "
    "such as a bare hex id, git SHAs or `--hash=sha256:...` and `sha256=...` values, are sent "
    "unchanged."
)


@router.get("/{snapshot_id}/logs", description=_LOGS_DESCRIPTION)
async def stream_build_logs(
    snapshot_id: str, principal: Reader, service: Service, slots: LogSlots
) -> StreamingResponse:
    async def make_frames() -> AsyncIterator[str]:
        lines = await service.follow_build_logs(principal.org_id, snapshot_id)  # 404 first
        return with_keepalive(
            _frames(service, principal.org_id, snapshot_id, lines),
            interval_s=DEFAULT_KEEPALIVE_INTERVAL_S,
        )

    return StreamingResponse(
        await capped_body(slots, principal.org_id, make_frames),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
