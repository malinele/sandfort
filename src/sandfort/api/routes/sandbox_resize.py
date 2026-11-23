"""``POST /v1/sandboxes/{sandbox_id}/resize``: change the resources of a stopped sandbox.

Omitted fields keep their value. A sandbox that is not stopped answers 409, a resize beyond
the org quota 429 (``QUOTA_EXCEEDED``) and beyond the host's effective capacity 503
(``CAPACITY``). The next start recreates the container with the new resources and keeps the
files of its root filesystem (the old container is committed to a temporary image, which the
new container starts from; a reset, unlike a resize, still wipes them).
"""

from typing import Annotated

from fastapi import APIRouter, Depends

from sandfort.api.envelope import Envelope, ok
from sandfort.api.schemas.sandboxes import ResizeSandboxRequest, SandboxResponse, sandbox_response
from sandfort.api.wiring import get_resize_service
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.domain.org import Scope
from sandfort.services.resize import ResizeCommand, ResizeService

router = APIRouter(prefix="/v1/sandboxes", tags=["sandboxes"])

Writer = Annotated[Principal, Depends(require_scopes(Scope.SANDBOXES_WRITE))]
Service = Annotated[ResizeService, Depends(get_resize_service)]


@router.post("/{sandbox_id}/resize")
async def resize_sandbox(
    sandbox_id: str, body: ResizeSandboxRequest, principal: Writer, service: Service
) -> Envelope[SandboxResponse]:
    command = ResizeCommand(
        cpu_millicores=body.cpu_millicores,
        memory_mib=body.memory_mib,
        disk_gib=body.disk_gib,
    )
    sandbox = await service.resize(principal.org_id, principal.key_id, sandbox_id, command)
    return ok(sandbox_response(sandbox))
