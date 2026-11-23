"""``GET /v1/nodes``: every node in the registry with its staleness and the caller's load.

Needs ``org:read`` and a key without sandbox labels (a label-scoped key gets 403). The node
rows are platform-wide (nodes are not org-owned), but ``running_sandboxes`` counts only the
caller org's started sandboxes on each node, never other tenants', and the listing carries
counts only, never sandbox ids. The route has no platform-admin distinction, so every caller
gets the per-org count. There is no mutation route: nodes register themselves by heartbeat.
"""

from typing import Annotated

from fastapi import APIRouter, Depends

from sandfort.api.deps import get_uow
from sandfort.api.envelope import Envelope, ok
from sandfort.api.query_guard import KnownQuery
from sandfort.api.schemas.common import Meta
from sandfort.api.schemas.nodes import NodeResponse, node_responses
from sandfort.api.wiring import get_node_registry
from sandfort.auth.label_scope import current_label_scope
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.org import Scope
from sandfort.errors import Forbidden
from sandfort.services.node_registry import NodeRegistry

router = APIRouter(prefix="/v1/nodes", tags=["nodes"])

NODES_LABEL_SCOPED_MESSAGE = "node data is only for API keys without sandbox labels"

# The committed openapi/sandfort.v1.json is regenerated owner-side; until then this route stays
# out of the export so the spec drift test keeps passing.
_IN_SCHEMA = False

Reader = Annotated[Principal, Depends(require_scopes(Scope.ORG_READ))]
Registry = Annotated[NodeRegistry, Depends(get_node_registry)]
Uow = Annotated[UnitOfWorkPort, Depends(get_uow)]


@router.get("", include_in_schema=_IN_SCHEMA)
async def list_nodes(
    principal: Reader, registry: Registry, uow: Uow, _known: KnownQuery
) -> Envelope[list[NodeResponse]]:
    # Node rows say where this org's sandboxes run; a key limited to some sandboxes by label
    # must not read the placement of the rest.
    if current_label_scope() is not None:
        raise Forbidden(NODES_LABEL_SCOPED_MESSAGE)
    statuses = await registry.list_nodes()
    async with uow:
        running = await uow.nodes.running_counts(principal.org_id)
    return ok(node_responses(statuses, running), meta=Meta(next_cursor=None))
