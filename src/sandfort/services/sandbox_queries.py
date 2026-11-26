"""Read queries of ``SandboxService`` (``get`` with an optional wait, ``list``), a mixin."""

import asyncio
import time
from collections.abc import Mapping, Sequence

from sandfort.auth.label_scope import current_label_scope
from sandfort.db.repositories.ports import LiveSandboxListing, SandboxRepository, SortOrder
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.services.label_scope import SCAN_PAGE, list_in_order
from sandfort.services.sandbox_listing import list_by_stop_cause
from sandfort.services.sandbox_service_base import SandboxServiceBase

MAX_WAIT_S = 60.0
POLL_INTERVAL_S = 0.1
LIVE_SCAN_PAGE = SCAN_PAGE  # rows per read while skipping tombstones (the repository's page cap)

_S = SandboxState


async def _live_by_scanning(
    repo: SandboxRepository,
    org_id: str,
    labels: Mapping[str, str] | None,
    cursor: str | None,
    limit: int,
    order: SortOrder = "asc",
) -> list[Sandbox]:
    """Up to ``limit`` non-destroyed sandboxes after ``cursor``, read through ``repo.list``.

    The fallback for a repository without ``list_live`` (or one behind a decorator): scan the
    id-ordered pages (in ``order``) and skip tombstones, so a run of destroyed rows never fills
    the page.
    """
    live: list[Sandbox] = []
    while len(live) < limit:
        page = await list_in_order(
            repo, org_id, labels=labels, cursor=cursor, limit=LIVE_SCAN_PAGE, order=order
        )
        live.extend(item for item in page if item.state is not _S.DESTROYED)
        if len(page) < LIVE_SCAN_PAGE:
            break
        cursor = page[-1].id
    return live[:limit]


class SandboxQueriesMixin(SandboxServiceBase):
    """``get`` and ``list`` of ``SandboxService``."""

    async def get(
        self,
        org_id: str,
        sandbox_id: str,
        *,
        wait_for: SandboxState | None = None,
        timeout_s: float = 0.0,
    ) -> Sandbox:
        deadline = time.monotonic() + min(max(timeout_s, 0.0), MAX_WAIT_S)
        while True:
            sandbox = await self._load(org_id, sandbox_id)
            settled = sandbox.state in (wait_for, _S.ERROR, _S.DESTROYED)
            remaining = deadline - time.monotonic()
            if wait_for is None or settled or remaining <= 0:
                return sandbox
            await asyncio.sleep(min(POLL_INTERVAL_S, remaining))

    async def list(
        self,
        org_id: str,
        *,
        state: SandboxState | None = None,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
        include_destroyed: bool = True,
        order: SortOrder = "asc",
        stop_cause: str | None = None,
    ) -> Sequence[Sandbox]:
        """One page by id (``order="desc"``: newest first; the cursor continues in that order).

        Without ``state``, ``include_destroyed=False`` hides tombstones. ``stop_cause`` keeps
        the sandboxes that show that cause (a destroyed row shows none, so no tombstone matches).
        """
        async with self._uow_factory() as uow:
            repo = uow.sandboxes
            if stop_cause is not None:
                return await list_by_stop_cause(
                    repo,
                    org_id,
                    stop_cause,
                    state=state,
                    labels=labels,
                    cursor=cursor,
                    limit=limit,
                    order=order,
                )
            if include_destroyed or state is not None:
                return await list_in_order(
                    repo,
                    org_id,
                    state=state,
                    labels=labels,
                    cursor=cursor,
                    limit=limit,
                    order=order,
                )
            # ``list_live`` is not scope-aware and the event/metering decorators do not forward
            # it, so it is used only on a bare repository with no label scope active.
            if current_label_scope() is None and isinstance(repo, LiveSandboxListing):
                return await repo.list_live(
                    org_id, labels=labels, cursor=cursor, limit=limit, order=order
                )
            return await _live_by_scanning(repo, org_id, labels, cursor, limit, order)
