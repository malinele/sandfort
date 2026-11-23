"""The sandbox list filtered by stop cause, answered by the SQL repository.

The label-scope, event and metering repository decorators do not forward ``stop_cause`` (the
frozen port has no such parameter), so the listing steps over them to the repository whose
``list`` takes it, like ``label_scope.list_in_order`` does for ``order``. The key's label scope
is applied here instead of by the skipped decorator: merged into the SQL label filter, with the
decorator's defense-in-depth recheck on the rows.
"""

import inspect
from collections.abc import Mapping, Sequence
from typing import Any

from sandfort.auth.label_scope import current_label_scope, matches
from sandfort.db.repositories.ports import OrderedSandboxListing, SandboxRepository, SortOrder
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.services.label_scope import scoped_labels


def _stop_cause_listing(repo: SandboxRepository) -> OrderedSandboxListing:
    """The wrapped repository whose ``list`` accepts ``stop_cause`` (the SQL one)."""
    target: Any = repo
    while "stop_cause" not in inspect.signature(target.list).parameters:
        target = getattr(target, "_inner", None)
        if target is None:
            raise TypeError("the sandbox repository cannot filter by stop cause")
    listing: OrderedSandboxListing = target
    return listing


async def list_by_stop_cause(
    repo: SandboxRepository,
    org_id: str,
    stop_cause: str,
    *,
    state: SandboxState | None,
    labels: Mapping[str, str] | None,
    cursor: str | None,
    limit: int,
    order: SortOrder,
) -> Sequence[Sandbox]:
    """One page of the sandboxes showing ``stop_cause``; ordering, cursor and scope as ``list``."""
    scope = current_label_scope()
    if scope is not None:
        labels = scoped_labels(scope, labels)
        if labels is None:
            return []
    rows = await _stop_cause_listing(repo).list(
        org_id,
        state=state,
        labels=labels,
        cursor=cursor,
        limit=limit,
        order=order,
        stop_cause=stop_cause,
    )
    return [row for row in rows if matches(row.labels, scope)]
