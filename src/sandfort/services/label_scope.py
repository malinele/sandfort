"""Sandbox label scope: an API key limited to sandboxes that carry given labels.

``LabelScopedSandboxRepository`` decorates the sandbox repository (like the metering and event
decorators) and reads the request's scope from ``auth.label_scope.current_label_scope``. With no
scope (an unscoped key, or a worker, where the context variable is never set) every call passes
through unchanged. With a scope:

- ``get`` / ``get_by_name`` answer ``None`` for a sandbox whose labels do not match, so the
  caller answers 404 and does not reveal that the sandbox exists;
- ``list`` adds the scope to the labels filter; a requested label that contradicts the scope
  (same key, other value) yields an empty page;
- ``add`` / ``update`` raise ``Forbidden`` when the resulting sandbox's labels do not match;
- every other method (``list_for_reconciler``, ``list_autostop_candidates``, ``list_for_node``,
  warm-pool claims, ...) is a system path and is delegated to the wrapped repository unchanged.

Only sandboxes are scoped. API keys, usage and audit stay org-wide. Volumes and snapshots carry
labels: a label-scoped key lists only volumes carrying its scope and may mount on sandbox create
only a volume whose labels contain the scope (``services.volumes.resolve_mounts``; the refusal
is ``mount_refusal``). A key's ``shared_volume_labels`` add volumes it may list, get and mount
read-only (``shared_write_refusal`` when it asks for read-write); delete stays within the scope.
"""

import inspect
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import Any, cast

from sandfort.auth.label_scope import current_label_scope, matches
from sandfort.db.repositories.ports import (
    OrderedSandboxListing,
    SandboxRepository,
    ScopedSandboxCounting,
    SortOrder,
    StandbyClaim,
    StandbyRepository,
    UnitOfWorkPort,
)
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.errors import Forbidden

SCAN_PAGE = 200  # rows per read while scanning ``list`` pages (the repository's page cap)


async def count_by_scanning(
    repo: SandboxRepository, org_id: str, labels: Mapping[str, str], stop_at: int
) -> int:
    """Non-destroyed sandboxes carrying every ``labels`` pair, counted through ``repo.list``.

    The fallback for a repository without ``count_in_scope``: scan the id-ordered pages, stopping
    once ``stop_at`` is reached (the caller only needs to know whether a cap is hit).
    """
    live, cursor = 0, None
    while True:
        page = await repo.list(org_id, labels=labels, cursor=cursor, limit=SCAN_PAGE)
        live += sum(1 for item in page if item.state is not SandboxState.DESTROYED)
        if live >= stop_at or len(page) < SCAN_PAGE:
            return live
        cursor = page[-1].id


async def count_through(inner: SandboxRepository, org_id: str, labels: Mapping[str, str]) -> int:
    """``inner.count_in_scope`` when it has one, else the scan fallback (no early stop).

    Shared by the repository decorators, which forward the count explicitly because a
    runtime-checkable protocol check ignores ``__getattr__``.
    """
    if isinstance(inner, ScopedSandboxCounting):
        return await inner.count_in_scope(org_id, labels)
    return await count_by_scanning(inner, org_id, labels, stop_at=sys.maxsize)


async def list_in_order(
    repo: SandboxRepository,
    org_id: str,
    *,
    state: SandboxState | None = None,
    labels: Mapping[str, str] | None = None,
    cursor: str | None = None,
    limit: int = 50,
    order: SortOrder = "asc",
) -> Sequence[Sandbox]:
    """``repo.list`` in ``order``, reaching through decorators that do not forward ``order``.

    Ascending is the repository's default, so that call is made exactly as before. For ``desc``
    the event and metering decorators (plain pass-throughs for ``list``) are stepped over via
    their ``_inner`` until a repository whose ``list`` takes ``order`` is found; the label-scope
    decorator takes it, so the scope still applies.
    """
    if order == "asc":
        return await repo.list(org_id, state=state, labels=labels, cursor=cursor, limit=limit)
    target: Any = repo
    while "order" not in inspect.signature(target.list).parameters:
        target = getattr(target, "_inner", None)
        if target is None:
            raise TypeError("the sandbox repository cannot list in descending order")
    ordered: OrderedSandboxListing = target
    return await ordered.list(
        org_id, state=state, labels=labels, cursor=cursor, limit=limit, order=order
    )


def scope_refusal(scope: Mapping[str, str]) -> Forbidden:
    """The 403 for a request that would leave the key's label scope."""
    pairs = ",".join(f"{name}={value}" for name, value in sorted(scope.items()))
    return Forbidden(f"this API key is limited to sandboxes labelled {pairs}")


def mount_refusal(scope: Mapping[str, str], volume_id: str) -> Forbidden:
    """The 403 for mounting ``volume_id`` when its labels do not contain the key's scope.

    The same answer covers a volume that does not exist, so it never reveals whether an id does.
    """
    pairs = ",".join(f"{name}={value}" for name, value in sorted(scope.items()))
    return Forbidden(
        f"this API key is limited to sandboxes labelled {pairs} and cannot mount volumes "
        f"outside that scope: {volume_id}",
        details={"volume_ids": [volume_id]},
    )


def shared_write_refusal(shared: Mapping[str, str], volume_id: str) -> Forbidden:
    """The 403 for a read-write mount of a volume the key reaches only through its shared labels.

    A key's ``shared_volume_labels`` open volumes to read-only mounts alone.
    """
    pairs = ",".join(f"{name}={value}" for name, value in sorted(shared.items()))
    return Forbidden(
        f"volume {volume_id} is shared with this API key (shared_volume_labels {pairs}) and can "
        "only be mounted read-only: set read_only to true",
        details={"volume_ids": [volume_id]},
    )


def shared_delete_refusal(shared: Mapping[str, str], volume_id: str) -> Forbidden:
    """The 403 for deleting a volume the key sees only through its shared labels (round 65).

    The key lists and gets the volume, so a 404 would contradict that; it just cannot delete it.
    """
    pairs = ",".join(f"{name}={value}" for name, value in sorted(shared.items()))
    return Forbidden(
        f"volume {volume_id} is shared with this API key (shared_volume_labels {pairs}) and "
        "cannot be deleted; only a key that owns its labels can delete it",
        details={"volume_ids": [volume_id]},
    )


def shared_transfer_refusal(shared: Mapping[str, str], volume_id: str, verb: str) -> Forbidden:
    """The 403 for exporting or restoring a volume the key reaches only through shared labels.

    ``verb`` is the past participle (``exported`` or ``restored``). Reading a shared volume is
    allowed, taking its data away or replacing it is not: only a key that owns the labels may.
    """
    pairs = ",".join(f"{name}={value}" for name, value in sorted(shared.items()))
    return Forbidden(
        f"volume {volume_id} is shared with this API key (shared_volume_labels {pairs}) and "
        f"cannot be {verb}; only a key that owns its labels can do that",
        details={"volume_ids": [volume_id]},
    )


def shared_publish_refusal(shared: Mapping[str, str]) -> Forbidden:
    """The 403 for creating a volume whose labels would put it in the key's shared pool.

    A key that reads the shared pool through ``shared_volume_labels`` must not also write to it.
    """
    pairs = ",".join(f"{name}={value}" for name, value in sorted(shared.items()))
    return Forbidden(
        f"this API key cannot create volumes carrying its shared_volume_labels ({pairs}); "
        "only a key without them can publish shared data"
    )


def contradicts(labels: Mapping[str, str], scope: Mapping[str, str]) -> bool:
    """True when ``labels`` holds a scope key with another value."""
    return any(name in labels and labels[name] != value for name, value in scope.items())


def scoped_labels(
    scope: Mapping[str, str], labels: Mapping[str, str] | None
) -> dict[str, str] | None:
    """The requested ``labels`` merged with ``scope``; ``None`` when they contradict it.

    The one place a listing turns a key's scope into its SQL label filter: ``None`` means the
    page is empty (the request asks for a sandbox outside the scope).
    """
    requested = labels or {}
    if contradicts(requested, scope):
        return None
    return {**requested, **scope}


def merge_scope(labels: Mapping[str, str], scope: Mapping[str, str] | None) -> dict[str, str]:
    """``labels`` plus the scope pairs; ``Forbidden`` when a label contradicts the scope."""
    if scope is None:
        return dict(labels)
    if contradicts(labels, scope):
        raise scope_refusal(scope)
    return {**labels, **scope}


class LabelScopedSandboxRepository:
    """Decorates a ``SandboxRepository`` so a label-scoped key only sees its own sandboxes."""

    def __init__(self, inner: SandboxRepository) -> None:
        self._inner = inner

    async def add(self, sandbox: Sandbox) -> None:
        self._require_in_scope(sandbox)
        await self._inner.add(sandbox)

    async def update(self, org_id: str, sandbox: Sandbox, *, expected_version: int) -> Sandbox:
        self._require_in_scope(sandbox)
        return await self._inner.update(org_id, sandbox, expected_version=expected_version)

    async def get(self, org_id: str, sandbox_id: str) -> Sandbox | None:
        return self._visible(await self._inner.get(org_id, sandbox_id))

    async def get_by_name(self, org_id: str, name: str) -> Sandbox | None:
        return self._visible(await self._inner.get_by_name(org_id, name))

    async def list(
        self,
        org_id: str,
        *,
        state: SandboxState | None = None,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
        order: SortOrder = "asc",
    ) -> Sequence[Sandbox]:
        scope = current_label_scope()
        if scope is not None:
            labels = scoped_labels(scope, labels)
            if labels is None:
                return []
        rows = await list_in_order(
            self._inner,
            org_id,
            state=state,
            labels=labels,
            cursor=cursor,
            limit=limit,
            order=order,
        )
        # Defense in depth: the SQL filter above is the primary guard, this one catches a row
        # that slipped through it.
        return [row for row in rows if matches(row.labels, scope)]

    @property
    def unscoped(self) -> SandboxRepository:
        """The wrapped repository, for system checks that must see every sandbox in the org."""
        return self._inner

    async def list_for_reconciler(self) -> Sequence[Sandbox]:
        return await self._inner.list_for_reconciler()

    async def count_in_scope(self, org_id: str, labels: Mapping[str, str]) -> int:
        """The cap count: the caller passes the scope itself, so it is delegated unchanged."""
        return await count_through(self._inner, org_id, labels)

    async def list_autostop_candidates(self, node_id: str | None = None) -> Sequence[Sandbox]:
        return await cast(StandbyRepository, self._inner).list_autostop_candidates(node_id)

    async def list_for_node(self, node_id: str) -> Sequence[Sandbox]:
        return await cast(StandbyRepository, self._inner).list_for_node(node_id)

    # The warm pool checks for ``StandbyRepository`` with ``isinstance``, which ignores
    # ``__getattr__``, so every member of that protocol (these four methods) is delegated
    # explicitly. A claim writes the labels of the already scope-merged create command, so it
    # needs no check here.
    async def claim_standby(
        self, org_id: str, spec_hash: str, claim: StandbyClaim
    ) -> Sandbox | None:
        return await cast(StandbyRepository, self._inner).claim_standby(org_id, spec_hash, claim)

    async def count_standby(self, org_id: str, spec_hash: str) -> int:
        return await cast(StandbyRepository, self._inner).count_standby(org_id, spec_hash)

    def __getattr__(self, name: str) -> Any:
        """Any other repository method is a system path: delegate it unchanged."""
        return getattr(self._inner, name)

    def _visible(self, sandbox: Sandbox | None) -> Sandbox | None:
        if sandbox is None or matches(sandbox.labels, current_label_scope()):
            return sandbox
        return None

    @staticmethod
    def _require_in_scope(sandbox: Sandbox) -> None:
        scope = current_label_scope()
        if scope is not None and not matches(sandbox.labels, scope):
            raise scope_refusal(scope)


def unscoped(repo: SandboxRepository) -> SandboxRepository:
    """``repo`` without the label scope decorator; any other repository comes back unchanged."""
    if isinstance(repo, LabelScopedSandboxRepository):
        return repo.unscoped
    return repo


def with_label_scope[U: UnitOfWorkPort](uow_factory: Callable[[], U]) -> Callable[[], U]:
    """A unit-of-work factory whose ``sandboxes`` repository enforces the request's label scope."""

    def factory() -> U:
        uow = uow_factory()
        uow.sandboxes = LabelScopedSandboxRepository(uow.sandboxes)
        return uow

    return factory
