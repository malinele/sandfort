"""Snapshot name, tier, resources and image resolution of ``SandboxService``, a mixin."""

import dataclasses

from sandfort.auth.label_scope import current_label_scope
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.snapshot import SnapshotState
from sandfort.errors import InvalidState, NotFound
from sandfort.services.image_policy import check_user_image_reference
from sandfort.services.sandbox_commands import (
    DEFAULT_IMAGE,
    SNAPSHOT_ID_PREFIX,
    CreateSandboxCommand,
)
from sandfort.services.sandbox_create_rules import SandboxCreateRulesMixin
from sandfort.services.snapshot_resources import merge_recorded
from sandfort.services.snapshots import snapshot_in_label_scope


class SnapshotResolutionMixin(SandboxCreateRulesMixin):
    """Resolve what a create names as its snapshot: id, tier, resources and image."""

    async def _with_snapshot_id(
        self, org_id: str, command: CreateSandboxCommand
    ) -> CreateSandboxCommand:
        """Replace a snapshot name of this org with the snapshot's id.

        A value that starts with the id prefix is already an id. A name that matches no snapshot,
        or whose snapshot is outside the caller's label scope, stays as it is and takes the
        image-reference path, so a scoped key cannot tell the two apart or learn the id. The
        state check is left to the id steps that follow, so the outcome equals a create by id.
        """
        name = command.snapshot
        if name is None or name.startswith(SNAPSHOT_ID_PREFIX):
            return command
        async with self._uow_factory() as uow:
            found = await uow.snapshots.get_by_name(org_id, name)
            if found is None or not await snapshot_in_label_scope(uow, found):
                return command
        return dataclasses.replace(command, snapshot=found.id)

    async def _inherit_snapshot_tier(
        self, org_id: str, command: CreateSandboxCommand
    ) -> CreateSandboxCommand:
        """Give a create that names no tier the tier recorded on its snapshot, if any.

        An explicit tier wins. A recorded tier this deployment does not offer is refused
        with the unavailable-tier 422 rather than replaced by the default.
        """
        snapshot_id = command.snapshot
        if command.isolation is not None or snapshot_id is None:
            return command
        if not snapshot_id.startswith(SNAPSHOT_ID_PREFIX):
            return command
        async with self._uow_factory() as uow:
            found = await uow.snapshots.get(org_id, snapshot_id)
        if found is None or found.isolation is None:  # a missing snapshot is reported later
            return command
        self._validate_isolation(found.isolation, f" (recorded on snapshot {snapshot_id})")
        return dataclasses.replace(command, isolation=found.isolation)

    async def _inherit_snapshot_resources(
        self, org_id: str, command: CreateSandboxCommand
    ) -> CreateSandboxCommand:
        """Opt-in: fill the resource fields the request left unset from the snapshot's record.

        Only a snapshot id (names are resolved to ids before this) whose row recorded resources
        changes anything; an explicit field wins. The merged values face the per-sandbox
        maximum again, so an oversized record is a 422, never clamped.
        """
        snapshot_id = command.snapshot
        if not command.inherit_resources or snapshot_id is None:
            return command
        if not snapshot_id.startswith(SNAPSHOT_ID_PREFIX):
            return command
        async with self._uow_factory() as uow:
            found = await uow.snapshots.get(org_id, snapshot_id)
        if found is None or found.resources is None:  # a missing snapshot is reported later
            return command
        merged = merge_recorded(command.resources, found.resources)
        self._check_resource_maximum(merged)
        return dataclasses.replace(command, resources=merged)

    async def _require_visible_snapshot(self, org_id: str, snapshot: str | None) -> None:
        """A label-scoped create from a snapshot id needs its source sandbox in scope (else 404).

        Runs before the warm pool is asked, since a standby built from such a snapshot would
        otherwise be claimed without ever resolving the snapshot. A missing snapshot is reported
        by ``_resolve_image``.
        """
        if current_label_scope() is None or snapshot is None:
            return
        if not snapshot.startswith(SNAPSHOT_ID_PREFIX):
            return
        async with self._uow_factory() as uow:
            found = await uow.snapshots.get(org_id, snapshot)
            if found is not None and not await snapshot_in_label_scope(uow, found):
                raise NotFound(f"snapshot {snapshot} not found")

    async def _resolve_image(self, uow: UnitOfWorkPort, org_id: str, snapshot: str | None) -> str:
        """A snapshot id resolves to its pinned image; anything else is an image reference."""
        if snapshot is None:
            return DEFAULT_IMAGE
        if not snapshot.startswith(SNAPSHOT_ID_PREFIX):
            check_user_image_reference(snapshot, self._settings.allowed_registries)
            return snapshot
        found = await uow.snapshots.get(org_id, snapshot)
        if found is None or not await snapshot_in_label_scope(uow, found):
            raise NotFound(f"snapshot {snapshot} not found")
        if found.state is not SnapshotState.READY:
            raise InvalidState(
                f"snapshot {snapshot} is {found.state.value}",
                details={"state": found.state.value},
            )
        return found.image_ref
