"""``update`` of ``SandboxService`` (labels, timers, public, egress allowlist), a mixin."""

from collections.abc import Mapping
from typing import Any

from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.errors import InvalidState
from sandfort.services.egress_update import EgressUpdate, plan_egress_update
from sandfort.services.sandbox_create_rules import SandboxCreateRulesMixin
from sandfort.services.sandbox_jobs import AuditNote
from sandfort.services.volumes import is_reserved_label

_S = SandboxState


class SandboxUpdateMixin(SandboxCreateRulesMixin):
    """Change a sandbox's labels, timers, visibility or egress allowlist in place."""

    async def update(
        self,
        org_id: str,
        actor_id: str,
        sandbox_id: str,
        *,
        labels: Mapping[str, str] | None = None,
        auto_stop_minutes: int | None = None,
        auto_delete_minutes: int | None = None,
        public: bool | None = None,
        egress_allowlist: tuple[str, ...] | None = None,
    ) -> Sandbox:
        self._validate_minutes(auto_stop_minutes, auto_delete_minutes)
        self._validate_labels(labels)
        requested: dict[str, Any] = {
            "labels": None if labels is None else dict(labels),
            "auto_stop_minutes": auto_stop_minutes,
            "auto_delete_minutes": auto_delete_minutes,
            "public": public,
        }
        changes = {key: value for key, value in requested.items() if value is not None}

        async with self._uow_factory() as uow:
            current = await self._core.require(uow, org_id, sandbox_id)
            if current.state in (_S.DESTROYING, _S.DESTROYED):
                raise InvalidState(
                    f"sandbox is {current.state.value}", details={"state": current.state.value}
                )
            note = AuditNote(actor_id, "sandbox.update", dict(changes))
            # the egress change, when the request carries an effective one
            plan: EgressUpdate | None = None
            if egress_allowlist is not None:  # None: the field was absent
                plan = plan_egress_update(current, egress_allowlist, actor_id, self._settings)
            if plan is not None:
                changes["egress_allowlist"] = plan.allowlist
                changes["egress_policy_generation"] = plan.generation
            if labels is not None:  # replacing user labels keeps the platform's reserved ones
                reserved = {k: v for k, v in current.labels.items() if is_reserved_label(k)}
                changes["labels"] = {**changes["labels"], **reserved}
            changes["updated_at"] = self._clock.now()
            saved = await uow.sandboxes.update(
                org_id, current.model_copy(update=changes), expected_version=current.version
            )
            if plan is None or note.details:  # an egress-only change has no update row
                await self._core.record(uow, org_id, sandbox_id, note)
            if plan is not None:
                await self._core.record(uow, org_id, sandbox_id, plan.note)
            await uow.commit()
        return saved
