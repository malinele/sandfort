"""Create validation, network defaults, env and the new row of ``SandboxService``, a mixin."""

import dataclasses
import re
from collections.abc import Mapping, Sequence
from datetime import datetime

from sandfort.config import ENV_PREFIX, is_reserved_env_name
from sandfort.domain.isolation import isolation_labels
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import (
    NetworkPolicy,
    Sandbox,
    SandboxState,
    check_egress_allowlist,
    take_egress_allowlist,
)
from sandfort.egress.env import compose_proxy_env
from sandfort.errors import Forbidden, InvalidState, Unprocessable
from sandfort.ids import new_sandbox_id
from sandfort.services.egress_provision import without_proxy_variables
from sandfort.services.egress_update import NETWORK_POLICY_MESSAGE
from sandfort.services.image_policy import check_user_image_reference
from sandfort.services.sandbox_commands import SNAPSHOT_ID_PREFIX, CreateSandboxCommand
from sandfort.services.sandbox_jobs import AuditNote
from sandfort.services.sandbox_service_base import SandboxServiceBase
from sandfort.services.volumes import (
    MOUNT_REQUESTS_LABEL,
    RESERVED_LABEL_PREFIX,
    VolumeMount,
    encode_mounts,
    is_reserved_label,
    take_mount_requests,
    validate_mount_requests,
)

MIN_AUTO_MINUTES = -1  # -1 disables the timer

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_S = SandboxState


class SandboxCreateRulesMixin(SandboxServiceBase):
    """The create checks and the row they build, shared by create, update and snapshots."""

    @staticmethod
    def _with_carried_mounts(command: CreateSandboxCommand) -> CreateSandboxCommand:
        """Move what the create schema carried in ``labels`` to ``volumes`` and the allowlist."""
        labels, allowlist = take_egress_allowlist(command.labels)
        if allowlist is not None:
            command = dataclasses.replace(command, labels=labels, egress_allowlist=allowlist)
        if MOUNT_REQUESTS_LABEL not in command.labels:
            return command
        labels, carried = take_mount_requests(command.labels)
        return dataclasses.replace(command, labels=labels, volumes=(*command.volumes, *carried))

    def _with_default_network(self, command: CreateSandboxCommand) -> CreateSandboxCommand:
        """Block the network of a create that names no policy, when the deployment says so.

        Only an unset ``network.block_all`` takes the default: an explicit ``false`` keeps the
        network open, and a create with a non-empty egress allowlist keeps its own rules. An
        empty allowlist reaches nothing, so it always blocks the network (fail closed), whatever
        the default or an explicit ``false``. Runs after ``_with_carried_mounts`` so the
        allowlist is already a command field.

        With ``enforce_block_network`` the default is no longer one a tenant overrides: an
        explicit ``block_all: false`` or a non-empty allowlist is refused with 403, and every
        accepted create is stored with ``block_all`` true.
        """
        if self._settings.enforce_block_network:
            return self._enforced_network(command)
        if command.egress_allowlist is not None and not command.egress_allowlist:
            return dataclasses.replace(command, network=NetworkPolicy(block_all=True))
        if not self._settings.default_block_network:
            return command
        if command.egress_allowlist is not None:
            return command
        if "block_all" in command.network.model_fields_set:
            return command
        return dataclasses.replace(command, network=NetworkPolicy(block_all=True))

    @staticmethod
    def _enforced_network(command: CreateSandboxCommand) -> CreateSandboxCommand:
        opens_network = (
            "block_all" in command.network.model_fields_set and not command.network.block_all
        )
        if opens_network or command.egress_allowlist:
            raise Forbidden(NETWORK_POLICY_MESSAGE)
        return dataclasses.replace(command, network=NetworkPolicy(block_all=True))

    @staticmethod
    def _create_note(actor_id: str, command: CreateSandboxCommand) -> AuditNote:
        details = {
            "name": command.name,
            "snapshot": command.snapshot,
            "resources": command.resources.model_dump(mode="json"),
            "env": dict(command.env),
            "labels": dict(command.labels),
            "network": command.network.model_dump(mode="json"),
            "auto_stop_minutes": command.auto_stop_minutes,
            "auto_delete_minutes": command.auto_delete_minutes,
            "public": command.public,
            "egress_allowlist": command.egress_allowlist,  # hostnames, not secrets
            "isolation": command.isolation,  # None: the deployment default
            "volumes": [
                {
                    "volume_id": mount.volume_id,
                    "mount_path": mount.mount_path,
                    "read_only": mount.read_only,
                }
                for mount in command.volumes
            ],
        }
        return AuditNote(actor_id, "sandbox.create", details)

    def _new_sandbox(
        self,
        org_id: str,
        command: CreateSandboxCommand,
        image_ref: str,
        mounts: Sequence[VolumeMount] = (),
    ) -> Sandbox:
        sandbox_id = new_sandbox_id()
        now = self._clock.now()
        tier = command.isolation or self._settings.default_isolation
        return Sandbox(
            id=sandbox_id,
            org_id=org_id,
            name=command.name or sandbox_id,
            state=_S.PENDING,
            desired_state=_S.STARTED,
            image_ref=image_ref,
            driver=self._driver.name,
            resources=command.resources,
            env=self._sandbox_env(sandbox_id, command, now),
            labels={**command.labels, **encode_mounts(mounts), **isolation_labels(tier)},
            network=command.network,
            public=command.public,
            auto_stop_minutes=command.auto_stop_minutes,
            auto_delete_minutes=command.auto_delete_minutes,
            created_at=now,
            updated_at=now,
            standby=command.standby,
            spec_hash=command.spec_hash,
            egress_allowlist=command.egress_allowlist,
            egress_policy_generation=0 if command.egress_allowlist is None else 1,
            snapshot=command.snapshot,
        )

    def _check_resource_maximum(self, resources: ResourceSpec) -> None:
        """422 when ``resources`` exceed the deployment's per-sandbox maximum."""
        maximum = ResourceSpec(
            cpu_millicores=self._settings.max_sandbox_cpu_millicores,
            memory_mib=self._settings.max_sandbox_memory_mib,
            disk_gib=self._settings.max_sandbox_disk_gib,
        )
        if not resources.fits_within(maximum):
            raise Unprocessable(
                "requested resources exceed the per-sandbox maximum",
                details={
                    "requested": resources.model_dump(),
                    "maximum": maximum.model_dump(),
                },
            )

    def _validate_create(self, command: CreateSandboxCommand) -> None:
        image = command.snapshot
        if image is not None and not image.startswith(SNAPSHOT_ID_PREFIX):
            check_user_image_reference(image, self._settings.allowed_registries)
        reserved = sorted(name for name in command.env if is_reserved_env_name(name))
        if reserved:
            raise Unprocessable(
                f"environment variable names starting with {ENV_PREFIX} are reserved",
                details={"names": reserved},
            )
        malformed = sorted(name for name in command.env if not _ENV_NAME.fullmatch(name))
        if malformed:
            raise Unprocessable("invalid environment variable names", details={"names": malformed})
        self._check_resource_maximum(command.resources)
        self._validate_minutes(command.auto_stop_minutes, command.auto_delete_minutes)
        self._validate_labels(command.labels)
        self._validate_isolation(command.isolation)
        validate_mount_requests(command.volumes)
        if command.volumes and self._use_jobs:
            raise Unprocessable(
                "volume mounts are not supported when sandboxes are created by jobs"
            )
        limit = self._settings.egress_allowlist_max_entries
        check_egress_allowlist(
            command.egress_allowlist,
            command.network,
            limit,
            Unprocessable,
            denied=self._settings.egress_denied_cidrs,
        )
        configured = self._settings.egress_proxy_address and self._settings.egress_secret
        if command.egress_allowlist and not configured:
            raise InvalidState("egress proxy address and secret are not configured")

    def _sandbox_env(
        self, sandbox_id: str, command: CreateSandboxCommand, now: datetime
    ) -> dict[str, str]:
        env = dict(command.env)
        if command.egress_allowlist and self._use_jobs:
            # The node that runs the create job mints (``egress_provision``); a user variable
            # must not pass for a minted one there.
            return without_proxy_variables(env)
        if command.egress_allowlist:
            address, secret = self._settings.egress_proxy_address, self._settings.egress_secret
            proxy_env = compose_proxy_env(
                address,
                secret,
                sandbox_id,
                now,
                ttl_s=self._settings.egress_token_ttl_s,
                auto_delete_minutes=command.auto_delete_minutes,
                epoch=0,
            )
            env.update(proxy_env)
        return env

    @staticmethod
    def _validate_labels(labels: Mapping[str, str] | None) -> None:
        reserved = sorted(name for name in labels or {} if is_reserved_label(name))
        if reserved:
            raise Unprocessable(
                f"label names starting with {RESERVED_LABEL_PREFIX} are reserved",
                details={"names": reserved},
            )

    def _validate_isolation(self, tier: str | None, origin: str = "") -> None:
        available = list(self._settings.isolation_tiers())
        if tier is not None and tier not in available:
            raise Unprocessable(
                f"isolation '{tier}'{origin} is not available here; "
                f"available: {', '.join(available)}",
                details={"requested": tier, "available": available},
            )

    @staticmethod
    def _validate_minutes(*values: int | None) -> None:
        if any(value is not None and value < MIN_AUTO_MINUTES for value in values):
            raise Unprocessable(f"auto stop/delete minutes must be >= {MIN_AUTO_MINUTES}")
