"""``MountingLifecycle``: the ``Lifecycle`` whose driver spec carries the recorded volume mounts."""

import dataclasses
import json
import logging
from collections.abc import Mapping, Sequence

from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.base import IMAGE_MOUNTS_LABEL, SandboxSpec, VolumeBind
from sandfort.services.sandbox_jobs import Lifecycle
from sandfort.services.volumes import decode_mounts

# Kept as the name of ``sandboxes``: it is the ``logger`` field of every JSON log line.
logger = logging.getLogger("sandfort.services.sandboxes")


def with_image_mounts_label(labels: Mapping[str, str], paths: Sequence[str]) -> dict[str, str]:
    """``labels`` with the reserved image-mounts record set to ``paths`` (dropped when empty)."""
    rest = {name: value for name, value in labels.items() if name != IMAGE_MOUNTS_LABEL}
    if not paths:
        return rest
    return {**rest, IMAGE_MOUNTS_LABEL: json.dumps(sorted(paths))}


class MountingLifecycle(Lifecycle):
    """``Lifecycle`` whose driver spec carries the volume mounts recorded on the row.

    After a create it also records the image-declared volume paths the driver backed with
    scratch volumes (``InstanceInfo.image_mounts``) on the row, for the sandbox view.
    """

    async def drive_create(
        self, org_id: str, sandbox_id: str, actor_id: str | None = None
    ) -> Sandbox:
        sandbox = await super().drive_create(org_id, sandbox_id, actor_id)
        if sandbox.state is not SandboxState.STARTED or sandbox.driver_ref is None:
            return sandbox
        return await self._record_image_mounts(org_id, sandbox)

    async def _record_image_mounts(self, org_id: str, sandbox: Sandbox) -> Sandbox:
        """Best effort: the container is already running, so a failure here only logs."""
        assert sandbox.driver_ref is not None
        try:
            info = await self._driver.inspect(sandbox.driver_ref)
            labels = with_image_mounts_label(sandbox.labels, info.image_mounts)
            if labels == sandbox.labels:
                return sandbox
            async with self._uow_factory() as uow:
                current = await self.require(uow, org_id, sandbox.id)
                changes = {"labels": labels, "updated_at": self._clock.now()}
                saved = await uow.sandboxes.update(
                    org_id, current.model_copy(update=changes), expected_version=current.version
                )
                await uow.commit()
        except Exception:
            logger.warning("could not record image mounts of %s", sandbox.id, exc_info=True)
            return sandbox
        return saved

    @staticmethod
    def spec(sandbox: Sandbox) -> SandboxSpec:
        base = Lifecycle.spec(sandbox)
        mounts = decode_mounts(sandbox.labels)
        if not mounts:
            return base
        binds = tuple(
            VolumeBind(mount.provider_volume_name, mount.mount_path, read_only=mount.read_only)
            for mount in mounts
        )
        return dataclasses.replace(base, volumes=binds)
