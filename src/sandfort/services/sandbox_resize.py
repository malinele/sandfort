"""The resize recreate of a stopped sandbox's container, a mixin of ``SandboxService``."""

import dataclasses
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from sandfort.config import FAULT_RESIZE_COMMIT_FAIL, FAULT_RESIZE_CREATE_FAIL
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.base import (
    RESIZE_IMAGE_LABEL,
    ImageRegistryDriver,
    InstanceInfo,
    resize_image_reference,
)
from sandfort.drivers.errors import DriverError, DriverNotFound, DriverUnsupported
from sandfort.errors import InternalError
from sandfort.services.sandbox_mounting import MountingLifecycle
from sandfort.services.sandbox_service_base import SandboxServiceBase

# Kept as the name of ``sandboxes``: it is the ``logger`` field of every JSON log line.
logger = logging.getLogger("sandfort.services.sandboxes")

RESIZE_FAILED_MESSAGE = (
    "resize could not prepare the sandbox's container; try again or contact the operator"
)

_S = SandboxState


class SandboxResizeMixin(SandboxServiceBase):
    """Replace a stopped sandbox's container when a resize changed its resources."""

    async def _recreate_if_resized(self, org_id: str, sandbox_id: str) -> None:
        """Replace a stopped sandbox's container when its resources no longer match the row.

        A resize only changes the row; the container (adopted by its deterministic name
        otherwise) is replaced here, before the start intent. The root filesystem is kept: the
        stopped container is committed to the local image ``sf-resize-<id>`` and the new
        container is created from it. The tag stays while the sandbox lives (the new container is
        based on it, and on classic overlay2 removing it would delete the image under that
        container); the next resize commits to the same tag and the driver removes the tag with
        the sandbox. No transaction is open during the driver calls. A failing commit or create
        is an internal error, never a 404 for a sandbox that exists; the row stays as it was.
        A create that fails after the destroy keeps the image (the only copy of the files); a
        later start finds no container but the image, and creates the container from it.
        """
        sandbox = await self._load(org_id, sandbox_id)
        if sandbox.state is not _S.STOPPED or sandbox.driver_ref is None:
            return
        try:
            existing = await self._driver.inspect(sandbox.driver_ref)
        except DriverNotFound:
            # No container. With the sandbox's resize image the replace died between its destroy
            # and its create, and the data lives in that image: create from it. Without one a
            # vanished container is reported by the start itself.
            if not await self._resize_image_exists(sandbox.id):
                return
            created = await self._guarded(sandbox_id, self._create_from_resize_image, sandbox)
        else:
            if existing.resources == sandbox.resources:
                return
            created = await self._guarded(
                sandbox_id, self._replace_container, sandbox, sandbox.driver_ref
            )
        if created.ref == sandbox.driver_ref:
            return
        async with self._uow_factory() as uow:
            current = await self._core.require(uow, org_id, sandbox_id)
            changes = {"driver_ref": created.ref, "updated_at": self._clock.now()}
            await uow.sandboxes.update(
                org_id, current.model_copy(update=changes), expected_version=current.version
            )
            await uow.commit()

    @staticmethod
    async def _guarded(
        sandbox_id: str, step: Callable[..., Awaitable[InstanceInfo]], *args: Any
    ) -> InstanceInfo:
        """Run a replace step; a driver failure is an internal error, never a 404 or a leak."""
        try:
            return await step(*args)
        except DriverUnsupported:
            raise
        except DriverError as exc:
            logger.exception("resize of %s could not replace its container", sandbox_id)
            raise InternalError(RESIZE_FAILED_MESSAGE) from exc

    async def _replace_container(self, sandbox: Sandbox, old_ref: str) -> InstanceInfo:
        """Commit ``old_ref``, destroy it and create the new container from the committed image."""
        images = self._driver
        if not isinstance(images, ImageRegistryDriver):
            raise DriverUnsupported(
                f"driver {self._driver.name} cannot commit a container, so a resize "
                "could not keep its files"
            )
        faults = self._settings.fault_injection
        if FAULT_RESIZE_COMMIT_FAIL in faults:  # instead of the commit: nothing is touched
            raise DriverError(f"injected fault: {FAULT_RESIZE_COMMIT_FAIL}", ref=old_ref)
        image = resize_image_reference(sandbox.id)
        previous = await self._resize_image_id(image)
        committed = await images.commit_container(old_ref, image, labels={RESIZE_IMAGE_LABEL: "1"})
        try:
            # Scratch volumes belong to the sandbox id, not to this container: keep them, so the
            # new container mounts the same ones (image-declared data survives the resize).
            await self._driver.destroy(old_ref, remove_volumes=False)
        except Exception:
            await self._discard_resize_image(images, image)  # the old container lives on
            raise
        try:
            created = await self._create_from_resize_image(sandbox)
        except Exception:
            # The old container is gone: the committed image is now the only copy of the
            # sandbox's files. Keep it; the next start creates the container from it.
            logger.warning(
                "resize of %s lost its container: the sandbox's data lives in the image %s "
                "until the next successful start",
                sandbox.id,
                image,
            )
            raise
        if previous is not None and previous != committed.digest:
            await self._discard_resize_image(images, previous)  # the image the tag moved off
        return created

    async def _create_from_resize_image(self, sandbox: Sandbox) -> InstanceInfo:
        """Create the sandbox's container from its resize image with the row's resources."""
        if FAULT_RESIZE_CREATE_FAIL in self._settings.fault_injection:  # instead of the create
            raise DriverError(f"injected fault: {FAULT_RESIZE_CREATE_FAIL}", ref=sandbox.id)
        image = resize_image_reference(sandbox.id)
        spec = dataclasses.replace(MountingLifecycle.spec(sandbox), image=image)
        return await self._driver.create(spec)

    async def _resize_image_exists(self, sandbox_id: str) -> bool:
        """True when the sandbox's resize image is present; a driver that cannot say, or fails."""
        images = self._driver
        if not isinstance(images, ImageRegistryDriver):
            return False
        try:
            return await images.image_exists(resize_image_reference(sandbox_id))
        except Exception:
            logger.warning("could not look for the resize image of %s", sandbox_id, exc_info=True)
            return False

    async def _resize_image_id(self, image: str) -> str | None:
        """The id the resize tag points at now (a resize before this one), else ``None``."""
        try:
            return (await self._driver.inspect_image(image)).digest
        except DriverNotFound:
            return None
        except Exception:
            logger.debug("could not inspect the resize image %s", image, exc_info=True)
            return None

    @staticmethod
    async def _discard_resize_image(images: ImageRegistryDriver, image: str) -> None:
        """Best effort: remove a resize image by tag or id (forced; failure only logs)."""
        try:
            await images.remove_image(image, force=True)
        except Exception:
            logger.debug("could not remove the resize image %s", image, exc_info=True)
