"""Image-declared volumes: platform-owned scratch volumes instead of anonymous ones.

An image may declare ``VOLUME`` paths (the image config ``Volumes`` map); a snapshot of a
sandbox with a mounted volume records its mount paths there too. For every declared path no
requested mount covers, the daemon would create an anonymous volume: writable storage outside
``disk_gib``, invisible to the API and untracked. Instead the driver creates a named volume per
path, carrying the managed label and the sandbox id, and mounts it read-write there.

The paths are recorded on the container under ``IMAGE_MOUNTS_LABEL`` so ``InstanceInfo``
reports them. Scratch volumes are removed after the container on every removal, by their
sandbox label, whether or not the container still exists; a failed or cancelled create removes
the ones it made. They show up in the managed volume listing, and the garbage collector removes
those whose sandbox row is gone.
"""

import asyncio
import contextlib
import json
import logging
import posixpath
from collections.abc import AsyncIterator, Mapping, Sequence
from typing import Any

from sandfort.drivers.base import IMAGE_MOUNTS_LABEL, SandboxSpec
from sandfort.drivers.docker.client import (
    clean_message,
    docker_errors,
    run_blocking,
    translate_errors,
)
from sandfort.drivers.docker.images import _pull as pull_reference
from sandfort.drivers.docker.images import invalid_reference, is_invalid_reference
from sandfort.drivers.docker.labels import (
    LABEL_MANAGED,
    LABEL_ORG_ID,
    LABEL_SANDBOX_ID,
    NAME_PREFIX,
)
from sandfort.drivers.docker.volumes import create_volume, remove_volume
from sandfort.drivers.errors import DriverConflict, DriverNotFound

logger = logging.getLogger(__name__)

# Not the user volume prefix (``sf-vol-``): the GC collects the two kinds by different rules.
IMAGE_MOUNT_VOLUME_PREFIX = "sf-imgvol-"
LABEL_IMAGE_MOUNT_PATH = "sandfort.image_mount_path"
SCRATCH_MODE = "rw"


def scratch_volume_name(sandbox_id: str, index: int) -> str:
    """Deterministic, so a retried create reuses the volume it made before."""
    return f"{IMAGE_MOUNT_VOLUME_PREFIX}{sandbox_id.lower()}-{index}"


def declared_paths(image_attrs: Mapping[str, Any]) -> list[str]:
    """The absolute volume paths an ``inspect_image`` payload declares, normalised and sorted."""
    config = image_attrs.get("Config") or {}
    declared = config.get("Volumes") or {}
    paths = {posixpath.normpath(str(key)) for key in declared if str(key).startswith("/")}
    return sorted(paths)


def _covers(mount_path: str, declared: str) -> bool:
    mount = posixpath.normpath(mount_path)
    return mount == declared or declared.startswith(mount.rstrip("/") + "/")


def uncovered_paths(declared: Sequence[str], mount_paths: Sequence[str]) -> list[str]:
    """``declared`` paths that no requested mount equals or is a parent of."""
    return [path for path in declared if not any(_covers(mount, path) for mount in mount_paths)]


async def image_volume_paths(client: Any, image: str) -> list[str]:
    """The volume paths ``image`` declares; a missing image is pulled first.

    A client without image inspection (a minimal test double) declares nothing.
    """
    inspect = getattr(getattr(client, "api", None), "inspect_image", None)
    if inspect is None:
        return []
    errors = docker_errors()
    try:
        try:
            attrs = await run_blocking(inspect, image)
        except errors.NotFound:
            await pull_reference(client, image)
            attrs = await run_blocking(inspect, image)
    except errors.APIError as exc:
        message = clean_message(exc)
        if is_invalid_reference(message):
            raise invalid_reference(image, message) from exc
        raise
    return declared_paths(attrs)


async def _ensure_scratch_volume(client: Any, name: str, labels: Mapping[str, str]) -> None:
    """Create the scratch volume, or reuse it: the name is per sandbox, not per container.

    A recreate (resize) and a retried create find the volume from before; a conflict answer
    for an existing name is reuse, not an error.
    """
    try:
        await create_volume(client, name, labels=labels)
    except DriverConflict:
        logger.debug("scratch volume %s exists; reusing it", name)


async def with_scratch_volumes(
    client: Any, spec: SandboxSpec, kwargs: Mapping[str, Any]
) -> dict[str, Any]:
    """``kwargs`` for ``containers.create`` plus a scratch volume per uncovered declared path."""
    declared = await image_volume_paths(client, spec.image)
    paths = uncovered_paths(declared, [bind.mount_path for bind in spec.volumes])
    labels = {key: value for key, value in kwargs["labels"].items() if key != IMAGE_MOUNTS_LABEL}
    result = {**kwargs, "labels": labels}
    if not paths:
        return result
    mounts: dict[str, dict[str, str]] = dict(kwargs.get("volumes") or {})
    for index, path in enumerate(paths):
        name = scratch_volume_name(spec.sandbox_id, index)
        scratch_labels = {
            LABEL_SANDBOX_ID: spec.sandbox_id,
            LABEL_ORG_ID: spec.org_id,
            LABEL_IMAGE_MOUNT_PATH: path,
        }
        await _ensure_scratch_volume(client, name, scratch_labels)
        mounts[name] = {"bind": path, "mode": SCRATCH_MODE}
    labels[IMAGE_MOUNTS_LABEL] = json.dumps(paths)
    result["volumes"] = mounts
    return result


def scratch_identity(name: str, labels: Mapping[str, str]) -> tuple[str, str] | None:
    """``(org id, sandbox id)`` of a scratch volume; ``None`` for any other volume.

    A scratch volume carries the scratch name prefix, the managed label and the scratch path
    label; the garbage collector selects by exactly this.
    """
    if not name.startswith(IMAGE_MOUNT_VOLUME_PREFIX) or LABEL_IMAGE_MOUNT_PATH not in labels:
        return None
    org_id, sandbox_id = labels.get(LABEL_ORG_ID), labels.get(LABEL_SANDBOX_ID)
    if labels.get(LABEL_MANAGED) != "true" or not org_id or not sandbox_id:
        return None
    return org_id, sandbox_id


def _sandbox_id_from_name(ref: str) -> str | None:
    """``sbx_x`` for the container name form ``sf-sbx_x``; a container id names no sandbox."""
    name = ref.lstrip("/")
    if not name.startswith(NAME_PREFIX):
        return None
    return name.removeprefix(NAME_PREFIX) or None


async def scratch_owner(client: Any, ref: str) -> str | None:
    """The sandbox id whose scratch volumes go with container ``ref``.

    Read from the container's sandbox label; when the container is already gone, taken from a
    name-form ``ref``. A gone container referenced by id names nobody: the GC collects those.
    """
    try:
        with translate_errors(ref, "container.inspect"):
            attrs = await run_blocking(client.api.inspect_container, ref)
    except DriverNotFound:
        return _sandbox_id_from_name(ref)
    labels = (attrs.get("Config") or {}).get("Labels") or {}
    return str(labels.get(LABEL_SANDBOX_ID) or "") or None


async def _list_scratch_volumes(client: Any, sandbox_id: str) -> list[str]:
    selectors = [
        f"{LABEL_MANAGED}=true",
        f"{LABEL_SANDBOX_ID}={sandbox_id}",
        LABEL_IMAGE_MOUNT_PATH,
    ]
    with translate_errors(sandbox_id, "volume.list"):
        listing = await run_blocking(client.api.volumes, filters={"label": selectors})
    names = [str(entry["Name"]) for entry in (listing or {}).get("Volumes") or []]
    return [name for name in names if name.startswith(IMAGE_MOUNT_VOLUME_PREFIX)]


async def remove_scratch_volumes(client: Any, sandbox_id: str) -> None:
    """Remove every scratch volume labelled with ``sandbox_id``; never raises.

    A missing volume is fine. Any other failure is logged and the next volume is tried; the
    garbage collector removes what is left once the sandbox row is gone.
    """
    try:
        names = await _list_scratch_volumes(client, sandbox_id)
    except Exception:
        logger.warning("could not list scratch volumes of %s", sandbox_id, exc_info=True)
        return
    for name in names:
        try:
            await remove_volume(client, name)
        except DriverNotFound:
            continue
        except Exception:
            logger.warning("could not remove scratch volume %s", name, exc_info=True)


async def _discard_shielded(client: Any, sandbox_id: str) -> bool:
    """Run the removal to its end even when the caller is cancelled again meanwhile.

    Returns ``True`` when the caller was cancelled while waiting; the removal then continues
    in the background.
    """
    cleanup = asyncio.ensure_future(remove_scratch_volumes(client, sandbox_id))
    try:
        await asyncio.shield(cleanup)
    except asyncio.CancelledError:
        logger.warning("scratch cleanup of %s continues in the background", sandbox_id)
        return True
    return False


@contextlib.asynccontextmanager
async def scratch_cleanup_on_failure(client: Any, sandbox_id: str) -> AsyncIterator[None]:
    """Remove the scratch volumes of ``sandbox_id`` when the body raises or is cancelled.

    Wraps scratch creation plus container creation, so a failure past the first scratch volume
    or a cancellation (a client disconnect during a pull) leaks nothing. Re-raises; when the
    task is cancelled again during the cleanup, the cancellation is what propagates and the
    original error is logged once.
    """
    try:
        yield
    except BaseException as exc:
        cancelled = await _discard_shielded(client, sandbox_id)
        if cancelled and not isinstance(exc, asyncio.CancelledError):
            logger.warning("create of %s failed: %r", sandbox_id, exc, exc_info=exc)
            raise asyncio.CancelledError from exc
        raise
