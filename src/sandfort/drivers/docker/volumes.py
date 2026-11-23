"""Docker ``NamedVolumeDriver`` operations (WP 3.4).

Volumes are local named volumes carrying the managed label like containers do; a docker
volume's name is its reference. ``inspect_volume`` reports a size only when docker already
knows it: the inspect payload's ``UsageData`` or, failing that, the disk usage api (``df``),
where ``-1`` means "not computed". A failed ``df`` leaves the size out rather than failing
the inspect. The disk usage call (``df``) walks every volume on the daemon, so it runs through
``run_bulk`` (bulk lane); every other docker-py call runs through ``run_blocking``.
"""

import asyncio
import logging
from collections.abc import Mapping
from typing import Any

from sandfort.drivers.base import VolumeInfo
from sandfort.drivers.docker.client import run_blocking, translate_errors
from sandfort.drivers.docker.labels import LABEL_MANAGED
from sandfort.drivers.docker.lanes import run_bulk
from sandfort.drivers.errors import DriverError, DriverNotFound

logger = logging.getLogger(__name__)

LOCAL_DRIVER = "local"
UNKNOWN_SIZE = -1
RECREATE_ATTEMPTS = 3  # creating the volume again after its removal
RECREATE_RETRY_S = 0.25


def _require_client(client: Any, operation: str) -> None:
    """Refuse to run without a daemon client (the seed suite still probes with ``None``)."""
    if client is None:
        raise NotImplementedError(f"{operation} needs a docker client (volumes work package)")


def _labels(attrs: Mapping[str, Any]) -> dict[str, str]:
    return {str(key): str(value) for key, value in (attrs.get("Labels") or {}).items()}


def _usage_size(usage: Any) -> int | None:
    if not isinstance(usage, Mapping):
        return None
    size = usage.get("Size")
    if isinstance(size, int) and size > UNKNOWN_SIZE:
        return size
    return None


async def _disk_usage_size(client: Any, name: str) -> int | None:
    """The size docker's disk usage api reports for ``name``; ``None`` when it has none."""
    try:
        with translate_errors(name, "volume.usage"):
            usage = await run_bulk(client.api.df)
    except DriverError:
        return None
    for entry in usage.get("Volumes") or []:
        if isinstance(entry, Mapping) and entry.get("Name") == name:
            return _usage_size(entry.get("UsageData"))
    return None


async def create_volume(client: Any, name: str, *, labels: Mapping[str, str]) -> VolumeInfo:
    _require_client(client, "create_volume")
    merged = {**labels, LABEL_MANAGED: "true"}
    with translate_errors(name, "volume.create"):
        attrs = await run_blocking(
            client.api.create_volume, name=name, driver=LOCAL_DRIVER, labels=merged
        )
    volume_name = str(attrs.get("Name") or name)
    return VolumeInfo(ref=volume_name, name=volume_name, labels=_labels(attrs))


async def remove_volume(client: Any, ref: str) -> None:
    """Remove ``ref``; docker answers 409 (``DriverConflict``) while a container uses it."""
    _require_client(client, "remove_volume")
    with translate_errors(ref, "volume.remove"):
        await run_blocking(client.api.remove_volume, ref)


async def inspect_volume(client: Any, ref: str) -> Mapping[str, Any]:
    _require_client(client, "inspect_volume")
    with translate_errors(ref, "volume.inspect"):
        attrs = await run_blocking(client.api.inspect_volume, ref)
    name = str(attrs.get("Name") or ref)
    result: dict[str, Any] = {"name": name, "ref": name, "labels": _labels(attrs)}
    size = _usage_size(attrs.get("UsageData"))
    if size is None:
        size = await _disk_usage_size(client, name)
    if size is not None:
        result["size_bytes"] = size
    return result


async def inspect_platform_volume(client: Any, ref: str) -> Mapping[str, Any]:
    """The raw inspect payload of ``ref``; ``DriverNotFound`` unless it is a platform volume.

    Volume transfer mounts the volume into a helper container, so it first makes sure ``ref``
    exists (creating a container with a missing named volume would create that volume) and
    carries the managed label (a volume of the host or of another tool is never mounted).
    """
    _require_client(client, "inspect_volume")
    with translate_errors(ref, "volume.inspect"):
        attrs = await run_blocking(client.api.inspect_volume, ref)
    if _labels(attrs).get(LABEL_MANAGED) != "true":
        raise DriverNotFound(f"volume {ref} does not exist", ref=ref)
    return dict(attrs)


async def recreate_volume(client: Any, ref: str) -> None:
    """Empty ``ref`` by removing it and creating it again: same name, driver, options, labels.

    No code runs and no file is touched, so the result is a volume that is empty by construction.
    The removal is refused (``DriverConflict``) while any container, even a stopped one, still
    references the volume; nothing has changed then. Between the removal and the creation the
    name is free: the creation is retried ``RECREATE_ATTEMPTS`` times and, should it never
    succeed, the error is raised and logged (the volume is gone; its row is repaired by the
    next create that names it).
    """
    attrs = await inspect_platform_volume(client, ref)
    driver = str(attrs.get("Driver") or LOCAL_DRIVER)
    options = {str(key): str(value) for key, value in (attrs.get("Options") or {}).items()}
    labels = _labels(attrs)
    await remove_volume(client, ref)
    for attempt in range(1, RECREATE_ATTEMPTS + 1):
        try:
            with translate_errors(ref, "volume.create"):
                await run_blocking(
                    client.api.create_volume,
                    name=ref,
                    driver=driver,
                    driver_opts=options or None,
                    labels=labels,
                )
            return
        except DriverError:
            if attempt == RECREATE_ATTEMPTS:
                logger.error("volume %s was removed but could not be created again", ref)
                raise
            await asyncio.sleep(RECREATE_RETRY_S)
