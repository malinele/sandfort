"""The helper container of a volume export or restore: created, never started, always removed.

The Docker daemon reads and writes a container's mounts itself for ``docker cp`` (the archive
endpoints), and it does so for a container that was only created. The helper therefore never
runs: no process starts, no code of the image or of the archive executes, and the network mode
is ``none`` besides. It exists to give the daemon one stable path (``HELPER_MOUNT``) to read
from or extract into, with the named volume mounted there (read-only for an export; ``nocopy``
so the daemon never copies image content into the volume).

The image is the operator-configured utility image the egress probe already uses
(``Settings.egress_probe_image``, ``alpine:3.20`` by default); it is pulled when missing, and
nothing in it is read.

Labels follow the other transient containers (the egress canary, the snapshot export): not
``sandfort.managed``, no sandbox id, so the reconciler never takes the helper for an orphan
sandbox and removes it under a running transfer. Instead it carries ``HELPER_LABEL`` and its
creation time; a helper that outlived its process (a crash between create and remove) is found
by that label, its name (``HELPER_NAME_PREFIX``) and an old timestamp, and removed by the next
transfer once it is older than ``STALE_HELPER_S``; a container with a sandbox id, a managed label
or another name is never touched, whatever labels an image gave it.

A helper is never started, so its state and age cannot tell a live transfer from a dead one. The
only sound liveness source is in-process: ``helper_container`` counts the transfers in flight per
(client, volume). ``remove_orphan_helpers`` (run before a clear, a restore and a volume delete)
removes every helper that mounts the volume, whatever its age, unless this process has a transfer
of that volume in flight; ``prune_stale_helpers`` skips helpers of such volumes. The count cannot
see another process: run one API process per volume host (``docs/operations.md``).
"""

import asyncio
import contextlib
import logging
import time
import uuid
import weakref
from collections.abc import AsyncIterator
from typing import Any

import anyio

from sandfort.drivers.docker import images, volumes
from sandfort.drivers.docker.client import run_blocking, translate_errors
from sandfort.drivers.docker.hardening import NO_NEW_PRIVILEGES
from sandfort.drivers.docker.labels import LABEL_MANAGED, LABEL_SANDBOX_ID

logger = logging.getLogger(__name__)

HELPER_MOUNT = "/volume-data"
HELPER_LABEL = "sandfort.volume_transfer"
HELPER_LABEL_VALUE = "helper"
HELPER_NAME_PREFIX = "sf-vxfer-"  # a sandbox container is named sf-<sandbox id> (sf-sbx_...)
HELPER_STARTED_LABEL = "sandfort.volume_transfer.started"  # epoch seconds of the create
HELPER_FILTERS = {"label": [f"{HELPER_LABEL}={HELPER_LABEL_VALUE}"]}
HELPER_COMMAND = ["/bin/true"]  # create needs a command; the helper is never started
NO_NETWORK = "none"
STALE_HELPER_S = 6 * 60 * 60  # an export may stream for hours; a crashed one is older than this
REMOVE_DEADLINE_S = 30.0


def helper_volumes(ref: str, *, writable: bool) -> dict[str, dict[str, str]]:
    """The ``volumes`` argument of ``containers.create``: ``ref`` at ``HELPER_MOUNT``."""
    mode = "rw,nocopy" if writable else "ro,nocopy"
    return {ref: {"bind": HELPER_MOUNT, "mode": mode}}


async def _ensure_image(client: Any, image: str) -> None:
    if not await images.image_exists(client, image):
        logger.info("pulling the volume transfer helper image %s", image)
        await images.pull_image(client, image)


# Transfers of this process in flight: client -> {volume ref: count}. Weak on the client, so a
# dropped client takes its counts with it.
_IN_FLIGHT: weakref.WeakKeyDictionary[Any, dict[str, int]] = weakref.WeakKeyDictionary()


def _in_flight(client: Any, ref: str) -> int:
    return _IN_FLIGHT.get(client, {}).get(ref, 0)


def _register(client: Any, ref: str) -> None:
    counts = _IN_FLIGHT.setdefault(client, {})
    counts[ref] = counts.get(ref, 0) + 1


def _release(client: Any, ref: str) -> None:
    counts = _IN_FLIGHT.get(client)
    if counts is None:
        return
    remaining = counts.get(ref, 0) - 1
    if remaining > 0:
        counts[ref] = remaining
        return
    counts.pop(ref, None)
    if not counts:
        _IN_FLIGHT.pop(client, None)


def _is_helper(entry: Any) -> bool:
    """True when ``entry`` is a transfer helper by identity. A label alone proves nothing (an
    image can bake ``LABEL sandfort.volume_transfer=helper`` into a sandbox container), so the
    container must also carry the helper name, no sandbox id and no managed label. A malformed
    entry is no helper; this never raises."""
    if not isinstance(entry, dict):
        return False
    labels = entry.get("Labels")
    if not isinstance(labels, dict):
        labels = {}
    if LABEL_SANDBOX_ID in labels or labels.get(LABEL_MANAGED) == "true":
        return False
    names = entry.get("Names")
    if not isinstance(names, list):
        return False
    return any(str(name).lstrip("/").startswith(HELPER_NAME_PREFIX) for name in names)


def _mounted_refs(entry: Any) -> list[str]:
    """The names of the volumes ``entry`` mounts; a malformed entry mounts none."""
    mounts = entry.get("Mounts") if isinstance(entry, dict) else None
    if not isinstance(mounts, list):
        return []
    return [
        str(mount["Name"]) for mount in mounts if isinstance(mount, dict) and mount.get("Name")
    ]


def _mounts_volume(entry: Any, ref: str) -> bool:
    return ref in _mounted_refs(entry)


def _is_stale(entry: dict[str, Any], now: float) -> bool:
    """True for a helper of a crashed transfer: a helper by identity (``_is_helper``) and a
    readable old timestamp; a missing or garbled one never counts as stale."""
    if not _is_helper(entry):
        return False
    try:
        started = float(entry["Labels"].get(HELPER_STARTED_LABEL, ""))
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
    return now - started > STALE_HELPER_S


async def prune_stale_helpers(client: Any) -> None:
    """Remove helpers an earlier, interrupted transfer left behind; never raises. A helper of a
    volume this process has a transfer of in flight is kept, however old it looks (an export may
    stream for longer than ``STALE_HELPER_S``)."""
    try:
        listing = await run_blocking(client.api.containers, all=True, filters=HELPER_FILTERS)
        now = time.time()
        for entry in listing or []:
            if not _is_stale(entry, now):
                continue
            if any(_in_flight(client, ref) for ref in _mounted_refs(entry)):
                continue
            await remove_helper(client, str(entry["Id"]))
    except Exception:
        logger.warning("could not prune stale volume transfer helpers", exc_info=True)


async def remove_orphan_helpers(client: Any, ref: str) -> None:
    """Remove every helper that mounts volume ``ref``, whatever its age; never raises.

    Run before a clear, a restore or a delete of the volume: a helper left by a killed transfer
    makes the daemon refuse to remove the volume. Returns at once, without listing, while this
    process has a transfer of ``ref`` in flight: its helper stays, and the volume operation
    answers a conflict as it always did. The count is checked again before each removal, so a
    transfer that starts while the listing is read keeps its helper."""
    try:
        if _in_flight(client, ref):
            return
        listing = await run_blocking(client.api.containers, all=True, filters=HELPER_FILTERS)
        for entry in listing or []:
            if not (_is_helper(entry) and _mounts_volume(entry, ref)):
                continue
            if _in_flight(client, ref):
                return
            helper_id = str(entry["Id"])
            logger.warning(
                "removing orphan volume transfer helper %s left by an interrupted transfer of %s",
                helper_id,
                ref,
            )
            await remove_helper(client, helper_id)
    except Exception:
        logger.warning("could not sweep orphan volume transfer helpers of %s", ref, exc_info=True)


async def remove_helper(client: Any, container_id: str) -> None:
    """Force-remove the helper (never its volume); a failure is logged, not raised."""
    try:
        await asyncio.wait_for(
            run_blocking(client.api.remove_container, container_id, force=True, v=False),
            REMOVE_DEADLINE_S,
        )
    except Exception:
        logger.warning("could not remove volume transfer helper %s", container_id, exc_info=True)


async def _create_helper(client: Any, image: str, ref: str, writable: bool) -> str:
    with translate_errors(ref, "volume.helper"):
        created = await run_blocking(
            client.containers.create,
            image,
            HELPER_COMMAND,
            name=f"{HELPER_NAME_PREFIX}{uuid.uuid4().hex}",
            volumes=helper_volumes(ref, writable=writable),
            network_mode=NO_NETWORK,
            labels={
                HELPER_LABEL: HELPER_LABEL_VALUE,
                HELPER_STARTED_LABEL: str(int(time.time())),
            },
            cap_drop=["ALL"],
            security_opt=[NO_NEW_PRIVILEGES],
        )
    return str(created.id)


@contextlib.asynccontextmanager
async def helper_container(
    client: Any, image: str, ref: str, *, writable: bool
) -> AsyncIterator[str]:
    """A created, never started container with volume ``ref`` mounted at ``HELPER_MOUNT``.

    Yields its id and removes it on every exit, a cancellation included. ``DriverNotFound``
    when ``ref`` is not a platform volume, before anything is created.
    """
    try:
        # Counted before anything exists on the daemon, so a helper that is listed is always
        # already counted, and a created one can never escape the decrement below.
        _register(client, ref)
        await volumes.inspect_platform_volume(client, ref)
        await _ensure_image(client, image)
        await prune_stale_helpers(client)
        with anyio.CancelScope(shield=True):  # a created helper is always in hand to be removed
            container_id = await _create_helper(client, image, ref, writable)
        try:
            yield container_id
        finally:
            with anyio.CancelScope(shield=True):
                await remove_helper(client, container_id)
    finally:
        _release(client, ref)
