"""Volume orchestration: create, get/list with size sampling, delete guarded by mounts.

Driver calls never run inside an open transaction (intent first, then act, architecture D4).
Creating persists the row first, then creates the provider volume; when the provider refuses,
the row is removed again and the failure is audited. Reads refresh ``sampled_size_bytes``
from the driver's inspect when it reports a size cheaply; a failed inspect never fails a read.
Deleting refuses while any non-deleted sandbox in the org records a mount of the volume,
otherwise marks the row ``deleting``, removes the provider volume best-effort and deletes it.

Sandbox mounts live in the sandbox row's labels under the reserved ``MOUNTS_LABEL`` key (a
JSON list), so they need no table of their own. User labels may not use the reserved
``sandfort.`` prefix; ``user_labels`` strips reserved keys before labels leave the service.

Volumes carry user labels. A label-scoped key creating a volume gets its scope merged into
the labels, and its list, get and delete reach only volumes carrying the scope (any other is
not found). The in-use scan on delete reads the unscoped sandbox view, so a sandbox outside
the scope still blocks the delete. A list filter key outside ``LABEL_FILTER_KEY`` is a 422.

Mount access on sandbox create: a read-only mount needs ``volumes:read`` and a read-write one
``volumes:write`` (``mount_scopes``). A label-scoped key may mount only a volume whose labels
contain its scope (``resolve_mounts``); any other volume, missing ones included, is a 403
naming the volume. A key with ``shared_volume_labels`` may also list, get and mount read-only
the volumes whose labels contain them (a read-write mount of one is a 403 naming the rule);
delete reaches only the key's own scope.

Size limit (``SANDFORT_VOLUME_MAX_BYTES``, ``services.volume_limit``): the limit is checked when
a read-write mount is made (create, start, and the resize recreate inside start). The sandbox
service first samples the requested read-write volumes through ``VolumeService.guard`` (before
its unit of work opens, as driver calls never run inside a transaction, and after the cheap
refusals); ``resolve_mounts`` then refuses, from those sizes and without the driver, a
read-write mount of a volume whose size exceeds the limit (422 ``VOLUME_OVER_LIMIT``); a
read-only mount is allowed. Running sandboxes are not stopped; the next release may add a stop
cause for that. The limit and the sampling interval are constructor arguments of the service,
and every volume the service returns carries that limit (``LimitedVolume``) for the response.
"""

import json
import logging
import posixpath
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sandfort.auth.label_scope import (
    current_label_scope,
    current_shared_volume_labels,
    matches,
)
from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType, AuditOutcome
from sandfort.domain.org import Scope
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.domain.volume import Volume, VolumeState
from sandfort.drivers.base import NamedVolumeDriver, SandboxDriver
from sandfort.drivers.errors import DriverError, DriverUnsupported
from sandfort.errors import IN_USE, Conflict, Forbidden, NotFound, Unprocessable
from sandfort.ids import new_volume_id
from sandfort.services.audit import AuditRecorder
from sandfort.services.label_scope import (
    contradicts,
    merge_scope,
    mount_refusal,
    shared_delete_refusal,
    shared_publish_refusal,
    shared_transfer_refusal,
    shared_write_refusal,
    unscoped,
)
from sandfort.services.volume_limit import (
    DEFAULT_SAMPLE_INTERVAL_S,
    NO_LIMIT,
    MountGuard,
    MountLimit,
    with_reported_limit,
)

logger = logging.getLogger(__name__)

TARGET_TYPE = "volume"
RESTORE_ACTION = "volume.restore"
RESTORE_UNRECOVERED = "restore_unrecovered"
PROVIDER_PREFIX = "sf-vol-"
RESERVED_LABEL_PREFIX = "sandfort."
MOUNTS_LABEL = f"{RESERVED_LABEL_PREFIX}volume_mounts"
# Transient carrier for requested mounts from the create schema to the service (the route
# copies request fields one by one); the service takes it out before anything is stored.
MOUNT_REQUESTS_LABEL = f"{RESERVED_LABEL_PREFIX}mount_requests"
ORG_ID_LABEL = f"{RESERVED_LABEL_PREFIX}org_id"
VOLUME_ID_LABEL = f"{RESERVED_LABEL_PREFIX}volume_id"
MOUNT_SCAN_PAGE = 200
MAX_MOUNTS = 16
MAX_MOUNT_PATH_LENGTH = 255
# Kernel and runtime trees a volume must never shadow.
FORBIDDEN_MOUNT_ROOTS = ("/proc", "/sys", "/dev")


@dataclass(frozen=True, slots=True)
class MountRequest:
    """A caller's ask: mount ``volume_id`` at the absolute ``mount_path``."""

    volume_id: str
    mount_path: str
    read_only: bool = False


@dataclass(frozen=True, slots=True)
class VolumeMount:
    """A resolved mount as recorded on the sandbox row."""

    volume_id: str
    provider_volume_name: str
    mount_path: str
    read_only: bool = False


def provider_volume_name(volume_id: str) -> str:
    """The deterministic driver-side name of a volume."""
    return f"{PROVIDER_PREFIX}{volume_id.lower()}"


def is_reserved_label(name: str) -> bool:
    return name.startswith(RESERVED_LABEL_PREFIX)


def user_labels(labels: Mapping[str, str]) -> dict[str, str]:
    """``labels`` without the platform's reserved keys."""
    return {name: value for name, value in labels.items() if not is_reserved_label(name)}


def encode_mounts(mounts: Sequence[VolumeMount]) -> dict[str, str]:
    """The reserved label recording ``mounts``; empty when there are none."""
    if not mounts:
        return {}
    items = [
        {
            "volume_id": mount.volume_id,
            "provider_volume_name": mount.provider_volume_name,
            "mount_path": mount.mount_path,
            **_mode_entry(mount.read_only),
        }
        for mount in mounts
    ]
    return {MOUNTS_LABEL: json.dumps(items, separators=(",", ":"))}


def _mode_entry(read_only: bool) -> dict[str, bool]:
    """The ``read_only`` record entry; omitted for read-write, the default and old format."""
    return {"read_only": True} if read_only else {}


def decode_mounts(labels: Mapping[str, str]) -> tuple[VolumeMount, ...]:
    """The mounts recorded on a sandbox's labels; a corrupt record is logged and ignored."""
    raw = labels.get(MOUNTS_LABEL)
    if raw is None:
        return ()
    try:
        items: Any = json.loads(raw)
        return tuple(
            VolumeMount(
                volume_id=str(item["volume_id"]),
                provider_volume_name=str(item["provider_volume_name"]),
                mount_path=str(item["mount_path"]),
                read_only=item.get("read_only") is True,
            )
            for item in items
        )
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        logger.error("unreadable volume mount record %r: %s", raw, exc)
        return ()


def encode_mount_requests(requests: Sequence[MountRequest]) -> dict[str, str]:
    """The transient label carrying ``requests``; empty when there are none."""
    if not requests:
        return {}
    items = [
        {"volume_id": item.volume_id, "mount_path": item.mount_path, **_mode_entry(item.read_only)}
        for item in requests
    ]
    return {MOUNT_REQUESTS_LABEL: json.dumps(items, separators=(",", ":"))}


def take_mount_requests(
    labels: Mapping[str, str],
) -> tuple[dict[str, str], tuple[MountRequest, ...]]:
    """Split the transient mount requests off ``labels``; a malformed carrier is rejected."""
    remaining = {name: value for name, value in labels.items() if name != MOUNT_REQUESTS_LABEL}
    raw = labels.get(MOUNT_REQUESTS_LABEL)
    if raw is None:
        return remaining, ()
    try:
        items: Any = json.loads(raw)
        requests = tuple(
            MountRequest(
                volume_id=str(item["volume_id"]),
                mount_path=str(item["mount_path"]),
                read_only=item.get("read_only") is True,
            )
            for item in items
        )
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise Unprocessable("malformed volume mount requests") from exc
    return remaining, requests


def _mount_path_problem(path: str) -> str | None:
    if len(path) > MAX_MOUNT_PATH_LENGTH:
        return f"is longer than {MAX_MOUNT_PATH_LENGTH} characters"
    if not path.startswith("/") or "\0" in path:
        return "must be an absolute path"
    if posixpath.normpath(path) != path or path.startswith("//"):
        return "must be normalized (no '.', '..', '//' or trailing '/')"
    if path == "/":
        return "cannot be the filesystem root"
    if any(path == root or path.startswith(root + "/") for root in FORBIDDEN_MOUNT_ROOTS):
        return "cannot be inside /proc, /sys or /dev"
    return None


def validate_mount_requests(requests: Sequence[MountRequest]) -> None:
    """Shape checks needing no database: count, absolute normalized paths, no duplicates."""
    if len(requests) > MAX_MOUNTS:
        raise Unprocessable(f"at most {MAX_MOUNTS} volume mounts are allowed")
    for request in requests:
        problem = _mount_path_problem(request.mount_path)
        if problem is not None:
            raise Unprocessable(
                f"mount path {request.mount_path!r} {problem}",
                details={"mount_path": request.mount_path},
            )
    paths = [request.mount_path for request in requests]
    duplicates = sorted({path for path in paths if paths.count(path) > 1})
    if duplicates:
        raise Unprocessable("duplicate volume mount paths", details={"mount_paths": duplicates})


def mount_scopes(requests: Sequence[MountRequest]) -> frozenset[Scope]:
    """The key scopes a create needs to mount ``requests``; none when nothing is mounted.

    A read-only mount needs ``volumes:read`` and a read-write one ``volumes:write``; a create
    mixing both modes needs both.
    """
    return frozenset(
        Scope.VOLUMES_READ if request.read_only else Scope.VOLUMES_WRITE for request in requests
    )


def refuse_label_scoped_mounts(
    requests: Sequence[MountRequest], scope: Mapping[str, str] | None
) -> None:
    """Refuse any mount requested under a label scope (``Forbidden``), whatever the volume.

    The all-or-nothing check from before volumes carried labels. The create path no longer
    uses it: ``resolve_mounts`` decides per volume by its labels. Unscoped keys (``scope`` is
    ``None``) pass unchanged.
    """
    if scope is None or not requests:
        return
    pairs = ",".join(f"{name}={value}" for name, value in sorted(scope.items()))
    raise Forbidden(
        f"this API key is limited to sandboxes labelled {pairs} and cannot mount volumes "
        "(whatever their labels)",
        details={"volume_ids": sorted({request.volume_id for request in requests})},
    )


async def resolve_mounts(
    uow: UnitOfWorkPort,
    org_id: str,
    requests: Sequence[MountRequest],
    *,
    limit: MountLimit | None = None,
) -> tuple[VolumeMount, ...]:
    """Resolve each volume id in ``org_id``; foreign, missing or deleting ones are not found.

    Under a label scope a volume must carry the scope labels; a volume that does not, and a
    missing one, are refused alike (``Forbidden`` naming the volume), so the answer never
    reveals whether a volume id exists. A deleting volume that does match is not found.

    ``limit`` (from ``MountGuard.prepare``, taken before the unit of work opened) carries the
    sizes a read-write mount is judged by; this function never calls the driver.
    """
    scope = current_label_scope()
    resolved: list[VolumeMount] = []
    for request in requests:
        volume = await uow.volumes.get(org_id, request.volume_id)
        if scope is not None and (volume is None or not matches(volume.labels, scope)):
            shared = current_shared_volume_labels()
            if volume is None or shared is None or not matches(volume.labels, shared):
                raise mount_refusal(scope, request.volume_id)
            if not request.read_only:
                raise shared_write_refusal(shared, request.volume_id)
        if volume is None or volume.state is not VolumeState.READY:
            raise NotFound(f"volume {request.volume_id} not found")
        if volume.restoring_since is not None:
            raise unrecovered_restore_conflict(volume.id)
        if limit is not None and not request.read_only:  # soft size limit, see volume_limit
            limit.check_read_write(volume)
        resolved.append(
            VolumeMount(
                volume.id, volume.provider_volume_name, request.mount_path, request.read_only
            )
        )
    return tuple(resolved)


class VolumeService:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        driver: SandboxDriver,
        clock: Clock,
        audit: AuditRecorder | None = None,
        *,
        max_bytes: int = NO_LIMIT,
        sample_interval_s: int = DEFAULT_SAMPLE_INTERVAL_S,
    ) -> None:
        self._uow_factory = uow_factory
        self._driver = driver
        self._clock = clock
        self._audit = audit or AuditRecorder(clock)
        self._guard = MountGuard(max_bytes, sample_interval_s, clock, self._inspect)

    @property
    def guard(self) -> MountGuard:
        """This service's own mount guard (the sandbox service samples through it)."""
        return self._guard

    @property
    def max_bytes(self) -> int | None:
        """The size limit this service enforces; ``None`` when there is none."""
        return self._guard.max_bytes

    # -- hooks for export and restore (``services.volume_transfer``) -------------

    async def authorize_transfer(self, org_id: str, volume_id: str, verb: str) -> Volume:
        """The volume when the key owns it through its labels, else 404 (unseen) or 403 (shared).

        ``verb`` (``exported`` or ``restored``) words the shared-labels refusal. Runs in its own
        short unit of work, so the driver is only called after it is closed.
        """
        async with self._uow_factory() as uow:
            volume = await self._require(uow, org_id, volume_id, shared=True)
        if not matches(volume.labels, current_label_scope()):
            raise shared_transfer_refusal(current_shared_volume_labels() or {}, volume_id, verb)
        return volume

    async def refuse_if_mounted(self, org_id: str, volume_id: str) -> None:
        """409 ``in_use`` while any non-destroyed sandbox of the org mounts the volume."""
        async with self._uow_factory() as uow:
            users = await mounting_sandboxes(uow, org_id, volume_id)
        if users:
            raise in_use_conflict(volume_id, users)

    async def record_transfer(
        self,
        volume: Volume,
        actor_id: str | None,
        action: str,
        details: Mapping[str, Any],
        *,
        ok: bool = True,
    ) -> None:
        """One audit row for ``volume`` in its own unit of work."""
        async with self._uow_factory() as uow:
            await self._record(uow, volume, actor_id, action, details, ok=ok)
            await uow.commit()

    async def mark_restoring(self, volume: Volume) -> None:
        """Commit the restore marker (now) on ``volume``: a restore is about to extract."""
        await self._set_marker(volume, self._clock.now())

    async def clear_restoring(self, volume: Volume) -> None:
        """Commit the end of the restore: the marker is NULL again."""
        await self._set_marker(volume, None)

    async def restoring_volumes(self) -> Sequence[Volume]:
        """Every volume of every org that still carries a restore marker (start-up recovery)."""
        async with self._uow_factory() as uow:
            return await uow.volumes.list_restoring()

    async def finish_recovery(self, volume: Volume, details: Mapping[str, Any]) -> bool:
        """Clear the marker the scan observed and write the recovery's audit row
        (``volume.restore``, an error outcome, actor ``system``) in one unit of work, so neither
        exists without the other.

        The marker is cleared only where it still equals ``volume.restoring_since``; when it
        changed (a newer restore re-marked the volume) nothing is written and ``False`` returns.
        """
        observed = volume.restoring_since
        async with self._uow_factory() as uow:
            if observed is None or not await uow.volumes.clear_restoring_if(
                volume.org_id, volume.id, observed
            ):
                logger.warning(
                    "volume %s: the restore marker changed during recovery (a newer restore "
                    "marked it); the marker and the audit row are left alone",
                    volume.id,
                )
                return False
            await self._record(
                uow,
                volume,
                None,
                RESTORE_ACTION,
                details,
                ok=False,
                actor_type=ActorType.SYSTEM,
            )
            await uow.commit()
        return True

    async def _set_marker(self, volume: Volume, since: datetime | None) -> None:
        async with self._uow_factory() as uow:
            await uow.volumes.set_restoring_since(volume.org_id, volume.id, since)
            await uow.commit()

    # -- queries ---------------------------------------------------------------

    async def get(self, org_id: str, volume_id: str) -> Volume:
        async with self._uow_factory() as uow:
            volume = await self._require(uow, org_id, volume_id, shared=True)
        return self._shown(await self._refresh(volume))

    async def list(
        self,
        org_id: str,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Sequence[Volume]:
        """Volumes carrying every requested label and, for a label-scoped key, its scope.

        A key with ``shared_volume_labels`` also gets the volumes carrying those, merged in id
        order (each query is id-ordered, so the first ``limit`` of the union are exact).
        """
        wanted = dict(labels or {})
        filters = _list_filters(wanted, current_label_scope(), current_shared_volume_labels())
        async with self._uow_factory() as uow:
            found: dict[str, Volume] = {}
            for rule_filter in filters:
                rows = await _list_matching(uow, org_id, rule_filter, cursor, limit)
                found.update((row.id, row) for row in rows)
        volumes = [found[key] for key in sorted(found)][:limit]
        return [self._shown(await self._refresh(volume)) for volume in volumes]

    # -- commands --------------------------------------------------------------

    async def create(
        self,
        org_id: str,
        actor_id: str | None,
        name: str,
        labels: Mapping[str, str] | None = None,
    ) -> Volume:
        """Create a volume; a label-scoped key's scope labels are merged into ``labels``.

        A key with ``shared_volume_labels`` may not create a volume whose stored labels contain
        all of them: that would publish into the pool other keys read (403).
        """
        stored = merge_scope(labels or {}, current_label_scope())
        shared = current_shared_volume_labels()
        if shared and matches(stored, shared):
            raise shared_publish_refusal(shared)
        volume_id = new_volume_id()
        volume = Volume(
            id=volume_id,
            org_id=org_id,
            name=name,
            provider_volume_name=provider_volume_name(volume_id),
            state=VolumeState.READY,
            labels=stored,
            created_at=self._clock.now(),
        )
        async with self._uow_factory() as uow:  # intent: the row exists before the volume
            await uow.volumes.add(volume)
            await uow.commit()
        labels = {ORG_ID_LABEL: org_id, VOLUME_ID_LABEL: volume_id}
        details: dict[str, Any] = {"name": name, "labels": dict(stored)}
        if self._guard.max_bytes is not None:  # the size limit this service enforces, if any
            details["max_bytes"] = self._guard.max_bytes
        try:
            await self._volumes().create_volume(volume.provider_volume_name, labels=labels)
        except DriverError as exc:
            async with self._uow_factory() as uow:
                await uow.volumes.delete(org_id, volume_id)
                failure = {**details, "reason": exc.message}
                await self._record(uow, volume, actor_id, "volume.create", failure, ok=False)
                await uow.commit()
            raise
        async with self._uow_factory() as uow:
            await self._record(uow, volume, actor_id, "volume.create", details)
            await uow.commit()
        return self._shown(volume)

    async def delete(self, org_id: str, actor_id: str | None, volume_id: str) -> Volume:
        async with self._uow_factory() as uow:
            volume = await self._require(uow, org_id, volume_id, shared=True)
            if not matches(volume.labels, current_label_scope()):
                reach = current_shared_volume_labels()
                raise shared_delete_refusal(reach or {}, volume_id)
            users = await mounting_sandboxes(uow, org_id, volume_id)
            if users:
                raise in_use_conflict(volume_id, users)
            deleting = await uow.volumes.set_state(org_id, volume_id, VolumeState.DELETING)
            if deleting is None:
                raise NotFound(f"volume {volume_id} not found")
            await self._record(uow, volume, actor_id, "volume.delete", {"name": volume.name})
            await uow.commit()
        await self._discard(volume.provider_volume_name)
        async with self._uow_factory() as uow:
            await uow.volumes.delete(org_id, volume_id)
            await uow.commit()
        self._guard.forget(volume_id)
        return self._shown(deleting)

    # -- helpers ---------------------------------------------------------------

    def _shown(self, volume: Volume) -> Volume:
        """``volume`` as returned to callers: tagged with this service's own limit."""
        return with_reported_limit(volume, self._guard.max_bytes)

    def _volumes(self) -> NamedVolumeDriver:
        driver = self._driver
        if not isinstance(driver, NamedVolumeDriver):
            raise DriverUnsupported(f"driver {driver.name} cannot manage named volumes")
        return driver

    async def _inspect(self, provider_name: str) -> Mapping[str, Any]:
        return await self._volumes().inspect_volume(provider_name)

    async def _refresh(self, volume: Volume) -> Volume:
        """Re-sample the size when the driver reports one cheaply; the stored row otherwise."""
        if volume.state is not VolumeState.READY:
            return volume
        try:
            inspected = await self._inspect(volume.provider_volume_name)
        except DriverError as exc:
            logger.warning("could not inspect volume %s: %s", volume.id, exc.message)
            return volume
        size = inspected.get("size_bytes")
        if not isinstance(size, int) or size < 0:
            return volume
        # A mount right after this read trusts the sample, but only once it is stored.
        return await self._guard.store_sample(self._uow_factory, volume, size)

    async def _discard(self, provider_name: str) -> None:
        """Remove a provider volume best-effort: a failure is logged, never raised."""
        try:
            await self._volumes().remove_volume(provider_name)
        except DriverError as exc:
            logger.warning("could not remove volume %s: %s", provider_name, exc.message)

    @staticmethod
    async def _require(
        uow: UnitOfWorkPort, org_id: str, volume_id: str, *, shared: bool = False
    ) -> Volume:
        """The volume, or ``NotFound`` when missing or outside the key's label scope.

        With ``shared`` (reads only) a volume carrying the key's ``shared_volume_labels`` counts
        as inside; delete passes it only to tell "shared, so 403" from "unseen, so 404".
        """
        volume = await uow.volumes.get(org_id, volume_id)
        visible = volume is not None and matches(volume.labels, current_label_scope())
        if volume is not None and shared and not visible:
            reach = current_shared_volume_labels()
            visible = reach is not None and matches(volume.labels, reach)
        if volume is None or not visible:
            raise NotFound(f"volume {volume_id} not found")
        return volume

    async def _record(
        self,
        uow: UnitOfWorkPort,
        volume: Volume,
        actor_id: str | None,
        action: str,
        details: Mapping[str, Any],
        *,
        ok: bool = True,
        actor_type: ActorType = ActorType.API_KEY,
    ) -> None:
        await self._audit.record(
            uow,
            org_id=volume.org_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            target_type=TARGET_TYPE,
            target_id=volume.id,
            outcome=AuditOutcome.SUCCESS if ok else AuditOutcome.ERROR,
            details=details,
        )


async def _list_matching(
    uow: UnitOfWorkPort,
    org_id: str,
    labels: Mapping[str, str],
    cursor: str | None,
    limit: int,
) -> Sequence[Volume]:
    """Up to ``limit`` volumes after ``cursor`` that carry every pair of ``labels``."""
    return await uow.volumes.list(org_id, labels=labels or None, cursor=cursor, limit=limit)


def _list_filters(
    wanted: Mapping[str, str], scope: Mapping[str, str] | None, shared: Mapping[str, str] | None
) -> list[dict[str, str]]:
    """The label filters whose union a list reads: none contradicting the request are kept.

    An unscoped key reads ``wanted`` alone; a scoped one its scope and, when it has them, its
    shared labels, each merged into ``wanted`` (a contradicted rule contributes nothing).
    """
    if scope is None:
        return [dict(wanted)]
    rules = [scope] if shared is None else [scope, shared]
    return [{**wanted, **rule} for rule in rules if not contradicts(wanted, rule)]


async def mounting_sandboxes(
    uow: UnitOfWorkPort, org_id: str, volume_id: str
) -> Sequence[Sandbox]:
    """The non-deleted sandboxes in ``org_id`` that mount ``volume_id``, in id order.

    A system check: it reads the unscoped view, so a sandbox outside the key's label scope
    still blocks the delete.
    """
    sandboxes = unscoped(uow.sandboxes)
    users: list[Sandbox] = []
    cursor: str | None = None
    while True:
        page = await sandboxes.list(org_id, cursor=cursor, limit=MOUNT_SCAN_PAGE)
        users.extend(
            sandbox
            for sandbox in page
            if _is_live(sandbox)
            and any(mount.volume_id == volume_id for mount in decode_mounts(sandbox.labels))
        )
        if len(page) < MOUNT_SCAN_PAGE:
            return users
        cursor = page[-1].id


def unrecovered_restore_conflict(volume_id: str) -> Conflict:
    """409: a restore of the volume began and never ended, so it may hold part of an archive.

    The volume is handed out again once the next API start recovered it, or a new restore
    replaced its contents (that restore is the one operation a marked volume still accepts).
    """
    return Conflict(
        f"volume {volume_id} may hold part of an interrupted restore; it is emptied at the next "
        "API start, or restore it again",
        reason=RESTORE_UNRECOVERED,
        details={"volume_id": volume_id},
    )


def in_use_conflict(volume_id: str, users: Sequence[Sandbox]) -> Conflict:
    """The 409 for a volume still mounted by ``users`` (at least one sandbox).

    Only sandboxes the request's label scope can see are named: ``sandbox_id`` is the first
    visible one and ``sandbox_ids`` lists them all when there are several. Sandboxes outside
    the scope are counted in ``hidden_sandboxes`` instead, so no foreign id leaks.
    """
    scope = current_label_scope()
    visible = [sandbox.id for sandbox in users if matches(sandbox.labels, scope)]
    hidden = len(users) - len(visible)
    details: dict[str, Any] = {}
    if visible:
        details["sandbox_id"] = visible[0]
    if len(visible) > 1:
        details["sandbox_ids"] = visible
    if hidden:
        details["hidden_sandboxes"] = hidden
    if not visible:
        message = f"volume {volume_id} is mounted by {hidden} sandbox(es) outside this key's scope"
    elif hidden:
        message = f"volume {volume_id} is mounted by sandbox {visible[0]} and {hidden} hidden"
    else:
        message = f"volume {volume_id} is mounted by sandbox {visible[0]}"
    return Conflict(message, reason=IN_USE, details=details)


def _is_live(sandbox: Sandbox) -> bool:
    return sandbox.state is not SandboxState.DESTROYED and sandbox.deleted_at is None
