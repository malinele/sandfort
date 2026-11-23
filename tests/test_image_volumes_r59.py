"""Image-declared volume paths become platform-owned scratch volumes (round 59, MAJOR-3).

Unit tests with a fake docker-py client; the one real-daemon test carries the docker marker.
"""

import asyncio
import threading
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.base import (
    IMAGE_MOUNTS_LABEL,
    InstanceInfo,
    InstanceState,
    SandboxSpec,
    VolumeBind,
    decode_image_mounts,
)
from sandfort.drivers.docker import capabilities
from sandfort.drivers.docker.containers import create_container, info_from_attrs, remove_container
from sandfort.drivers.docker.image_volumes import (
    IMAGE_MOUNT_VOLUME_PREFIX,
    LABEL_IMAGE_MOUNT_PATH,
    declared_paths,
    image_volume_paths,
    scratch_volume_name,
    uncovered_paths,
)
from sandfort.drivers.docker.labels import LABEL_MANAGED, LABEL_ORG_ID, LABEL_SANDBOX_ID
from sandfort.drivers.fake import FakeDriver
from sandfort.workers.gc import GarbageCollector

errors = pytest.importorskip("docker.errors")

SETTINGS = Settings()
SANDBOX_ID = "sbx_1"
ORG_ID = "org_1"
RESOURCES = ResourceSpec(cpu_millicores=1000, memory_mib=512, disk_gib=2)
CREATE_BLOCK_S = 5.0


def make_spec(
    volumes: tuple[VolumeBind, ...] = (), labels: Mapping[str, str] | None = None
) -> SandboxSpec:
    return SandboxSpec(
        sandbox_id=SANDBOX_ID,
        org_id=ORG_ID,
        name=f"sf-{SANDBOX_ID}",
        image="img:1",
        resources=RESOURCES,
        volumes=volumes,
        labels=labels or {},
    )


def _label_matches(labels: Mapping[str, str], selector: str) -> bool:
    key, sep, value = selector.partition("=")
    return key in labels and (not sep or labels[key] == value)


class FakeDocker:
    """A docker-py stand-in that remembers volumes and the container it was asked to create."""

    def __init__(self, declared: list[str] | None = None) -> None:
        self.declared = declared
        self.volumes: dict[str, dict[str, str]] = {}
        self.created_kwargs: dict[str, Any] = {}
        self.removed: list[str] = []
        self.container_labels: dict[str, str] = {}
        self.create_error: Exception | None = None
        self.container_gone = False
        self.volume_creates_allowed: int | None = None  # fail every create past this count
        self.volume_remove_error: Exception | None = None
        self.events: list[str] = []
        self.create_started = threading.Event()
        self.volume_conflict_on_existing = False  # a create of an existing name answers 409
        self.volume_remove_started = threading.Event()
        self.volume_remove_release: threading.Event | None = None  # set: removal blocks on it
        self.create_release: threading.Event | None = None  # set: the create blocks on it
        self.containers = SimpleNamespace(create=self._create)
        self.networks = SimpleNamespace(
            list=lambda **_: [SimpleNamespace(name="sf-net")], create=lambda *_, **__: None
        )
        self.api = SimpleNamespace(
            inspect_image=self._inspect_image,
            inspect_volume=lambda ref: {"Name": ref},
            create_volume=self._create_volume,
            remove_volume=self._remove_volume,
            volumes=self._list_volumes,
            inspect_container=self._inspect_container,
            remove_container=self._remove_container,
        )

    def _inspect_image(self, _ref: str) -> dict[str, Any]:
        volumes = None if self.declared is None else dict.fromkeys(self.declared, {})
        return {"Id": "sha256:1", "Config": {"Volumes": volumes}}

    def _inspect_container(self, _ref: str) -> dict[str, Any]:
        if self.container_gone:
            raise errors.NotFound("no such container")
        return self._attrs()

    def _create_volume(
        self, *, name: str, driver: str, labels: Mapping[str, str]
    ) -> dict[str, Any]:
        assert driver == "local"
        if self.volume_conflict_on_existing and name in self.volumes:
            raise errors.APIError("volume exists", response=_response(409))
        if self.volume_creates_allowed is not None:
            if self.volume_creates_allowed <= 0:
                raise errors.APIError("disk full", response=_response(500))
            self.volume_creates_allowed -= 1
        self.volumes[name] = dict(labels)
        return {"Name": name, "Labels": dict(labels)}

    def _remove_volume(self, name: str) -> None:
        self.events.append(f"volume:{name}")
        self.volume_remove_started.set()
        if self.volume_remove_release is not None:
            self.volume_remove_release.wait(CREATE_BLOCK_S)
        if self.volume_remove_error is not None:
            raise self.volume_remove_error
        if name not in self.volumes:
            raise errors.NotFound("gone")
        del self.volumes[name]

    def _list_volumes(self, filters: Mapping[str, list[str]] | None = None) -> dict[str, Any]:
        wanted = (filters or {}).get("label", [])
        found = [
            {"Name": name, "Labels": labels}
            for name, labels in self.volumes.items()
            if all(_label_matches(labels, selector) for selector in wanted)
        ]
        return {"Volumes": found}

    def _create(self, _image: str, **kwargs: Any) -> Any:
        self.create_started.set()
        if self.create_release is not None:
            self.create_release.wait(CREATE_BLOCK_S)
        if self.create_error is not None:
            raise self.create_error
        self.created_kwargs = kwargs
        self.container_labels = dict(kwargs["labels"])
        return SimpleNamespace(attrs=self._attrs())

    def _attrs(self) -> dict[str, Any]:
        return {
            "Id": "cid1",
            "Name": f"/sf-{SANDBOX_ID}",
            "Created": "2026-11-11T00:00:00Z",
            "State": {"Status": "created"},
            "Config": {"Image": "img:1", "Labels": self.container_labels},
            "HostConfig": {"NanoCpus": 1_000_000_000, "Memory": 512 * 1024 * 1024},
        }

    def _remove_container(self, ref: str, *, v: bool, force: bool) -> None:
        self.events.append(f"container:{ref}")
        if self.container_gone:
            raise errors.NotFound("no such container")
        self.removed.append(ref)


def _response(status: int) -> Any:
    return SimpleNamespace(status_code=status, reason="x", url="http://docker/x")


def scratch_names(fake: FakeDocker) -> list[str]:
    return sorted(name for name in fake.volumes if name.startswith(IMAGE_MOUNT_VOLUME_PREFIX))


# --- pure helpers -------------------------------------------------------------------


def test_declared_paths_reads_the_config_volumes_keys_sorted() -> None:
    attrs = {"Config": {"Volumes": {"/var/lib/db": {}, "/data": {}, "/data/": {}}}}
    assert declared_paths(attrs) == ["/data", "/var/lib/db"]


def test_declared_paths_tolerates_images_without_volumes() -> None:
    assert declared_paths({"Config": {"Volumes": None}}) == []
    assert declared_paths({"Config": None}) == []
    assert declared_paths({}) == []


def test_uncovered_paths_skips_an_exact_match() -> None:
    assert uncovered_paths(["/data", "/other"], ["/data"]) == ["/other"]


def test_uncovered_paths_skips_a_path_under_a_requested_parent() -> None:
    assert uncovered_paths(["/mnt/data/cache", "/mnt2"], ["/mnt/data"]) == ["/mnt2"]


def test_uncovered_paths_does_not_treat_a_sibling_prefix_as_a_parent() -> None:
    assert uncovered_paths(["/data2"], ["/data"]) == ["/data2"]


def test_uncovered_paths_root_mount_covers_everything() -> None:
    assert uncovered_paths(["/data"], ["/"]) == []


def test_scratch_volume_name_derives_from_sandbox_id_and_index() -> None:
    assert scratch_volume_name("sbx_ABC", 2) == f"{IMAGE_MOUNT_VOLUME_PREFIX}sbx_abc-2"


# --- create -------------------------------------------------------------------------


async def test_covered_declared_paths_create_no_scratch_volume() -> None:
    fake = FakeDocker(declared=["/data", "/mnt/vol/inner"])
    spec = make_spec((VolumeBind("sf-vol-a", "/data"), VolumeBind("sf-vol-b", "/mnt/vol")))
    info = await create_container(fake, spec, SETTINGS)
    assert scratch_names(fake) == []
    assert info.image_mounts == []
    assert IMAGE_MOUNTS_LABEL not in fake.created_kwargs["labels"]
    assert set(fake.created_kwargs["volumes"]) == {"sf-vol-a", "sf-vol-b"}


async def test_uncovered_path_gets_a_labelled_scratch_volume_mounted_read_write() -> None:
    fake = FakeDocker(declared=["/data", "/var/lib/db"])
    spec = make_spec((VolumeBind("sf-vol-a", "/data", read_only=True),))
    info = await create_container(fake, spec, SETTINGS)

    name = scratch_volume_name(SANDBOX_ID, 0)
    assert scratch_names(fake) == [name]
    labels = fake.volumes[name]
    assert labels[LABEL_MANAGED] == "true"
    assert labels[LABEL_SANDBOX_ID] == SANDBOX_ID
    assert labels[LABEL_ORG_ID] == ORG_ID
    assert labels[LABEL_IMAGE_MOUNT_PATH] == "/var/lib/db"
    mounts = fake.created_kwargs["volumes"]
    assert mounts[name] == {"bind": "/var/lib/db", "mode": "rw"}
    assert mounts["sf-vol-a"] == {"bind": "/data", "mode": "ro"}
    assert info.image_mounts == ["/var/lib/db"]


async def test_several_uncovered_paths_get_indexed_volumes_and_a_sorted_report() -> None:
    fake = FakeDocker(declared=["/b", "/a"])
    info = await create_container(fake, make_spec(), SETTINGS)
    assert scratch_names(fake) == [
        scratch_volume_name(SANDBOX_ID, 0),
        scratch_volume_name(SANDBOX_ID, 1),
    ]
    assert info.image_mounts == ["/a", "/b"]
    assert fake.volumes[scratch_volume_name(SANDBOX_ID, 0)][LABEL_IMAGE_MOUNT_PATH] == "/a"


async def test_image_without_declared_volumes_changes_nothing() -> None:
    fake = FakeDocker(declared=None)
    info = await create_container(fake, make_spec(), SETTINGS)
    assert fake.volumes == {}
    assert "volumes" not in fake.created_kwargs
    assert info.image_mounts == []


async def test_a_client_without_api_declares_no_volumes() -> None:
    assert await image_volume_paths(object(), "alpine:3.20") == []


async def test_an_api_without_inspect_image_declares_no_volumes() -> None:
    client = SimpleNamespace(api=object())
    assert await image_volume_paths(client, "alpine:3.20") == []


async def test_a_stale_image_mounts_label_in_the_spec_is_not_carried_over() -> None:
    fake = FakeDocker(declared=None)
    spec = make_spec(labels={IMAGE_MOUNTS_LABEL: '["/old"]'})
    info = await create_container(fake, spec, SETTINGS)
    assert IMAGE_MOUNTS_LABEL not in fake.created_kwargs["labels"]
    assert info.image_mounts == []


async def test_a_failed_create_discards_the_scratch_volumes_it_made() -> None:
    fake = FakeDocker(declared=["/data"])
    response = SimpleNamespace(status_code=500, reason="x", url="http://docker/x")
    fake.create_error = errors.APIError("boom", response=response)
    with pytest.raises(Exception):  # noqa: B017 - the driver error type is not the point here
        await create_container(fake, make_spec(), SETTINGS)
    assert scratch_names(fake) == []


# --- remove and orphan listing ------------------------------------------------------


async def test_removal_deletes_the_scratch_volumes_of_that_sandbox_only() -> None:
    fake = FakeDocker(declared=["/data"])
    info = await create_container(fake, make_spec(), SETTINGS)
    fake.volumes["sf-imgvol-other-0"] = {
        LABEL_MANAGED: "true",
        LABEL_SANDBOX_ID: "sbx_other",
        LABEL_IMAGE_MOUNT_PATH: "/data",
    }
    fake.volumes["sf-vol-user"] = {LABEL_MANAGED: "true", LABEL_SANDBOX_ID: SANDBOX_ID}
    await remove_container(fake, info.ref, remove_volumes=True)
    assert fake.removed == [info.ref]
    assert sorted(fake.volumes) == ["sf-imgvol-other-0", "sf-vol-user"]


async def test_removal_without_the_volume_flag_keeps_the_scratch_volumes() -> None:
    fake = FakeDocker(declared=["/data"])
    info = await create_container(fake, make_spec(), SETTINGS)
    await remove_container(fake, info.ref, remove_volumes=False)
    assert len(scratch_names(fake)) == 1


async def test_orphan_listing_includes_the_scratch_volumes() -> None:
    fake = FakeDocker(declared=["/data"])
    await create_container(fake, make_spec(), SETTINGS)
    listed = await capabilities.list_volumes(fake)
    scratch = [item for item in listed if item.name.startswith(IMAGE_MOUNT_VOLUME_PREFIX)]
    assert [item.name for item in scratch] == [scratch_volume_name(SANDBOX_ID, 0)]
    assert scratch[0].labels[LABEL_SANDBOX_ID] == SANDBOX_ID
    assert scratch[0].labels[LABEL_IMAGE_MOUNT_PATH] == "/data"


# --- leak fixes (second review of round 59: M3, L8) ----------------------------------


async def test_removal_with_the_container_gone_removes_scratch_by_the_sandbox_label() -> None:
    fake = FakeDocker(declared=["/data"])
    await create_container(fake, make_spec(), SETTINGS)
    fake.container_gone = True
    await remove_container(fake, f"sf-{SANDBOX_ID}", remove_volumes=True)
    assert scratch_names(fake) == []


async def test_removal_without_the_mounts_label_still_removes_labelled_scratch() -> None:
    fake = FakeDocker(declared=["/data"])
    info = await create_container(fake, make_spec(), SETTINGS)
    fake.container_labels.pop(IMAGE_MOUNTS_LABEL)
    await remove_container(fake, info.ref, remove_volumes=True)
    assert scratch_names(fake) == []


async def test_a_repeated_removal_is_idempotent() -> None:
    fake = FakeDocker(declared=["/data"])
    info = await create_container(fake, make_spec(), SETTINGS)
    await remove_container(fake, info.ref, remove_volumes=True)
    fake.container_gone = True
    await remove_container(fake, info.ref, remove_volumes=True)
    assert scratch_names(fake) == []


async def test_a_failure_after_the_first_scratch_volume_removes_it() -> None:
    fake = FakeDocker(declared=["/a", "/b"])
    fake.volume_creates_allowed = 1
    with pytest.raises(Exception):  # noqa: B017 - the driver error type is not the point here
        await create_container(fake, make_spec(), SETTINGS)
    assert fake.created_kwargs == {}
    assert scratch_names(fake) == []


async def test_a_cancelled_create_removes_the_scratch_volumes() -> None:
    fake = FakeDocker(declared=["/data"])
    fake.create_release = threading.Event()
    task = asyncio.create_task(create_container(fake, make_spec(), SETTINGS))
    try:
        assert await asyncio.to_thread(fake.create_started.wait, CREATE_BLOCK_S)
        assert scratch_names(fake) == [scratch_volume_name(SANDBOX_ID, 0)]
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        fake.create_release.set()
    assert scratch_names(fake) == []


async def test_a_name_conflict_adopts_and_keeps_the_scratch_volumes() -> None:
    fake = FakeDocker(declared=["/data"])
    await create_container(fake, make_spec(), SETTINGS)
    fake.container_labels = {**fake.container_labels, LABEL_MANAGED: "true"}
    fake.create_error = errors.APIError("conflict", response=_response(409))
    fake.containers.get = lambda _name: SimpleNamespace(attrs=fake._attrs())
    await create_container(fake, make_spec(), SETTINGS)
    assert scratch_names(fake) == [scratch_volume_name(SANDBOX_ID, 0)]


async def test_destroy_succeeds_when_the_scratch_removal_fails() -> None:
    fake = FakeDocker(declared=["/data"])
    info = await create_container(fake, make_spec(), SETTINGS)
    fake.volume_remove_error = errors.APIError("daemon hiccup", response=_response(500))
    await remove_container(fake, info.ref, remove_volumes=True)
    assert fake.removed == [info.ref]
    assert fake.events[0] == f"container:{info.ref}"
    assert fake.events[1:] == [f"volume:{scratch_volume_name(SANDBOX_ID, 0)}"]


async def test_destroy_succeeds_when_the_scratch_listing_fails() -> None:
    fake = FakeDocker(declared=["/data"])
    info = await create_container(fake, make_spec(), SETTINGS)

    def broken_listing(**_: Any) -> dict[str, Any]:
        raise errors.APIError("daemon hiccup", response=_response(500))

    fake.api.volumes = broken_listing
    await remove_container(fake, info.ref, remove_volumes=True)
    assert fake.removed == [info.ref]


# --- third review (round 59: LOW 7, LOW 8) -------------------------------------------


async def _settle(fake: FakeDocker) -> None:
    """Let the shielded background cleanup finish after the test released it."""
    for _ in range(100):
        if scratch_names(fake) == []:
            return
        await asyncio.sleep(0.02)


async def test_a_second_cancellation_during_the_cleanup_is_preserved() -> None:
    fake = FakeDocker(declared=["/data"])
    fake.create_release = threading.Event()
    fake.volume_remove_release = threading.Event()
    task = asyncio.create_task(create_container(fake, make_spec(), SETTINGS))
    try:
        assert await asyncio.to_thread(fake.create_started.wait, CREATE_BLOCK_S)
        task.cancel()  # the first cancellation starts the shielded cleanup
        assert await asyncio.to_thread(fake.volume_remove_started.wait, CREATE_BLOCK_S)
        task.cancel()  # the second one arrives while the cleanup is awaited
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        fake.create_release.set()
        fake.volume_remove_release.set()
    await _settle(fake)
    assert scratch_names(fake) == []  # the cleanup still ran to its end in the background


async def test_cancellation_during_the_cleanup_of_a_failed_create_wins_over_the_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakeDocker(declared=["/data"])
    fake.create_error = errors.APIError("boom", response=_response(500))
    fake.volume_remove_release = threading.Event()
    task = asyncio.create_task(create_container(fake, make_spec(), SETTINGS))
    try:
        assert await asyncio.to_thread(fake.volume_remove_started.wait, CREATE_BLOCK_S)
        task.cancel()  # the create failed; the cleanup is running when the cancel lands
        with caplog.at_level("WARNING"), pytest.raises(asyncio.CancelledError):
            await task
    finally:
        fake.volume_remove_release.set()
    await _settle(fake)
    assert scratch_names(fake) == []
    logged = [r for r in caplog.records if "create of" in r.getMessage()]
    assert len(logged) == 1  # the original error is logged once


async def test_an_uncancelled_failed_create_still_raises_the_original_error() -> None:
    fake = FakeDocker(declared=["/data"])
    fake.create_error = errors.APIError("boom", response=_response(500))
    with pytest.raises(Exception) as caught:  # noqa: B017 - the driver error type varies
        await create_container(fake, make_spec(), SETTINGS)
    assert not isinstance(caught.value, asyncio.CancelledError)
    assert scratch_names(fake) == []


async def test_creating_a_scratch_volume_that_exists_is_reuse_not_an_error() -> None:
    fake = FakeDocker(declared=["/data"])
    fake.volume_conflict_on_existing = True
    name = scratch_volume_name(SANDBOX_ID, 0)
    fake.volumes[name] = {LABEL_MANAGED: "true", LABEL_SANDBOX_ID: SANDBOX_ID}
    info = await create_container(fake, make_spec(), SETTINGS)
    assert scratch_names(fake) == [name]
    assert fake.created_kwargs["volumes"][name] == {"bind": "/data", "mode": "rw"}
    assert info.image_mounts == ["/data"]


async def test_a_recreate_that_keeps_the_volumes_mounts_the_same_scratch_names() -> None:
    fake = FakeDocker(declared=["/a", "/b"])
    fake.volume_conflict_on_existing = True
    first = await create_container(fake, make_spec(), SETTINGS)
    before = dict(fake.created_kwargs["volumes"])
    fake.volumes[scratch_volume_name(SANDBOX_ID, 0)]["seeded"] = "data"

    await remove_container(fake, first.ref, remove_volumes=False)  # the resize path
    assert len(scratch_names(fake)) == 2
    second = await create_container(fake, make_spec(), SETTINGS)

    assert fake.created_kwargs["volumes"] == before
    assert second.image_mounts == ["/a", "/b"]
    assert fake.volumes[scratch_volume_name(SANDBOX_ID, 0)]["seeded"] == "data"  # same volume


async def test_delete_still_removes_the_scratch_volumes() -> None:
    fake = FakeDocker(declared=["/a", "/b"])
    info = await create_container(fake, make_spec(), SETTINGS)
    await remove_container(fake, info.ref, remove_volumes=True)
    assert scratch_names(fake) == []


async def test_the_resize_recreate_keeps_volumes_and_delete_removes_them(tmp_path: Any) -> None:
    from test_resize import auth, key_for_new_org, make_app, resize, serve, stopped_sandbox

    app = make_app(tmp_path)
    calls: list[bool] = []
    driver = app.state.driver
    assert isinstance(driver, FakeDriver)
    original = driver.destroy

    async def recording(ref: str, *, remove_volumes: bool = True) -> None:
        calls.append(remove_volumes)
        await original(ref, remove_volumes=remove_volumes)

    driver.destroy = recording  # type: ignore[method-assign]
    async with serve(app) as client:
        key = await key_for_new_org(app, "acme")
        sandbox_id = await stopped_sandbox(client, key)
        assert (await resize(client, key, sandbox_id, cpu_millicores=2000)).status_code == 200
        started = await client.post(f"/v1/sandboxes/{sandbox_id}/start", headers=auth(key))
        assert started.status_code == 200, started.text
        assert calls == [False]  # the recreate keeps the container's volumes
        deleted = await client.delete(f"/v1/sandboxes/{sandbox_id}", headers=auth(key))
        assert deleted.status_code in (200, 202, 204), deleted.text
    assert calls[-1] is True  # delete keeps the default: scratch volumes go


class _Sandboxes:
    def __init__(self, live: Mapping[tuple[str, str], Sandbox]) -> None:
        self._live = live

    async def get(self, org_id: str, sandbox_id: str) -> Sandbox | None:
        return self._live.get((org_id, sandbox_id))

    async def list_for_reconciler(self) -> list[Sandbox]:
        return list(self._live.values())


class _Uow:
    """Just enough unit of work for the gc volume pass; audit writes fail and are logged."""

    def __init__(self, live: Mapping[tuple[str, str], Sandbox]) -> None:
        self.sandboxes = _Sandboxes(live)

    async def __aenter__(self) -> "_Uow":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None


async def _plant_scratch(driver: FakeDriver, sandbox_id: str) -> str:
    name = scratch_volume_name(sandbox_id, 0)
    labels = {
        LABEL_MANAGED: "true",
        LABEL_SANDBOX_ID: sandbox_id,
        LABEL_ORG_ID: ORG_ID,
        LABEL_IMAGE_MOUNT_PATH: "/data",
    }
    await driver.create_volume(name, labels=labels)
    return name


async def test_gc_collects_an_orphaned_scratch_volume_and_keeps_a_live_one() -> None:
    driver = FakeDriver()
    orphan = await _plant_scratch(driver, "sbx_gone")
    live_name = await _plant_scratch(driver, "sbx_live")
    destroyed = await _plant_scratch(driver, "sbx_destroyed")
    live = {
        (ORG_ID, "sbx_live"): _sandbox({}).model_copy(update={"id": "sbx_live"}),
        (ORG_ID, "sbx_destroyed"): _sandbox({}).model_copy(
            update={"id": "sbx_destroyed", "state": SandboxState.DESTROYED}
        ),
    }
    collector = GarbageCollector(
        cast(Any, lambda: _Uow(live)),
        cast(Any, None),  # the image pass fails on it and is counted; volumes are the point
        driver,
        FrozenClock(),
        interval_s=1,
        grace_s=0,
    )
    report = await collector.collect_once()
    assert sorted(report.volumes_removed) == sorted([orphan, destroyed])
    assert [item.name for item in await driver.list_volumes()] == [live_name]


async def test_gc_waits_out_the_grace_before_collecting_a_scratch_volume() -> None:
    driver = FakeDriver()
    orphan = await _plant_scratch(driver, "sbx_gone")
    clock = FrozenClock()
    collector = GarbageCollector(
        cast(Any, lambda: _Uow({})),
        cast(Any, None),
        driver,
        clock,
        interval_s=1,
        grace_s=60,
    )
    assert (await collector.collect_once()).volumes_removed == ()
    clock.advance(timedelta(seconds=61))
    assert (await collector.collect_once()).volumes_removed == (orphan,)


# --- instance info and the sandbox view ---------------------------------------------


def test_info_from_attrs_reports_sorted_image_mounts_from_the_container_label() -> None:
    attrs = {
        "Id": "cid",
        "Name": "/sf-x",
        "Created": "2026-11-11T00:00:00Z",
        "State": {"Status": "running"},
        "Config": {"Image": "i", "Labels": {IMAGE_MOUNTS_LABEL: '["/z", "/a"]'}},
        "HostConfig": {},
    }
    assert info_from_attrs(attrs).image_mounts == ["/a", "/z"]


def test_decode_image_mounts_ignores_garbage() -> None:
    assert decode_image_mounts(None) == []
    assert decode_image_mounts("not json") == []
    assert decode_image_mounts('{"a": 1}') == []
    assert decode_image_mounts('["/a", 3, "/a"]') == ["/a"]


def test_instance_info_defaults_to_no_image_mounts() -> None:
    info = InstanceInfo(
        ref="r",
        name="n",
        sandbox_id="s",
        org_id="o",
        state=InstanceState.RUNNING,
        image="i",
        resources=RESOURCES,
        labels={},
        created_at=datetime.now(UTC),
    )
    assert info.image_mounts == []


def _sandbox(labels: dict[str, str]) -> Sandbox:
    now = datetime.now(UTC)
    return Sandbox(
        id="sbx_1",
        org_id=ORG_ID,
        name="n",
        state=SandboxState.STARTED,
        driver="docker",
        image_ref="img:1",
        resources=RESOURCES,
        labels=labels,
        created_at=now,
        updated_at=now,
    )


def test_sandbox_view_lists_image_mounts_and_defaults_to_empty() -> None:
    from sandfort.api.schemas.sandboxes import SandboxResponse, sandbox_response

    assert sandbox_response(_sandbox({})).image_mounts == []
    shown = sandbox_response(_sandbox({IMAGE_MOUNTS_LABEL: '["/b", "/a"]', "team": "x"}))
    assert shown.image_mounts == ["/a", "/b"]
    assert shown.labels == {"team": "x"}  # the reserved label stays out of the user labels
    description = SandboxResponse.model_fields["image_mounts"].description or ""
    assert "disk_gib" in description
    assert "soft limit" in description


def test_row_label_helper_records_and_clears_image_mounts() -> None:
    from sandfort.services.sandboxes import with_image_mounts_label

    labels = with_image_mounts_label({"team": "x"}, ["/b", "/a"])
    assert decode_image_mounts(labels[IMAGE_MOUNTS_LABEL]) == ["/a", "/b"]
    assert labels["team"] == "x"
    assert IMAGE_MOUNTS_LABEL not in with_image_mounts_label(labels, [])


@pytest.mark.docker
async def test_real_daemon_declared_volume_gets_a_scratch_volume() -> None:
    from sandfort.drivers.docker.driver import DockerDriver

    driver = DockerDriver(SETTINGS)
    spec = SandboxSpec(
        sandbox_id="sbx_r59img",
        org_id=ORG_ID,
        name="sf-sbx_r59img",
        image="postgres:16-alpine",
        resources=RESOURCES,
    )
    name = scratch_volume_name("sbx_r59img", 0)
    info = await driver.create(spec)
    try:
        assert "/var/lib/postgresql/data" in info.image_mounts
        assert name in [item.name for item in await driver.list_volumes()]
    finally:
        await driver.destroy(info.ref)
    try:
        assert name not in [item.name for item in await driver.list_volumes()]
    finally:
        await driver.aclose()
