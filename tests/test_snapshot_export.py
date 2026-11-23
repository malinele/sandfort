"""``GET /v1/snapshots/{id}/export`` and the Docker image export behind it.

The route runs on the fake driver, which has no image export of its own: the unsupported
case uses it as is, the others answer the route's driver dependency with a stub exporter.
The Docker function is driven by a fake low-level client; one test needs a real daemon.
"""

import threading
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from fastapi import FastAPI

from sandfort.api.deps import get_driver
from sandfort.api.routes.snapshots import export_file_name
from sandfort.config import Settings
from sandfort.domain.snapshot import Snapshot, SnapshotState
from sandfort.drivers.base import ImageExportDriver
from sandfort.drivers.docker import image_export, lanes
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.errors import DriverNotFound
from sandfort.drivers.fake import FakeDriver
from test_api_sandboxes import add_org, migrated_app, send
from test_snapshot_export_sanitize import CHUNKS, RELEASE_TIMEOUT_S, FakeDockerApi
from test_snapshot_scope import BLUE, RED, SNAPSHOTS, commit_snapshot, make_sandbox, seed_key
from test_snapshots import audit_rows

SNAPSHOT_REF = "sandfort-snapshot:snap_1"
TAR_TYPE = "application/x-tar"
EXPORT_ACTION = "snapshot.exported"


@pytest.fixture(autouse=True)
def default_lanes() -> Iterator[None]:
    """Other tests resize or close the process-wide docker lanes; start from the defaults."""
    lanes.configure_thread_limit()
    yield
    lanes.configure_thread_limit()


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path) as application:
        yield application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "export-org")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id, None)


@pytest.fixture
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


class StubExporter:
    """A driver stand-in for the route: yields ``CHUNKS`` or raises ``failure``."""

    def __init__(self, failure: Exception | None = None) -> None:
        self.seen: list[str] = []
        self._failure = failure

    async def export_image(self, reference: str) -> AsyncIterator[bytes]:
        self.seen.append(reference)
        if self._failure is not None:
            raise self._failure
        for chunk in CHUNKS:
            yield chunk


def give_export(app: FastAPI, failure: Exception | None = None) -> StubExporter:
    """Answer the route's driver dependency with an ``ImageExportDriver`` stub.

    The app hands routes an instrumented wrapper that mirrors the driver *class*, so an
    attribute set on the fake driver instance would be invisible to it.
    """
    stub = StubExporter(failure)
    app.dependency_overrides[get_driver] = lambda: stub
    return stub


async def ready_snapshot(app: FastAPI, client: httpx.AsyncClient, key: str, **labels: str) -> str:
    payload: dict[str, Any] = {"labels": labels} if labels else {}
    sandbox_id = await make_sandbox(client, key, **payload)
    return await commit_snapshot(app, client, key, sandbox_id)


async def export_response(client: httpx.AsyncClient, key: str, snapshot_id: str) -> httpx.Response:
    return await client.get(
        f"{SNAPSHOTS}/{snapshot_id}/export", headers={"Authorization": f"Bearer {key}"}
    )


async def test_export_streams_the_driver_bytes_with_download_headers(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    snapshot_id = await ready_snapshot(app, client, key)
    stub = give_export(app)
    fetched = (await send(client, "GET", f"{SNAPSHOTS}/{snapshot_id}", key, status=200))["data"]

    response = await export_response(client, key, snapshot_id)

    assert response.status_code == 200, response.text
    assert response.content == b"".join(CHUNKS)
    assert response.headers["content-type"] == TAR_TYPE
    disposition = response.headers["content-disposition"]
    assert disposition == f'attachment; filename="{fetched["name"]}.tar"'
    assert stub.seen == [fetched["image_ref"]]


async def test_export_records_the_audit_event(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    snapshot_id = await ready_snapshot(app, client, key)
    give_export(app)

    await export_response(client, key, snapshot_id)

    events = [e for e in await audit_rows(app, org_id) if e.action == EXPORT_ACTION]
    assert len(events) == 1
    assert events[0].target_type == "snapshot"
    assert events[0].target_id == snapshot_id
    assert events[0].actor_id is not None


async def test_export_of_another_orgs_snapshot_is_not_found(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    snapshot_id = await ready_snapshot(app, client, key)
    give_export(app)
    other_org = await add_org(app, "someone-else")
    other_key = await seed_key(app, other_org, None)

    body = await send(client, "GET", f"{SNAPSHOTS}/{snapshot_id}/export", other_key, status=404)

    assert body["error"]["code"] == "NOT_FOUND"


async def test_export_outside_the_label_scope_is_not_found(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    blue_snapshot = await ready_snapshot(app, client, key, **BLUE)
    give_export(app)
    red_key = await seed_key(app, org_id, RED)

    await send(client, "GET", f"{SNAPSHOTS}/{blue_snapshot}/export", red_key, status=404)


async def test_export_of_a_pending_snapshot_is_an_invalid_state(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await make_sandbox(client, key)
    give_export(app)
    payload = {"sandbox_id": sandbox_id, "name": "not-yet"}
    created = await send(client, "POST", f"{SNAPSHOTS}/from-sandbox", key, status=202, json=payload)
    pending_id = created["data"]["id"]

    body = await send(client, "GET", f"{SNAPSHOTS}/{pending_id}/export", key, status=409)

    assert body["error"]["code"] == "INVALID_STATE"
    assert body["error"]["details"]["state"] == SnapshotState.PENDING.value


async def test_export_without_driver_support_is_unsupported_mode(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, key: str, org_id: str
) -> None:
    assert not isinstance(driver, ImageExportDriver)
    snapshot_id = await ready_snapshot(app, client, key)

    body = await send(client, "GET", f"{SNAPSHOTS}/{snapshot_id}/export", key, status=409)

    assert body["error"]["code"] == "CONFLICT"
    assert body["error"]["details"]["reason"] == "unsupported_mode"
    exported = [e for e in await audit_rows(app, org_id) if e.action == EXPORT_ACTION]
    assert exported == []


async def test_export_of_a_missing_image_is_not_found(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    snapshot_id = await ready_snapshot(app, client, key)
    give_export(app, DriverNotFound("no such image", ref="x"))

    await send(client, "GET", f"{SNAPSHOTS}/{snapshot_id}/export", key, status=404)


async def test_export_without_a_key_is_unauthenticated(client: httpx.AsyncClient) -> None:
    await send(client, "GET", f"{SNAPSHOTS}/snap_x/export", None, status=401)


def snapshot_named(name: str) -> Snapshot:
    return Snapshot(
        id="snap_ABC",
        org_id="org_1",
        name=name,
        image_ref="sandfort-snapshot:snap_abc",
        digest="sha256:" + "ab" * 32,
        layer_count=1,
        state=SnapshotState.READY,
        created_at=datetime(2026, 11, 5, tzinfo=UTC),
    )


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("my-env_1.2", "my-env_1.2.tar"),
        ('a b/c"d\r\ne', "a-b-c-d-e.tar"),
        ("../../etc/passwd", "etc-passwd.tar"),
        ("..", "snap_ABC.tar"),
        ("///", "snap_ABC.tar"),
        ("é" * 5, "snap_ABC.tar"),
        ("x" * 300, "x" * 100 + ".tar"),
    ],
)
def test_export_file_name_keeps_safe_characters_only(name: str, expected: str) -> None:
    assert export_file_name(snapshot_named(name)) == expected


# --- the Docker export function ---------------------------------------------------------
# The sanitizing behaviour itself is covered in test_snapshot_export_sanitize.py.


async def test_docker_export_streams_the_chunks_of_the_temporary_image() -> None:
    api = FakeDockerApi()

    received = [chunk async for chunk in image_export.export_image(api.client(), SNAPSHOT_REF)]

    assert received == CHUNKS
    assert api.created["image"] == SNAPSHOT_REF
    assert api.response.closed == 1


async def test_cancel_during_the_import_still_removes_the_late_container_and_image() -> None:
    release = threading.Event()
    importing = threading.Event()
    api = FakeDockerApi()
    fast_import = api.import_image

    def slow_import(**kwargs: Any) -> str:
        importing.set()
        assert release.wait(RELEASE_TIMEOUT_S)
        return fast_import(**kwargs)

    api.import_image = slow_import  # type: ignore[method-assign]

    async def consume() -> None:
        async for _ in image_export.export_image(api.client(), SNAPSHOT_REF):
            pass

    async with anyio.create_task_group() as group:
        group.start_soon(consume)
        with anyio.fail_after(RELEASE_TIMEOUT_S):
            while not importing.is_set():
                await anyio.sleep(0.01)
        group.cancel_scope.cancel()
    assert api.removed_images == []  # docker has not finished: nothing to remove yet

    release.set()
    with anyio.fail_after(RELEASE_TIMEOUT_S):
        while not api.removed_images:
            await anyio.sleep(0.01)

    assert api.removed_containers == [api.created["name"]]
    assert api.removed_images == [api.temp_reference]
    assert "save" not in api.events


async def test_docker_export_of_a_missing_image_raises_not_found() -> None:
    docker = pytest.importorskip("docker")
    api = FakeDockerApi()

    def missing(reference: str) -> dict[str, Any]:
        raise docker.errors.ImageNotFound("no such image: ghost")

    api.inspect_image = missing  # type: ignore[method-assign]

    with pytest.raises(DriverNotFound):
        await anext(image_export.export_image(api.client(), "ghost:latest"))

    assert api.created == {}


async def test_docker_driver_is_an_image_export_driver() -> None:
    api = FakeDockerApi()
    driver = DockerDriver(Settings(driver="docker"), client=api.client())

    assert isinstance(driver, ImageExportDriver)
    assert [chunk async for chunk in driver.export_image(SNAPSHOT_REF)] == CHUNKS
