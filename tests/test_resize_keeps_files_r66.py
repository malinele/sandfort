"""r66a: a resize keeps the root filesystem (S1), over the fake driver and the ASGI client.

The recreate that follows a resize commits the stopped container to a local image
(``sf-resize-<sandbox id>``) and creates the new container from it. The tag stays while the
sandbox lives (the new container is still based on it; the next resize commits to the same tag)
and goes with the sandbox; a create failing after the destroy keeps the commit (the only copy).
The fake models overlay2: force-removing an image that only stopped containers use deletes it.
A reset still starts from the original image.
"""

import io
import tarfile
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sandfort.domain.resources import ResourceSpec
from sandfort.drivers.base import SandboxSpec
from sandfort.drivers.errors import DriverError, DriverNotFound
from sandfort.drivers.fake import FakeDriver
from test_resize import (
    GROWN_CPU,
    GROWN_MEMORY,
    SANDBOXES,
    auth,
    key_for_new_org,
    resize,
    serve,
    stopped_sandbox,
)

# the fake pulls an image on demand; the default sandbox image is whatever the service picks
PATH = "/tmp/m"
CONTENT = b"kept across the resize"


@pytest.fixture
async def app(tmp_path: Any) -> FastAPI:
    from test_resize import make_app

    return make_app(tmp_path)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with serve(app) as http:
        yield http


@pytest.fixture
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


def tar_of(name: str, content: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        member = tarfile.TarInfo(name)
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return buffer.getvalue()


async def one_chunk(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def write_file(driver: FakeDriver, ref: str, path: str, content: bytes) -> None:
    directory, _, name = path.rpartition("/")
    await driver.put_archive(ref, directory or "/", one_chunk(tar_of(name, content)))


async def read_file(driver: FakeDriver, ref: str, path: str) -> bytes:
    chunks = [chunk async for chunk in driver.get_archive(ref, path)]
    with tarfile.open(fileobj=io.BytesIO(b"".join(chunks)), mode="r") as archive:
        [member] = archive.getmembers()
        handle = archive.extractfile(member)
        assert handle is not None
        return handle.read()


async def sandbox_with_file(client: httpx.AsyncClient, driver: FakeDriver, key: str) -> str:
    """A started sandbox with ``PATH`` written, then stopped; returns its id."""
    created = await client.post(SANDBOXES, headers=auth(key), json={})
    assert created.status_code == 201, created.text
    sandbox_id: str = created.json()["data"]["id"]
    [info] = await driver.list_managed()
    await write_file(driver, info.ref, PATH, CONTENT)
    stopped = await client.post(f"{SANDBOXES}/{sandbox_id}/stop", headers=auth(key))
    assert stopped.json()["data"]["state"] == "stopped", stopped.text
    return sandbox_id


def temp_image(sandbox_id: str) -> str:
    return f"sf-resize-{sandbox_id.lower()}"


class Recorder:
    """Wraps the fake driver's calls and records their order."""

    def __init__(self, driver: FakeDriver) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail_create_from_temp = False
        self._driver = driver
        self._wrap_commit()
        self._wrap_create()
        self._wrap_destroy()
        self._wrap_remove_image()

    def _wrap_commit(self) -> None:
        original = self._driver.commit_container

        async def commit_container(provider_id: str, image_reference: str, **kwargs: Any) -> Any:
            self.calls.append(("commit", image_reference))
            return await original(provider_id, image_reference, **kwargs)

        self._driver.commit_container = commit_container  # type: ignore[method-assign]

    def _wrap_create(self) -> None:
        original = self._driver.create

        async def create(spec: SandboxSpec) -> Any:
            self.calls.append(("create", spec.image))
            if self.fail_create_from_temp and spec.image.startswith("sf-resize-"):
                raise DriverError("create refused", ref=spec.name)
            return await original(spec)

        self._driver.create = create  # type: ignore[method-assign]

    def _wrap_destroy(self) -> None:
        original = self._driver.destroy

        async def destroy(ref: str, *, remove_volumes: bool = True) -> None:
            self.calls.append(("destroy", ref))
            await original(ref, remove_volumes=remove_volumes)

        self._driver.destroy = destroy  # type: ignore[method-assign]

    def _wrap_remove_image(self) -> None:
        original = self._driver.remove_image

        async def remove_image(ref: str, **kwargs: Any) -> None:
            self.calls.append(("remove_image", ref))
            await original(ref, **kwargs)

        self._driver.remove_image = remove_image  # type: ignore[method-assign]


async def test_a_resize_keeps_files_written_before_the_stop(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver
) -> None:
    key = await key_for_new_org(app, "acme")
    sandbox_id = await sandbox_with_file(client, driver, key)

    resized = await resize(client, key, sandbox_id, cpu_millicores=GROWN_CPU)
    started = await client.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

    assert resized.status_code == 200, resized.text
    assert started.status_code == 200, started.text
    [info] = await driver.list_managed()
    assert info.resources.cpu_millicores == GROWN_CPU  # a new container
    assert await read_file(driver, info.ref, PATH) == CONTENT


async def test_the_new_container_is_created_from_the_committed_image_and_the_tag_stays(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver
) -> None:
    key = await key_for_new_org(app, "acme")
    sandbox_id = await sandbox_with_file(client, driver, key)
    [old] = await driver.list_managed()
    recorder = Recorder(driver)
    await resize(client, key, sandbox_id, cpu_millicores=GROWN_CPU)

    started = await client.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

    assert started.status_code == 200, started.text
    image = temp_image(sandbox_id)
    assert recorder.calls == [
        ("commit", image),
        ("destroy", old.ref),
        ("create", image),
    ]  # the new (not running) container still uses the image: it must not be removed
    assert await driver.image_exists(image)


async def test_a_second_resize_keeps_the_files_of_both_rounds(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver
) -> None:
    key = await key_for_new_org(app, "acme")
    sandbox_id = await sandbox_with_file(client, driver, key)
    await resize(client, key, sandbox_id, cpu_millicores=GROWN_CPU)
    first = await client.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))
    assert first.status_code == 200, first.text
    [info] = await driver.list_managed()
    await write_file(driver, info.ref, "/root/second", b"written after the first resize")
    stopped = await client.post(f"{SANDBOXES}/{sandbox_id}/stop", headers=auth(key))
    assert stopped.json()["data"]["state"] == "stopped", stopped.text

    resized = await resize(client, key, sandbox_id, memory_mib=GROWN_MEMORY)
    second = await client.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

    assert resized.status_code == 200, resized.text
    assert second.status_code == 200, second.text
    [info] = await driver.list_managed()
    assert info.resources.memory_mib == GROWN_MEMORY
    assert await read_file(driver, info.ref, PATH) == CONTENT
    assert await read_file(driver, info.ref, "/root/second") == b"written after the first resize"
    assert await driver.image_exists(temp_image(sandbox_id))


async def test_a_third_resize_removes_the_previous_commit_by_its_id(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver
) -> None:
    key = await key_for_new_org(app, "acme")
    sandbox_id = await sandbox_with_file(client, driver, key)
    await resize(client, key, sandbox_id, cpu_millicores=GROWN_CPU)
    await client.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))
    first = (await driver.inspect_image(temp_image(sandbox_id))).digest
    await client.post(f"{SANDBOXES}/{sandbox_id}/stop", headers=auth(key))
    recorder = Recorder(driver)
    await resize(client, key, sandbox_id, memory_mib=GROWN_MEMORY)

    started = await client.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

    assert started.status_code == 200, started.text
    assert ("remove_image", first) in recorder.calls
    assert (await driver.inspect_image(temp_image(sandbox_id))).digest != first


async def test_deleting_the_sandbox_removes_the_tagged_resize_image(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver
) -> None:
    key = await key_for_new_org(app, "acme")
    sandbox_id = await sandbox_with_file(client, driver, key)
    await resize(client, key, sandbox_id, cpu_millicores=GROWN_CPU)
    await client.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))
    assert await driver.image_exists(temp_image(sandbox_id))

    deleted = await client.delete(f"{SANDBOXES}/{sandbox_id}", headers=auth(key))

    assert deleted.status_code == 200, deleted.text
    assert await driver.list_managed() == []
    assert not await driver.image_exists(temp_image(sandbox_id))


def spec_for(sandbox_id: str, image: str) -> SandboxSpec:
    return SandboxSpec(
        sandbox_id=sandbox_id,
        org_id="org_1",
        name=f"sf-{sandbox_id}",
        image=image,
        resources=ResourceSpec(cpu_millicores=1000, memory_mib=512, disk_gib=3),
    )


async def test_the_fake_deletes_an_image_that_only_stopped_containers_use(
    driver: FakeDriver,
) -> None:
    """The overlay2 behaviour of ``rmi -f`` the beta runs on (the second-resize regression)."""
    source = await driver.create(spec_for("sbx_src", "alpine"))
    await driver.commit_container(source.ref, "overlay-image")
    created = await driver.create(spec_for("sbx_overlay", "overlay-image"))

    await driver.remove_image("overlay-image", force=True)

    assert not await driver.image_exists("overlay-image")
    with pytest.raises(DriverNotFound, match="No such image"):
        await driver.commit_container(created.ref, "again")


async def test_the_fake_keeps_the_image_in_the_containerd_mode(driver: FakeDriver) -> None:
    driver.overlay2_images = False
    source = await driver.create(spec_for("sbx_src", "alpine"))
    await driver.commit_container(source.ref, "overlay-image")
    created = await driver.create(spec_for("sbx_overlay", "overlay-image"))

    await driver.remove_image("overlay-image", force=True)

    await driver.commit_container(created.ref, "again")  # only untagged: the config is still there


async def test_a_failing_create_keeps_the_temporary_image(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver
) -> None:
    key = await key_for_new_org(app, "acme")
    sandbox_id = await sandbox_with_file(client, driver, key)
    recorder = Recorder(driver)
    recorder.fail_create_from_temp = True
    await resize(client, key, sandbox_id, cpu_millicores=GROWN_CPU)

    started = await client.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

    assert started.status_code == 500, started.text
    image = temp_image(sandbox_id)
    assert ("remove_image", image) not in recorder.calls  # the old container is gone: keep it
    assert await driver.image_exists(image)


async def test_a_failing_commit_is_an_internal_error_and_the_retry_works(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver
) -> None:
    key = await key_for_new_org(app, "acme")
    sandbox_id = await sandbox_with_file(client, driver, key)
    [old] = await driver.list_managed()
    await resize(client, key, sandbox_id, cpu_millicores=GROWN_CPU)
    original = driver.commit_container

    async def refuse(provider_id: str, image_reference: str, **kwargs: Any) -> Any:
        raise DriverNotFound("No such image: sha256:0", ref=provider_id)  # what overlay2 said

    driver.commit_container = refuse  # type: ignore[method-assign]

    started = await client.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

    assert started.status_code == 500, started.text  # never the 404 of a sandbox that exists
    body = started.json()["error"]
    assert body["code"] == "INTERNAL"
    assert "resize could not prepare" in body["message"]
    assert "sha256" not in body["message"]
    [still] = await driver.list_managed()
    assert still.ref == old.ref
    assert await driver.image_exists(temp_image(sandbox_id)) is False
    row = await client.get(f"{SANDBOXES}/{sandbox_id}", headers=auth(key))
    assert row.json()["data"]["state"] == "stopped"

    driver.commit_container = original  # type: ignore[method-assign]
    retried = await client.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

    assert retried.status_code == 200, retried.text
    [info] = await driver.list_managed()
    assert info.resources.cpu_millicores == GROWN_CPU
    assert await read_file(driver, info.ref, PATH) == CONTENT


async def test_a_resize_without_a_stop_start_cycle_commits_nothing(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver
) -> None:
    key = await key_for_new_org(app, "acme")
    sandbox_id = await stopped_sandbox(client, key)
    recorder = Recorder(driver)

    started = await client.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

    assert started.status_code == 200, started.text
    assert recorder.calls == []  # unchanged resources: the container is adopted as before


async def test_reset_still_wipes_the_root_filesystem_after_a_resize(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver
) -> None:
    key = await key_for_new_org(app, "acme")
    sandbox_id = await sandbox_with_file(client, driver, key)
    await resize(client, key, sandbox_id, cpu_millicores=GROWN_CPU)
    await client.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

    reset = await client.post(f"{SANDBOXES}/{sandbox_id}/reset", headers=auth(key))

    assert reset.status_code == 200, reset.text
    [info] = await driver.list_managed()
    assert info.state.value == "running"
    with pytest.raises(Exception, match="no such path"):
        await read_file(driver, info.ref, PATH)
