"""Round 67: the docker volume transfer against a fake docker-py client (no daemon).

What is pinned here: the helper container (created never started, no network, the volume at
``/volume-data``, always removed), the guards in front of it (a missing or foreign volume),
clear by remove-and-create, the policy running in front of the daemon, and that daemon text never
reaches the error a tenant sees.
"""

import asyncio
import gzip
import io
import tarfile
import time
from collections.abc import AsyncIterator, Iterator
from types import SimpleNamespace
from typing import Any

import docker
import pytest
import requests

from sandfort.config import Settings
from sandfort.drivers.base import VolumeTransferDriver
from sandfort.drivers.docker.client import GENERIC_DRIVER_MESSAGE
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.docker.labels import LABEL_MANAGED, LABEL_SANDBOX_ID
from sandfort.drivers.docker.volume_helper import (
    HELPER_LABEL,
    HELPER_MOUNT,
    HELPER_NAME_PREFIX,
    HELPER_STARTED_LABEL,
    STALE_HELPER_S,
)
from sandfort.drivers.docker.volume_transfer import AbortableSource, UploadAborted
from sandfort.drivers.errors import (
    DriverError,
    DriverForbiddenEntry,
)

REF = "sf-vol-vol_x"
HELPER_IMAGE = "alpine:3.20"
MANAGED = {LABEL_MANAGED: "true", "team": "infra"}
DAEMON_SECRET = "open /var/lib/docker/volumes/sf-vol-vol_x/_data: permission denied"


def error(cls: type[Exception], status: int, text: str = "boom") -> Exception:
    response = requests.Response()
    response.status_code = status
    return cls(text, response=response, explanation=text)


class FakeApi:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.volume: dict[str, Any] | None = {
            "Name": REF,
            "Driver": "local",
            "Options": {"o": "size=1g"},
            "Labels": dict(MANAGED),
        }
        self.image_present = True
        self.listing: list[dict[str, Any]] = []
        self.remove_volume_error: Exception | None = None
        self.create_volume_failures = 0
        self.get_chunks: list[bytes] = [b"tar-part-1", b"tar-part-2"]
        self.get_error: Exception | None = None
        self.put_error: Exception | None = None
        self.uploaded: list[bytes] = []
        self.created_volumes: list[dict[str, Any]] = []
        self.removed_containers: list[tuple[str, dict[str, Any]]] = []

    def inspect_volume(self, ref: str) -> dict[str, Any]:
        self.events.append("inspect_volume")
        if self.volume is None:
            raise error(docker.errors.NotFound, 404, f"get {ref}: no such volume")
        return self.volume

    def inspect_image(self, ref: str) -> dict[str, Any]:
        if not self.image_present:
            raise error(docker.errors.NotFound, 404, "No such image: x")
        return {"Id": "sha256:1"}

    def containers(self, **kwargs: Any) -> list[dict[str, Any]]:
        return self.listing

    def remove_container(self, container: str, **kwargs: Any) -> None:
        self.events.append("remove_container")
        self.removed_containers.append((container, kwargs))

    def get_archive(self, container: str, path: str, chunk_size: int) -> tuple[Any, dict[str, Any]]:
        self.events.append(f"get_archive {path}")
        if self.get_error is not None:
            raise self.get_error
        return iter(self.get_chunks), {"name": "volume-data"}

    def put_archive(self, container: str, path: str, data: Iterator[bytes]) -> bool:
        self.events.append(f"put_archive {path}")
        if self.put_error is not None:
            raise self.put_error
        try:
            self.uploaded.append(b"".join(data))
        except DriverError as exc:
            raise requests.exceptions.ConnectionError("the request body was aborted") from exc
        return True

    def remove_volume(self, ref: str) -> None:
        self.events.append("remove_volume")
        if self.remove_volume_error is not None:
            raise self.remove_volume_error

    def create_volume(self, **kwargs: Any) -> dict[str, Any]:
        self.events.append("create_volume")
        if self.create_volume_failures:
            self.create_volume_failures -= 1
            raise error(docker.errors.APIError, 500, "transient")
        self.created_volumes.append(kwargs)
        return {"Name": kwargs["name"], "Labels": kwargs["labels"]}


class FakeClient:
    def __init__(self) -> None:
        self.api = FakeApi()
        self.created: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.pulled: list[str] = []
        self.started: list[str] = []
        self.containers = SimpleNamespace(create=self._create)
        self.images = SimpleNamespace(pull=self._pull)

    def _create(self, *args: Any, **kwargs: Any) -> Any:
        self.api.events.append("create_container")
        self.created.append((args, kwargs))
        return SimpleNamespace(id="c0ffee", start=lambda: self.started.append("started"))

    def _pull(self, reference: str) -> None:
        self.pulled.append(reference)
        self.api.image_present = True


@pytest.fixture
def client() -> FakeClient:
    return FakeClient()


@pytest.fixture
def driver(client: FakeClient) -> DockerDriver:
    return DockerDriver(Settings(driver="docker"), client=client)


def tar_of(*entries: tuple[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


async def source(data: bytes, step: int = 700) -> AsyncIterator[bytes]:
    for start in range(0, len(data), step):
        yield data[start : start + step]


async def drain(stream: AsyncIterator[bytes]) -> bytes:
    return b"".join([piece async for piece in stream])


def test_the_docker_driver_implements_the_volume_transfer_protocol(driver: DockerDriver) -> None:
    assert isinstance(driver, VolumeTransferDriver)


# -- helper container -----------------------------------------------------------------------


async def test_export_helper_has_no_network_a_read_only_mount_and_is_never_started(
    driver: DockerDriver, client: FakeClient
) -> None:
    await drain(driver.export_volume(REF))

    (args, kwargs), *_ = client.created
    assert args[0] == HELPER_IMAGE
    assert kwargs["network_mode"] == "none"
    assert kwargs["volumes"] == {REF: {"bind": HELPER_MOUNT, "mode": "ro,nocopy"}}
    assert kwargs["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in kwargs["security_opt"]
    assert client.started == []


async def test_restore_helper_mounts_the_volume_writable_and_is_never_started(
    driver: DockerDriver, client: FakeClient
) -> None:
    await driver.restore_volume(REF, source(tar_of(("a.txt", b"1"))))

    ((_, kwargs),) = client.created
    assert kwargs["volumes"] == {REF: {"bind": HELPER_MOUNT, "mode": "rw,nocopy"}}
    assert kwargs["network_mode"] == "none"
    assert client.started == []
    assert "start" not in " ".join(client.api.events)


async def test_the_helper_is_labelled_for_cleanup_and_invisible_to_the_reconciler(
    driver: DockerDriver, client: FakeClient
) -> None:
    await drain(driver.export_volume(REF))

    labels = client.created[0][1]["labels"]
    assert labels[HELPER_LABEL] == "helper"
    assert abs(int(labels[HELPER_STARTED_LABEL]) - time.time()) < 60
    assert LABEL_MANAGED not in labels and LABEL_SANDBOX_ID not in labels


async def test_the_helper_is_removed_after_a_successful_export_and_restore(
    driver: DockerDriver, client: FakeClient
) -> None:
    await drain(driver.export_volume(REF))
    await driver.restore_volume(REF, source(tar_of(("a", b"1"))))

    assert [c for c, _ in client.api.removed_containers] == ["c0ffee", "c0ffee"]
    assert all(kw == {"force": True, "v": False} for _, kw in client.api.removed_containers)


async def test_the_helper_is_removed_when_the_daemon_refuses_the_upload(
    driver: DockerDriver, client: FakeClient
) -> None:
    client.api.put_error = error(docker.errors.APIError, 500, DAEMON_SECRET)

    with pytest.raises(DriverError):
        await driver.restore_volume(REF, source(tar_of(("a", b"1"))))

    assert [c for c, _ in client.api.removed_containers] == ["c0ffee"]


async def test_the_helper_is_removed_when_the_export_stream_is_closed_early(
    driver: DockerDriver, client: FakeClient
) -> None:
    client.api.get_chunks = [bytes(1000)] * 5
    stream = driver.export_volume(REF)

    assert await anext(stream)
    await stream.aclose()  # type: ignore[attr-defined]

    assert [c for c, _ in client.api.removed_containers] == ["c0ffee"]


async def test_a_failing_helper_removal_is_logged_and_does_not_mask_the_result(
    driver: DockerDriver, client: FakeClient, caplog: pytest.LogCaptureFixture
) -> None:
    def refuse(container: str, **kwargs: Any) -> None:
        raise error(docker.errors.APIError, 500, "removal failed")

    client.api.remove_container = refuse  # type: ignore[method-assign]

    assert await drain(driver.export_volume(REF))

    assert "could not remove volume transfer helper" in caplog.text


async def test_the_helper_image_is_pulled_when_it_is_missing(
    driver: DockerDriver, client: FakeClient
) -> None:
    client.api.image_present = False

    await drain(driver.export_volume(REF))

    assert client.pulled == [HELPER_IMAGE]


def listed(name: str, labels: dict[str, str], *, names: list[str] | None = None) -> dict[str, Any]:
    return {"Id": name, "Names": names or [f"/{HELPER_NAME_PREFIX}{name}"], "Labels": labels}


async def test_stale_helpers_of_a_crashed_transfer_are_removed_and_fresh_ones_are_kept(
    driver: DockerDriver, client: FakeClient
) -> None:
    now = int(time.time())
    client.api.listing = [
        listed("old", {HELPER_STARTED_LABEL: str(now - STALE_HELPER_S - 60)}),
        listed("fresh", {HELPER_STARTED_LABEL: str(now - 60)}),
    ]

    await drain(driver.export_volume(REF))

    removed = [c for c, _ in client.api.removed_containers]
    assert "old" in removed and "fresh" not in removed


async def test_the_prune_never_removes_a_container_that_only_carries_the_helper_label(
    driver: DockerDriver, client: FakeClient
) -> None:
    """An image can bake ``LABEL sandfort.volume_transfer=helper`` into a sandbox container."""
    old = {HELPER_STARTED_LABEL: str(int(time.time()) - STALE_HELPER_S - 60)}
    client.api.listing = [
        listed("sandbox", {**old, LABEL_SANDBOX_ID: "sbx_1"}, names=["/sf-sbx_1"]),
        listed("managed", {**old, LABEL_MANAGED: "true"}),
        listed("other-name", dict(old), names=["/someone-elses-container"]),
        listed("undated", {}),
        listed("garbled", {HELPER_STARTED_LABEL: "yesterday"}),
    ]

    await drain(driver.export_volume(REF))

    assert [c for c, _ in client.api.removed_containers] == ["c0ffee"]  # only this helper


async def test_the_helper_gets_a_name_the_prune_can_recognise(
    driver: DockerDriver, client: FakeClient
) -> None:
    await drain(driver.export_volume(REF))

    assert client.created[0][1]["name"].startswith(HELPER_NAME_PREFIX)


# -- export ---------------------------------------------------------------------------------


async def test_export_is_a_gzip_of_the_daemons_tar_read_from_the_whole_volume(
    driver: DockerDriver, client: FakeClient
) -> None:
    client.api.get_chunks = [b"A" * 3000, b"B" * 3000, b"C"]

    raw = await drain(driver.export_volume(REF))

    assert gzip.decompress(raw) == b"A" * 3000 + b"B" * 3000 + b"C"
    assert f"get_archive {HELPER_MOUNT}/." in client.api.events


async def test_export_failures_use_the_driver_errors_without_daemon_text(
    driver: DockerDriver, client: FakeClient
) -> None:
    client.api.get_error = error(docker.errors.APIError, 500, DAEMON_SECRET)

    with pytest.raises(DriverError) as caught:
        await anext(driver.export_volume(REF))

    assert caught.value.message == GENERIC_DRIVER_MESSAGE
    assert "/var/lib" not in caught.value.message
    assert [c for c, _ in client.api.removed_containers] == ["c0ffee"]


# -- restore --------------------------------------------------------------------------------


async def test_restore_empties_the_volume_first_then_uploads_the_checked_tar(
    driver: DockerDriver, client: FakeClient
) -> None:
    await driver.restore_volume(REF, source(tar_of(("a.txt", b"alpha"), ("sub/b", b"beta"))))

    events = client.api.events
    assert events.index("create_volume") < events.index("create_container")
    assert events.index("create_container") < events.index(f"put_archive {HELPER_MOUNT}")
    with tarfile.open(fileobj=io.BytesIO(client.api.uploaded[0]), mode="r:") as archive:
        assert sorted(archive.getnames()) == ["a.txt", "sub/b"]


async def test_a_forbidden_member_aborts_the_upload_with_the_policy_error_not_a_transport_error(
    driver: DockerDriver, client: FakeClient
) -> None:
    archive = tar_of(("ok.txt", b"1"), ("../evil.txt", b"2"))

    with pytest.raises(DriverForbiddenEntry) as caught:
        await driver.restore_volume(REF, source(archive))

    assert caught.value.violation == "path_traversal"
    assert [c for c, _ in client.api.removed_containers] == ["c0ffee"]


async def test_daemon_failures_while_extracting_are_tenant_safe(
    driver: DockerDriver, client: FakeClient
) -> None:
    client.api.put_error = error(docker.errors.APIError, 500, DAEMON_SECRET)

    with pytest.raises(DriverError) as caught:
        await driver.restore_volume(REF, source(tar_of(("a", b"1"))))

    assert caught.value.message == GENERIC_DRIVER_MESSAGE
    assert caught.value.daemon_text is not None and "permission denied" in caught.value.daemon_text


async def test_an_error_of_the_upload_source_reaches_the_caller_unchanged(
    driver: DockerDriver, client: FakeClient
) -> None:
    class Dropped(Exception):
        pass

    async def dropping() -> AsyncIterator[bytes]:
        yield tar_of(("a", b"1" * 4000))[:1024]
        raise Dropped("the client went away")

    with pytest.raises(Dropped):
        await driver.restore_volume(REF, dropping())

    assert [c for c, _ in client.api.removed_containers] == ["c0ffee"]


async def test_aborting_the_source_unblocks_a_read_waiting_for_the_next_piece() -> None:
    release = asyncio.Event()

    async def stalling() -> AsyncIterator[bytes]:
        yield b"first"
        await release.wait()
        yield b"never read"

    reader = AbortableSource(stalling(), asyncio.get_running_loop())
    assert await asyncio.to_thread(next, reader) == b"first"
    waiting = asyncio.create_task(asyncio.to_thread(next, reader))
    await asyncio.sleep(0.1)

    reader.abort()

    with pytest.raises(UploadAborted):
        await asyncio.wait_for(waiting, 5)
    with pytest.raises(UploadAborted):
        next(reader)  # every later read is refused too
    release.set()
