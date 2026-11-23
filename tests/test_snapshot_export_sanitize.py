"""Snapshot export must not leak the source sandbox's environment.

A snapshot image keeps the container's whole ``Env``. The export builds a sanitized single-layer
image first (container from the snapshot image, filesystem export into an import whose config is
``config_changes`` only), saves that, and removes the temporary container and image. Unit tests
use ``FakeDockerApi``; one test needs a real daemon. The stream close race is covered here too.
"""

import contextlib
import io
import json
import tarfile
import threading
import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import anyio
import pytest

from sandfort.drivers.docker import image_export, images, lanes
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.docker.labels import LABEL_MANAGED, LABEL_SANDBOX_ID
from sandfort.drivers.errors import DriverError

SOURCE = "sandfort-snapshot:snap_src"
CHUNKS = [b"first-chunk-", b"second-chunk-", b"last"]
SECRET_ENV = [
    "PATH=/usr/local/bin:/usr/bin",
    "SECRET_TOKEN=abc",
    "HTTPS_PROXY=http://sandbox:signed.token@egress:3128",
]
SOURCE_CONFIG: dict[str, Any] = {
    "Env": SECRET_ENV,
    "Labels": {"sandfort.sandbox": "sbx_1"},
    "WorkingDir": "/work",
    "Cmd": ["sleep", "30"],
}
RELEASE_TIMEOUT_S = 10.0
TEMP_IMAGE_ID = "sha256:" + "ab" * 32


@pytest.fixture(autouse=True)
def default_lanes() -> Iterator[None]:
    lanes.configure_thread_limit()
    yield
    lanes.configure_thread_limit()


class FakeResponse:
    """A requests response: ``iter_content`` yields chunks, ``close`` is recorded."""

    def __init__(self, chunks: Any) -> None:
        self._chunks = chunks
        self.closed = 0

    def iter_content(self, chunk_size: int, decode: bool) -> Any:
        assert not decode
        return self._chunks

    def close(self) -> None:
        self.closed += 1


class FakeDockerApi:
    """The low-level docker-py calls the export uses; ``events`` records them in order."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        chunks: Any = None,
        import_failure: Exception | None = None,
    ) -> None:
        self.config = SOURCE_CONFIG if config is None else config
        self.response = FakeResponse(iter(CHUNKS) if chunks is None else chunks)
        self.import_failure = import_failure
        self.events: list[str] = []
        self.created: dict[str, Any] = {}
        self.imported: dict[str, Any] = {}
        self.saved: list[str] = []
        self.removed_containers: list[str] = []
        self.removed_images: list[str] = []

    def inspect_image(self, reference: str) -> dict[str, Any]:
        self.events.append("inspect")
        return {"Config": self.config, "Id": TEMP_IMAGE_ID}

    def create_container(self, image: str, **kwargs: Any) -> dict[str, str]:
        self.events.append("create")
        self.created = {"image": image, **kwargs}
        return {"Id": "tmp-container-id"}

    def export(self, container: str) -> Iterator[bytes]:
        assert container == "tmp-container-id"
        return iter([b"fs"])

    def import_image(self, **kwargs: Any) -> str:
        self.events.append("import")
        if self.import_failure is not None:
            raise self.import_failure
        self.imported = kwargs
        return "ok"

    def _url(self, path: str, *parts: str) -> str:
        return path.format(*parts)

    def _get(self, url: str, stream: bool) -> FakeResponse:
        assert stream
        self.events.append("save")
        self.saved.append(url)
        return self.response

    def _raise_for_status(self, response: FakeResponse) -> None:
        return None

    def _get_raw_response_socket(self, response: FakeResponse) -> None:
        return None

    def _disable_socket_timeout(self, socket: None) -> None:
        return None

    def remove_container(self, container: str, **kwargs: Any) -> None:
        self.events.append("remove-container")
        self.removed_containers.append(container)

    def remove_image(self, reference: str, **kwargs: Any) -> None:
        self.events.append("remove-image")
        self.removed_images.append(reference)

    def client(self) -> Any:
        return SimpleNamespace(api=self)

    @property
    def temp_reference(self) -> str:
        return f"{self.imported['repository']}:{self.imported['tag']}"


async def drain(api: FakeDockerApi) -> list[bytes]:
    return [chunk async for chunk in image_export.export_image(api.client(), SOURCE)]


async def test_export_builds_a_sanitized_image_from_the_snapshot_image() -> None:
    api = FakeDockerApi()

    received = await drain(api)

    assert received == CHUNKS
    assert api.created["image"] == SOURCE
    assert api.created["network_disabled"] is True
    assert api.created["command"] is None
    changes = api.imported["changes"]
    assert changes == ["ENV PATH=/usr/local/bin:/usr/bin", "WORKDIR /work"]
    env_names = {c.removeprefix("ENV ").partition("=")[0] for c in changes if c.startswith("ENV ")}
    assert env_names <= images.CARRIED_ENV
    assert not any(change.startswith("LABEL") for change in changes)
    assert api.imported["stream_src"] is True


async def test_export_saves_the_temporary_image_by_id_not_by_reference() -> None:
    api = FakeDockerApi()

    await drain(api)

    assert api.imported["repository"] == image_export.EXPORT_REPOSITORY
    assert api.saved == [f"/images/{TEMP_IMAGE_ID}/get"]
    assert api.temp_reference not in api.saved[0]
    assert SOURCE not in api.saved[0]
    assert api.events.index("import") < api.events.index("inspect", 1) < api.events.index("save")


async def test_export_creates_the_temporary_container_unmanaged() -> None:
    api = FakeDockerApi()

    await drain(api)

    assert api.created["labels"] == {LABEL_MANAGED: "false", LABEL_SANDBOX_ID: ""}


async def test_export_removes_the_temporary_container_and_image() -> None:
    api = FakeDockerApi()

    await drain(api)

    assert api.removed_containers == [api.created["name"]]
    assert api.removed_images == [api.temp_reference]
    assert api.response.closed == 1


async def test_export_cleans_up_when_the_consumer_stops_early() -> None:
    api = FakeDockerApi()
    chunks = image_export.export_image(api.client(), SOURCE)

    assert await anext(chunks) == CHUNKS[0]
    await chunks.aclose()  # type: ignore[attr-defined]

    assert api.removed_containers == [api.created["name"]]
    assert api.removed_images == [api.temp_reference]
    assert api.response.closed == 1


async def test_export_cleans_up_when_the_import_fails() -> None:
    api = FakeDockerApi(import_failure=DriverError("import failed"))

    with pytest.raises(DriverError):
        await drain(api)

    assert api.removed_containers == [api.created["name"]]
    assert len(api.removed_images) == 1
    assert "save" not in api.events


async def test_export_gives_a_commandless_image_a_placeholder_command() -> None:
    api = FakeDockerApi(config={"Env": SECRET_ENV})

    await drain(api)

    assert api.created["command"] == ["/bin/true"]


async def test_export_survives_a_cleanup_failure() -> None:
    api = FakeDockerApi()

    def failing_remove(container: str, **kwargs: Any) -> None:
        raise OSError("daemon went away")

    api.remove_container = failing_remove  # type: ignore[method-assign]

    received = await drain(api)

    assert received == CHUNKS
    assert api.removed_images == [api.temp_reference]


# --- the stream close race ---------------------------------------------------------------


class BlockingChunks:
    """A chunk iterator whose ``next`` blocks until released; records what ran when."""

    def __init__(self, events: list[str]) -> None:
        self.release = threading.Event()
        self.reading = threading.Event()
        self.events = events
        self.closes = 0

    def __iter__(self) -> "BlockingChunks":
        return self

    def __next__(self) -> bytes:
        self.events.append("read-start")
        self.reading.set()
        assert self.release.wait(RELEASE_TIMEOUT_S)
        self.events.append("read-end")
        return b"late-chunk"

    def close(self) -> None:
        self.closes += 1
        self.events.append("close")


async def test_close_closes_the_response_first_then_waits_for_the_read_in_flight() -> None:
    events: list[str] = []
    blocking = BlockingChunks(events)
    api = FakeDockerApi(chunks=blocking)
    api.response.close = lambda: events.append("response-close")  # type: ignore[method-assign]
    chunks = image_export.export_image(api.client(), SOURCE)

    async def consume() -> None:
        async for _ in chunks:
            pass

    async with anyio.create_task_group() as group:
        group.start_soon(consume)
        with anyio.fail_after(RELEASE_TIMEOUT_S):
            while not blocking.reading.is_set():
                await anyio.sleep(0.01)
        group.cancel_scope.cancel()
        threading.Timer(0.2, blocking.release.set).start()

    assert events == ["read-start", "response-close", "read-end", "close"]
    assert blocking.closes == 1
    assert api.removed_images == [api.temp_reference]


def test_close_unblocks_a_stalled_read_by_closing_the_response() -> None:
    response_closed = threading.Event()
    reading = threading.Event()

    class StalledChunks:
        def __iter__(self) -> "StalledChunks":
            return self

        def __next__(self) -> bytes:
            reading.set()
            assert response_closed.wait(RELEASE_TIMEOUT_S), "close never closed the response"
            raise StopIteration

    response = FakeResponse(iter(()))
    response.close = response_closed.set  # type: ignore[method-assign]
    stream = image_export.GuardedStream(StalledChunks(), response)
    results: list[bytes | None] = []
    reader = threading.Thread(target=lambda: results.append(stream.read()))
    reader.start()
    assert reading.wait(RELEASE_TIMEOUT_S)

    stream.close()
    reader.join(RELEASE_TIMEOUT_S)

    assert not reader.is_alive()
    assert results == [None]
    assert stream.read() is None


def test_guarded_stream_close_logs_failures_and_never_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class Broken:
        def __iter__(self) -> "Broken":
            return self

        def __next__(self) -> bytes:
            raise StopIteration

        def close(self) -> None:
            raise OSError("boom")

    response = FakeResponse(iter(()))
    stream = image_export.GuardedStream(Broken(), response)

    stream.close()
    stream.close()

    assert response.closed == 1
    assert stream.read() is None
    assert "closing the export chunk iterator failed" in caplog.text


# --- real Docker -----------------------------------------------------------------------


@pytest.mark.docker
async def test_exported_tar_of_a_committed_container_has_no_secret_env() -> None:
    docker = pytest.importorskip("docker")
    try:
        client = make_client()
        client.ping()
        client.images.get("alpine:3.20")
    except Exception as exc:
        pytest.skip(f"no Docker daemon with alpine:3.20: {exc}")
    suffix = uuid.uuid4().hex[:8]
    reference = f"sandfort-snapshot-test:sanitize-{suffix}"
    loaded_tag = f"sandfort-snapshot-test:loaded-{suffix}"
    blanked_reference = f"sandfort-snapshot-test:blanked-{suffix}"
    container = client.api.create_container(
        "alpine:3.20", command=["sleep", "60"], environment={"SECRET_TOKEN": "abc"}
    )
    try:
        client.api.start(container["Id"])
        client.containers.get(container["Id"]).exec_run(["sh", "-c", "echo hi > /marker.txt"])
        # A raw docker commit keeps the value, like a snapshot taken before env blanking.
        raw_repository, raw_tag = reference.split(":")
        client.api.commit(container["Id"], repository=raw_repository, tag=raw_tag)
        committed = client.api.inspect_image(reference)["Config"]["Env"]
        assert "SECRET_TOKEN=abc" in committed  # the leak the export must not pass on
        data = b"".join([c async for c in image_export.export_image(client, reference)])
        loaded = client.images.load(data)
        assert len(loaded) == 1
        assert loaded[0].tags == []  # loaded by id: no temporary tag came back
        client.api.tag(loaded[0].id, *loaded_tag.split(":"))
        env = client.api.inspect_image(loaded_tag)["Config"].get("Env") or []
        assert not any(entry.startswith("SECRET_TOKEN") for entry in env)
        output = client.containers.run(loaded_tag, ["/bin/cat", "/marker.txt"], remove=True)
        leftovers = client.api.images(name=image_export.EXPORT_REPOSITORY)
        # The current commit path blanks the value: the key stays, the value is empty.
        await images.commit_container(client, container["Id"], blanked_reference)
        blanked = client.api.inspect_image(blanked_reference)["Config"]["Env"]
    finally:
        client.api.remove_container(container["Id"], v=True, force=True)
        for name in (reference, loaded_tag, blanked_reference):
            with contextlib.suppress(docker.errors.NotFound):
                client.api.remove_image(name, force=True)
    assert output.strip() == b"hi"
    assert leftovers == []
    assert "SECRET_TOKEN=" in blanked
    assert not any(entry.startswith("SECRET_TOKEN=abc") for entry in blanked)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        assert "manifest.json" in archive.getnames()
        manifest = json.load(archive.extractfile("manifest.json"))  # type: ignore[arg-type]
    repo_tags = [tag for entry in manifest for tag in entry.get("RepoTags") or []]
    assert not any(tag.startswith(image_export.EXPORT_REPOSITORY) for tag in repo_tags)
