"""Filesystem toolbox primitives against a real local daemon (skipped when none is reachable).

Runs on gnu coreutils (debian) and busybox (alpine): the same exec argv lists, stat/find
parsers and streaming tar helpers the ``/fs`` routes use, driven through ``DockerDriver``.
"""

import contextlib
import io
import tarfile
import uuid
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest

from sandfort.config import Settings
from sandfort.domain.resources import ResourceSpec
from sandfort.drivers.base import ExecRequest, SandboxSpec
from sandfort.drivers.docker.archive import CHUNK_BYTES
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.toolbox.fs_parse import (
    VARIANTS,
    FsEntry,
    StatVariant,
    list_argv,
    parse_stat_output,
    stat_argv,
)
from sandfort.toolbox.fs_transfer import archive_kind, extract_file, tar_upload_stream

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

IMAGES = ["alpine:3.20", "debian:bookworm-slim"]
DATA_DIR = "/tmp/sf-fs/data"
FILE_PATH = f"{DATA_DIR}/hello.bin"
MOVED_PATH = f"{DATA_DIR}/moved.bin"
UPLOAD_MTIME = 1761825600


@pytest.fixture(scope="module")
def client() -> Any:
    try:
        docker_client = make_client()
        docker_client.ping()
    except Exception as exc:
        pytest.skip(f"no reachable Docker daemon: {exc}")
    return docker_client


@pytest.fixture(params=IMAGES)
def image(client: Any, request: pytest.FixtureRequest) -> str:
    name: str = request.param
    try:
        client.images.get(name)
    except docker.errors.ImageNotFound:
        try:
            client.images.pull(name)
        except Exception as exc:
            pytest.skip(f"cannot pull {name}: {exc}")
    return name


@pytest.fixture
def driver(client: Any) -> DockerDriver:
    return DockerDriver(Settings(), client=client)


def make_spec(image: str) -> SandboxSpec:
    token = uuid.uuid4().hex[:10]
    return SandboxSpec(
        sandbox_id=f"sbx_t{token}",
        org_id=f"org_t{token}",
        name=f"sf-sbx_t{token}",
        image=image,
        resources=ResourceSpec(cpu_millicores=1000, memory_mib=512, disk_gib=1),
        labels={"suite": "test_docker_fs"},
    )


def force_remove(client: Any, ref: str) -> None:
    with contextlib.suppress(docker.errors.NotFound):
        client.api.remove_container(ref, v=True, force=True)


async def run(driver: DockerDriver, ref: str, *argv: str) -> None:
    result = await driver.exec(ref, ExecRequest(argv=list(argv)))
    assert result.exit_code == 0, result.stderr.decode()


async def probe(
    driver: DockerDriver,
    ref: str,
    argv_for: Callable[[StatVariant], list[str]],
    directory: str | None = None,
) -> list[FsEntry]:
    """Run a stat-based command with the same variant fallback the service uses."""
    for variant in VARIANTS:
        result = await driver.exec(ref, ExecRequest(argv=argv_for(variant)))
        if result.exit_code == 0:
            return parse_stat_output(result.stdout, variant, directory=directory)
    raise AssertionError("no stat variant produced output")


async def list_data_dir(driver: DockerDriver, ref: str) -> list[FsEntry]:
    return await probe(driver, ref, lambda v: list_argv(DATA_DIR, v), DATA_DIR)


async def upload(driver: DockerDriver, ref: str, path: str, payload: bytes) -> None:
    parent, _, name = path.rpartition("/")

    async def body() -> AsyncIterator[bytes]:
        yield payload

    stream = tar_upload_stream(
        body(),
        name=name,
        size=len(payload),
        mode=0o640,
        mtime=UPLOAD_MTIME,
        max_bytes=len(payload),
    )
    await driver.put_archive(ref, parent, stream)


async def test_fs_round_trip_on_a_real_container(
    client: Any, driver: DockerDriver, image: str
) -> None:
    ref = ""
    try:
        info = await driver.create(make_spec(image))
        ref = info.ref
        await driver.start(ref)
        payload = bytes(range(256)) * 4096 + b"tail"  # just over 1 MiB, so it spans chunks
        assert len(payload) > CHUNK_BYTES

        await run(driver, ref, "mkdir", "-m", "755", "-p", DATA_DIR)

        await upload(driver, ref, FILE_PATH, payload)
        [stat_entry] = await probe(driver, ref, lambda v: stat_argv(FILE_PATH, v))
        assert (stat_entry.name, stat_entry.kind) == ("hello.bin", "file")
        assert stat_entry.size_bytes == len(payload)
        assert stat_entry.mode == 0o640
        assert stat_entry.mtime == UPLOAD_MTIME

        listing = await list_data_dir(driver, ref)
        assert [(e.name, e.path, e.kind) for e in listing] == [("hello.bin", FILE_PATH, "file")]

        stat, chunks = await driver.get_archive_with_stat(ref, FILE_PATH)
        assert archive_kind(stat) == "file"
        pieces = [piece async for piece in extract_file(chunks)]
        assert b"".join(pieces) == payload
        assert max(len(piece) for piece in pieces) <= CHUNK_BYTES

        dir_stat, dir_chunks = await driver.get_archive_with_stat(ref, DATA_DIR)
        assert archive_kind(dir_stat) == "dir"
        raw = b"".join([chunk async for chunk in dir_chunks])
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            assert "data/hello.bin" in archive.getnames()

        await run(driver, ref, "mv", FILE_PATH, MOVED_PATH)
        assert [e.name for e in await list_data_dir(driver, ref)] == ["moved.bin"]

        await run(driver, ref, "rm", "-r", MOVED_PATH)
        assert await list_data_dir(driver, ref) == []
    finally:
        if ref:
            force_remove(client, ref)
