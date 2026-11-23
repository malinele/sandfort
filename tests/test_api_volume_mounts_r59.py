"""Round 59 (persona deepa): mount reporting and three error-quality items.

1. The sandbox view reports ``read_only`` for every mount.
2. The 503 CAPACITY body no longer carries the host-wide reserved totals.
3. A put into a read-only mount is 409 READ_ONLY_PATH, not an opaque 502 DRIVER_ERROR.
4. A file download carries Content-Length (size known) and a weak ETag (size and mtime known).

Daemon-free: the docker-py failures are built by hand, the download goes through the app on the
fake driver and a temp SQLite database.
"""

import errno
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.errors import error_response
from sandfort.api.routes.toolbox.fs import _download_response
from sandfort.api.schemas.sandboxes import sandbox_response
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.quota import Reservation
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.docker import archive
from sandfort.drivers.docker.client import DriverReadOnlyPath, map_driver_error
from sandfort.drivers.errors import DriverError
from sandfort.errors import CapacityExceeded
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.admission import AdmissionService
from sandfort.services.volumes import VolumeMount, encode_mounts
from sandfort.toolbox.fs import FileDownload, FsToolbox, parse_stat_mtime

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
READ_ONLY_TEXT = "mounted volume is marked read-only"


# --- 1. read_only in the sandbox view ----------------------------------------------------


def _sandbox(mounts: tuple[VolumeMount, ...]) -> Sandbox:
    return Sandbox(
        id="sbx_view",
        org_id="org_view",
        name="view",
        state=SandboxState.STARTED,
        image_ref="alpine:3.20",
        driver="fake",
        labels=encode_mounts(mounts),
        created_at=NOW,
        updated_at=NOW,
    )


def test_view_reports_read_only_true_and_false_per_mount() -> None:
    sandbox = _sandbox(
        (
            VolumeMount("vol_a", "sf-vol-a", "/ro", read_only=True),
            VolumeMount("vol_b", "sf-vol-b", "/rw"),
        )
    )

    view = sandbox_response(sandbox)

    by_path = {mount.mount_path: mount for mount in view.volumes}
    assert by_path["/ro"].read_only is True
    assert by_path["/rw"].read_only is False
    dumped = view.model_dump(mode="json")["volumes"]
    flags = {item["mount_path"]: item["read_only"] for item in dumped}
    assert flags == {"/ro": True, "/rw": False}


# --- 2. the 503 CAPACITY body ------------------------------------------------------------


@dataclass
class _Quotas:
    totals: Reservation

    async def ledger_recount(self, org_id: str) -> Reservation:
        return self.totals

    async def host_totals(self) -> Reservation:
        return self.totals


@dataclass
class _Uow:
    quotas: _Quotas


async def _capacity_error() -> CapacityExceeded:
    settings = Settings(
        driver="fake",
        database_url="sqlite+aiosqlite:///unused.db",
        api_key_pepper=PEPPER,
        host_capacity_cpu_millicores=2000,
        host_capacity_memory_mib=4096,
    )
    held = Reservation(vcpus=1.5, memory_mib=3000, disk_gib=10, sandboxes=3)
    wanted = Reservation(vcpus=1.0, memory_mib=512, disk_gib=1, sandboxes=1)
    uow: Any = _Uow(_Quotas(held))
    with pytest.raises(CapacityExceeded) as raised:
        await AdmissionService(settings).admit(uow, wanted)
    return raised.value


async def test_capacity_details_hide_the_host_totals() -> None:
    error = await _capacity_error()

    assert error.message == "host capacity exhausted"
    assert "host_reserved" not in error.details
    assert error.details["host_full"] is True
    assert error.details["requested"] == {
        "vcpus": 1.0,
        "memory_mib": 512,
        "disk_gib": 1,
        "sandboxes": 1,
    }
    assert set(error.details) == {"requested", "host_full"}


async def test_capacity_totals_are_logged_server_side_at_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="sandfort.services.admission"):
        await _capacity_error()

    records = [r for r in caplog.records if r.name == "sandfort.services.admission"]
    assert records and all(r.levelno == logging.WARNING for r in records)
    assert "3000" in records[0].getMessage()  # the reserved memory total


async def test_capacity_response_body_has_no_host_reserved_key() -> None:
    response = error_response(await _capacity_error())

    body = json.loads(bytes(response.body))
    assert response.status_code == 503
    assert "host_reserved" not in body["error"]["details"]
    assert body["error"]["details"]["host_full"] is True


# --- 3. upload into a read-only mount ----------------------------------------------------


def _api_error(text: str) -> Exception:
    docker_errors = pytest.importorskip("docker.errors")
    return docker_errors.APIError("daemon said no", explanation=text)  # type: ignore[no-any-return]


@pytest.mark.parametrize(
    "text", ["Error: read-only file system", "mounted volume is marked read-only"]
)
def test_daemon_read_only_text_maps_to_the_distinct_error(text: str) -> None:
    mapped = map_driver_error(_api_error(text), "ref", "archive.put")

    assert isinstance(mapped, DriverReadOnlyPath)


def test_erofs_errno_maps_to_the_distinct_error() -> None:
    pytest.importorskip("docker.errors")

    # The text carries no read-only marker, so only the errno can identify the failure.
    mapped = map_driver_error(OSError(errno.EROFS, "denied"), "ref", "archive.put")

    assert isinstance(mapped, DriverReadOnlyPath)


def test_read_only_text_on_another_operation_stays_generic() -> None:
    mapped = map_driver_error(_api_error("read-only file system"), "ref", "container.start")

    assert type(mapped) is DriverError


async def _no_chunks() -> AsyncIterator[bytes]:
    return
    yield b""


def _put_failure(text: str, dest: str) -> DriverReadOnlyPath:
    api_error = _api_error(text)

    class Api:
        def put_archive(self, ref: str, dest_path: str, source: Any) -> bool:
            raise api_error

    class Client:
        api = Api()

    source = archive._BlockingSource(_no_chunks())
    with pytest.raises(DriverReadOnlyPath) as raised:
        archive._put_blocking(Client(), "ref", dest, source)
    return raised.value


def test_put_archive_names_the_destination_path() -> None:
    error = _put_failure("read-only file system", "/data/ro")

    assert error.path == "/data/ro"
    assert "/data/ro" in error.message
    assert "read-only" in error.message


def test_put_archive_sanitises_the_path_echo() -> None:
    error = _put_failure(READ_ONLY_TEXT, "/data/\x1b[31m\nro/" + "x" * 1000)

    assert "\x1b" not in error.message and "\n" not in error.message
    assert len(error.message) < 600


def test_read_only_error_is_409_read_only_path_with_the_path() -> None:
    error = DriverReadOnlyPath.for_path("/data/ro", ref="ref")

    response = error_response(error)

    body = json.loads(bytes(response.body))
    assert response.status_code == 409
    assert body["error"]["code"] == "READ_ONLY_PATH"
    assert "/data/ro" in body["error"]["message"]
    assert body["error"]["details"] == {"path": "/data/ro"}


def test_plain_driver_error_is_still_502() -> None:
    response = error_response(DriverError("boom"))

    assert response.status_code == 502
    assert json.loads(bytes(response.body))["error"]["code"] == "DRIVER_ERROR"


# --- 4. Content-Length and ETag on a file download ---------------------------------------


async def _stream() -> AsyncIterator[bytes]:
    yield b"hello"


def _download(size: int, kind: str = "file", mtime: float | None = None) -> FileDownload:
    stream = _stream()
    if kind == "file":
        return FileDownload("/w/a.txt", "a.txt", "file", size, stream, stream, mtime)
    return FileDownload("/w", "w", "dir", size, stream, stream, mtime)


def test_known_size_sets_content_length() -> None:
    response = _download_response(_download(5))

    assert response.headers["content-length"] == "5"


def test_size_and_mtime_make_a_weak_etag() -> None:
    first = _download_response(_download(5, mtime=1761825600.0)).headers["etag"]
    other_time = _download_response(_download(5, mtime=1761825601.0)).headers["etag"]
    other_size = _download_response(_download(6, mtime=1761825600.0)).headers["etag"]

    assert first.startswith('W/"') and first.endswith('"')
    assert len({first, other_time, other_size}) == 3


def test_etag_absent_without_mtime() -> None:
    response = _download_response(_download(5))

    assert "etag" not in response.headers
    assert response.headers["content-length"] == "5"


def test_real_download_with_mtime_yields_etag_and_unchanged_length() -> None:
    response = _download_response(_download(5, mtime=1761825600.0))

    assert response.headers["etag"] == f'W/"{5:x}-{1761825600:x}"'
    assert response.headers["content-length"] == "5"


def test_file_download_mtime_defaults_to_none() -> None:
    stream = _stream()

    assert FileDownload("/w/a.txt", "a.txt", "file", 5, stream, stream).mtime is None


class _StatDriver:
    def __init__(self, stat: dict[str, Any]) -> None:
        self._stat = stat

    async def get_archive_with_stat(
        self, ref: str, path: str
    ) -> tuple[dict[str, Any], AsyncIterator[bytes]]:
        return self._stat, _stream()


async def _opened(stat: dict[str, Any]) -> FileDownload:
    toolbox: Any = FsToolbox(None, None, None)  # type: ignore[arg-type]
    toolbox._archive_driver = lambda: _StatDriver(stat)
    sandbox: Any = SimpleNamespace(driver_ref="c1")
    download: FileDownload = await toolbox._open_download(sandbox, "/w/a.txt")
    return download


async def test_open_download_fills_mtime_from_the_stat() -> None:
    stat = {"size": 5, "mode": 0o644, "mtime": "2025-10-30T12:00:00Z"}

    download = await _opened(stat)

    assert download.mtime == 1761825600.0
    assert _download_response(download).headers["etag"] == f'W/"{5:x}-{1761825600:x}"'


async def test_open_download_without_stat_mtime_has_none() -> None:
    download = await _opened({"size": 5, "mode": 0o644})

    assert download.mtime is None
    assert "etag" not in _download_response(download).headers


def test_stat_mtime_parsing() -> None:
    assert parse_stat_mtime({"mtime": "2025-10-30T12:00:00Z"}) == 1761825600.0
    assert parse_stat_mtime({"mtime": "2025-10-30T12:00:00.5123456789Z"}) == pytest.approx(
        1761825600.5123, abs=1e-3
    )
    assert parse_stat_mtime({"mtime": 1761825600}) == 1761825600.0
    assert parse_stat_mtime({"mtime": "not a time"}) is None
    assert parse_stat_mtime({"mtime": True}) is None
    assert parse_stat_mtime({}) is None


def test_unknown_size_sets_neither_header() -> None:
    response = _download_response(_download(0, mtime=1761825600.0))

    assert "content-length" not in response.headers
    assert "etag" not in response.headers


def test_directory_tar_has_no_content_length_or_etag() -> None:
    response = _download_response(_download(4096, kind="dir", mtime=1761825600.0))

    assert "content-length" not in response.headers
    assert "etag" not in response.headers


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'r59.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield application
    finally:
        await application.state.engine.dispose()


async def _key(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def test_download_over_http_carries_content_length(app: FastAPI) -> None:
    key = await _key(app)
    headers = {"Authorization": f"Bearer {key}"}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post(BASE, headers=headers, json={})
        assert created.status_code == 201, created.text
        sandbox_id = created.json()["data"]["id"]
        fs = f"{BASE}/{sandbox_id}/toolbox/fs"
        put = await client.put(
            f"{fs}/upload", headers=headers, params={"path": "/a.bin"}, content=b"x" * 123
        )
        assert put.status_code == 200, put.text

        response = await client.get(f"{fs}/download", headers=headers, params={"path": "/a.bin"})

    assert response.status_code == 200
    assert response.content == b"x" * 123
    assert response.headers["content-length"] == "123"
