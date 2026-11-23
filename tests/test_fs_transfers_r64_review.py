# ruff: noqa: F401, F811
"""Round 64 review: ranged and HEAD downloads, audit rows, If-Range, empty files, streamed
overflow text, the SDK path-kind order, the CLI's single stat and the PTY cleanup log level."""

import logging
import os
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import requests
import respx
from fastapi import FastAPI
from tests.test_fs_transfers_r64 import (
    BASE,
    CONTENT,
    DOWNLOAD_URL,
    PATH,
    SID,
    call,
    fetch,
    sdk_api,
    sdk_box,
    stored,
)
from tests.test_toolbox_fs import (
    app,
    audit_events,
    auth,
    client,
    create_sandbox,
    driver,
    failed,
    fs_path,
    key,
    org_id,
    out,
    script,
    upload,
)

from sandfort.api.routes.toolbox import fs as fs_routes
from sandfort.drivers.fake import FakeDriver
from sandfort.errors import PayloadTooLarge
from sandfort.toolbox import fs as fs_toolbox
from sandfort.toolbox.fs import FileDownload
from sandfort.toolbox.fs_range import RangeNotSatisfiable, parse_range
from sandfort.toolbox.fs_transfer import tar_upload_stream

MTIME = 1_700_000_000
SIZE = len(CONTENT)
FILE_MODE = 0o100644
DIR_MODE = 0o040755


def stat_record(mode: int, size: int, name: str) -> str:
    return f"{mode:x}|{size}|{MTIME}|{name}\n"


def script_stat(driver: FakeDriver, path: str, mode: int, size: int) -> Any:
    """Answer ``stat`` from now on (after the upload, which stats the file itself)."""
    return script(driver, stat=out(stat_record(mode, size, path)))


def forbid_archive(driver: FakeDriver, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    opened: list[str] = []

    async def refused(ref: str, path: str) -> Any:
        opened.append(path)
        raise AssertionError("HEAD must not open the archive")

    monkeypatch.setattr(driver, "get_archive_with_stat", refused)
    return opened


@pytest.fixture
def mtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fake archive stat has no mtime; give GET the one the scripted stat reports."""
    monkeypatch.setattr(fs_toolbox, "parse_stat_mtime", lambda _stat: float(MTIME))


# --- 1: huge digit runs ---------------------------------------------------------------------

NINES = "9" * 5000


@pytest.mark.parametrize(
    ("spec", "status", "first", "last"),
    [
        ("bytes=0-" + "9" * 4400, 206, 0, SIZE - 1),
        ("bytes=-" + NINES, 206, 0, SIZE - 1),
        ("bytes=" + NINES + "-", 416, 0, 0),
        ("bytes=" + NINES + "-" + NINES, 416, 0, 0),
        ("bytes=" + "0" * 5000 + "5-6", 206, 5, 6),
        ("bytes=5-" + "0" * 5000 + "6", 206, 5, 6),
    ],
)
@pytest.mark.parametrize("method", ["GET", "HEAD"])
async def test_huge_digit_runs_in_a_range_never_become_a_500(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    method: str,
    spec: str,
    status: int,
    first: int,
    last: int,
) -> None:
    sandbox_id = await stored(client, key)
    script_stat(driver, PATH, FILE_MODE, SIZE)

    response = await fetch(client, key, sandbox_id, method=method, Range=spec)

    assert response.status_code == status, response.text
    if status == 206:
        assert response.headers["content-range"] == f"bytes {first}-{last}/{SIZE}"
    else:
        assert response.headers["content-range"] == f"bytes */{SIZE}"


class Download(FileDownload):
    """A FileDownload that counts its closes."""

    closes = 0

    async def close(self) -> None:
        type(self).closes += 1


async def _nothing() -> AsyncIterator[bytes]:
    return
    yield b""


@pytest.mark.parametrize("head", [False, True])
async def test_the_download_is_closed_when_range_parsing_fails_unexpectedly(
    monkeypatch: pytest.MonkeyPatch, head: bool
) -> None:
    def broken(header: str | None, size: int) -> None:
        raise ValueError("boom")

    monkeypatch.setattr(fs_routes, "parse_range", broken)
    Download.closes = 0
    download = Download("/f", "f", "file", 10, _nothing(), _nothing(), None)
    request = SimpleNamespace(headers={"range": "bytes=0-1"}, state=SimpleNamespace())

    with pytest.raises(ValueError, match="boom"):
        await fs_routes._serve_download(request, download, head=head)  # type: ignore[arg-type]

    assert Download.closes == 1


# --- 2: audit rows tell GET from HEAD and carry the range -----------------------------------


async def download_rows(app: FastAPI, org_id: str) -> list[dict[str, Any]]:
    events = await audit_events(app, org_id)
    return [dict(e.details) for e in events if e.action == "toolbox.fs.download"]


async def test_audit_rows_name_the_method_and_the_range(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str, driver: FakeDriver
) -> None:
    sandbox_id = await stored(client, key)
    script_stat(driver, PATH, FILE_MODE, SIZE)
    await fetch(client, key, sandbox_id)
    await fetch(client, key, sandbox_id, Range="bytes=10-19")
    await fetch(client, key, sandbox_id, method="HEAD")
    await fetch(client, key, sandbox_id, method="HEAD", Range="bytes=200-")

    rows = await download_rows(app, org_id)

    assert [(r["method"], r.get("range")) for r in rows] == [
        ("GET", None),
        ("GET", "bytes=10-19"),
        ("HEAD", None),
        ("HEAD", "bytes=200-"),
    ]
    assert all(r["path"] == PATH and r["inline"] is False for r in rows)


async def test_a_long_range_is_truncated_in_the_audit_row(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    sandbox_id = await stored(client, key)
    await fetch(client, key, sandbox_id, Range="bytes=0-" + "9" * 400)

    (row,) = await download_rows(app, org_id)

    assert row["range"] == ("bytes=0-" + "9" * 400)[:100]


# --- 3: HEAD stats; it never opens the archive ----------------------------------------------


async def test_head_of_a_file_does_not_open_the_archive(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    mtime: None,
) -> None:
    sandbox_id = await stored(client, key)
    get = await fetch(client, key, sandbox_id)
    handler = script_stat(driver, PATH, FILE_MODE, SIZE)
    opened = forbid_archive(driver, monkeypatch)

    head = await fetch(client, key, sandbox_id, method="HEAD")

    assert head.status_code == 200
    assert opened == []
    assert handler.argvs("stat")
    for name in ("content-length", "etag", "accept-ranges", "content-disposition"):
        assert head.headers[name] == get.headers[name], name


async def test_head_of_a_range_is_computed_from_the_stat_size(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox_id = await stored(client, key)
    script_stat(driver, PATH, FILE_MODE, SIZE)
    forbid_archive(driver, monkeypatch)

    partial = await fetch(client, key, sandbox_id, method="HEAD", Range="bytes=10-19")
    refused = await fetch(client, key, sandbox_id, method="HEAD", Range="bytes=100-")

    assert (partial.status_code, partial.headers["content-range"]) == (206, f"bytes 10-19/{SIZE}")
    assert partial.headers["content-length"] == "10"
    assert (refused.status_code, refused.headers["content-range"]) == (416, f"bytes */{SIZE}")


async def test_head_of_a_directory_needs_no_archive(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox_id = await stored(client, key)
    script_stat(driver, "/work", DIR_MODE, 4096)
    opened = forbid_archive(driver, monkeypatch)

    head = await client.head(
        fs_path(sandbox_id, "download"), headers=auth(key), params={"path": "/work"}
    )

    assert head.status_code == 200
    assert opened == []
    assert head.headers["accept-ranges"] == "none"
    assert "content-length" not in head.headers
    assert head.headers["content-disposition"].endswith("work.tar")


async def test_head_of_a_missing_path_is_404_from_the_stat(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    script(driver, stat=failed("stat: cannot stat '/work/data.bin': No such file or directory"))

    head = await fetch(client, key, sandbox_id, method="HEAD")

    assert head.status_code == 404


# --- 4: If-Range ----------------------------------------------------------------------------


async def test_if_range_with_the_current_etag_keeps_the_range(
    client: httpx.AsyncClient, key: str, mtime: None
) -> None:
    sandbox_id = await stored(client, key)
    etag = (await fetch(client, key, sandbox_id)).headers["etag"]

    weak = await fetch(client, key, sandbox_id, Range="bytes=10-19", **{"If-Range": etag})
    strong = await fetch(
        client, key, sandbox_id, Range="bytes=10-19", **{"If-Range": etag.removeprefix("W/")}
    )

    assert weak.status_code == 206
    assert weak.content == CONTENT[10:20]
    assert strong.status_code == 206


@pytest.mark.parametrize("validator", ['W/"1-2"', '"other"', "Wed, 21 Oct 2015 07:28:00 GMT", ""])
async def test_if_range_that_does_not_match_sends_the_whole_file(
    client: httpx.AsyncClient, key: str, mtime: None, validator: str
) -> None:
    sandbox_id = await stored(client, key)

    response = await fetch(client, key, sandbox_id, Range="bytes=10-19", **{"If-Range": validator})

    assert response.status_code == 200
    assert "content-range" not in response.headers
    assert response.content == CONTENT


async def test_if_range_also_turns_an_unsatisfiable_range_into_the_whole_file(
    client: httpx.AsyncClient, key: str, mtime: None
) -> None:
    sandbox_id = await stored(client, key)

    response = await fetch(client, key, sandbox_id, Range="bytes=500-", **{"If-Range": '"old"'})

    assert response.status_code == 200
    assert response.content == CONTENT


# --- 5: the unit is case-insensitive; inner whitespace is not tolerated ----------------------


@pytest.mark.parametrize("spec", ["Bytes=10-19", "BYTES=10-19", "bYtEs=10-19", "bytes=10-19 "])
async def test_the_range_unit_is_case_insensitive(
    client: httpx.AsyncClient, key: str, spec: str
) -> None:
    sandbox_id = await stored(client, key)

    response = await fetch(client, key, sandbox_id, Range=spec)

    assert response.status_code == 206
    assert response.content == CONTENT[10:20]


@pytest.mark.parametrize("spec", ["bytes= 0 - 1", "bytes= 5-6", "bytes=5 -6", "bytes=5- 6"])
def test_inner_whitespace_makes_the_range_malformed_so_it_is_ignored(spec: str) -> None:
    assert parse_range(spec, SIZE) is None


def test_non_ascii_digits_are_not_digits() -> None:
    assert parse_range("bytes=٣-٥", SIZE) is None


# --- 6: an empty file answers 416 for any range ---------------------------------------------


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("spec", ["bytes=0-", "bytes=0-0", "bytes=-5"])
async def test_a_range_on_an_empty_file_is_416(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, method: str, spec: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    await upload(client, key, sandbox_id, "/work/empty", b"")
    script_stat(driver, "/work/empty", FILE_MODE, 0)

    response = await client.request(
        method,
        fs_path(sandbox_id, "download"),
        headers={**auth(key), "Range": spec},
        params={"path": "/work/empty"},
    )

    assert response.status_code == 416
    assert response.headers["content-range"] == "bytes */0"


async def test_an_empty_file_without_a_range_is_still_200(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    await upload(client, key, sandbox_id, "/work/empty", b"")

    response = await client.get(
        fs_path(sandbox_id, "download"), headers=auth(key), params={"path": "/work/empty"}
    )

    assert response.status_code == 200
    assert response.content == b""


def test_a_malformed_range_on_an_empty_file_is_still_ignored() -> None:
    assert parse_range("garbage", 0) is None
    with pytest.raises(RangeNotSatisfiable):
        parse_range("bytes=0-", 0)


# --- 7: SDK path kind comes before the range check -------------------------------------------


async def test_sdk_ranged_download_of_a_directory_reports_the_path_kind(
    sdk_box: Any, sdk_api: respx.MockRouter
) -> None:
    sdk_api.get(DOWNLOAD_URL).respond(
        200, content=b"tar", headers={"Content-Type": "application/x-tar"}
    )

    with pytest.raises(Exception, match="is not a file") as caught:
        await call(sdk_box.fs.download_file, "/w/dir", range=(0, 9))

    assert "ignored the range" not in str(caught.value)


# --- 8: streamed overflow names the limit like the declared one -------------------------------


async def one_chunk(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def drain(stream: AsyncIterator[bytes]) -> None:
    async for _ in stream:
        pass


async def test_a_streamed_overflow_names_the_limit_and_the_bytes_received() -> None:
    stream = tar_upload_stream(
        one_chunk(b"x" * 20), name="f", size=10, mode=0o644, mtime=0, max_bytes=10
    )

    with pytest.raises(PayloadTooLarge) as caught:
        await drain(stream)

    assert str(caught.value) == "upload limit is 10 bytes; this upload is at least 20 bytes"
    assert caught.value.details == {"limit_bytes": 10, "size_bytes": 20}


async def test_a_declared_size_over_the_cap_in_the_stream_has_the_same_shape() -> None:
    stream = tar_upload_stream(
        one_chunk(b"x"), name="f", size=20, mode=0o644, mtime=0, max_bytes=10
    )

    with pytest.raises(PayloadTooLarge) as caught:
        await drain(stream)

    assert str(caught.value) == "upload limit is 10 bytes; this upload is 20 bytes"
    assert caught.value.details == {"limit_bytes": 10, "size_bytes": 20}


# --- 9: HEAD takes the parameters of GET ------------------------------------------------------


async def test_head_accepts_and_ignores_inline_and_max_bytes(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await stored(client, key)
    script_stat(driver, PATH, FILE_MODE, SIZE)

    head = await client.head(
        fs_path(sandbox_id, "download"),
        headers=auth(key),
        params={"path": PATH, "inline": "true", "max_bytes": "5"},
    )

    assert head.status_code == 200
    assert head.headers["content-length"] == str(SIZE)
    assert head.headers["content-type"].startswith("application/octet-stream")
    assert head.content == b""


async def test_head_still_validates_max_bytes_like_get(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await stored(client, key)
    script_stat(driver, PATH, FILE_MODE, SIZE)

    head = await client.head(
        fs_path(sandbox_id, "download"),
        headers=auth(key),
        params={"path": PATH, "max_bytes": "0"},
    )

    assert head.status_code == 422


# --- 11: the pid-file cleanup logs a gone container at debug -----------------------------------

from tests.test_pty_pid_cleanup_r64 import LocalApi, LocalClient  # noqa: E402

from sandfort.drivers.docker import pty as pty_module  # noqa: E402

PTY_LOGGER = "sandfort.drivers.docker.pty"


class GoneApi(LocalApi):
    def __init__(self, error: Exception) -> None:
        super().__init__(None, running=False)  # type: ignore[arg-type]
        self.error = error

    def exec_create(self, container: str, **kwargs: Any) -> dict[str, str]:
        raise self.error


def docker_errors() -> tuple[Exception, Exception]:
    docker_module = pytest.importorskip("docker")
    response = requests.Response()
    response.status_code = 409
    response.reason = "Conflict"
    response._content = b'{"message": "Container is not running"}'
    return (
        docker_module.errors.NotFound("no such container"),
        docker_module.errors.APIError(
            "Container is not running", response=response, explanation="Container is not running"
        ),
    )


@pytest.mark.parametrize("which", [0, 1])
def test_a_stopped_or_removed_container_is_logged_at_debug(
    caplog: pytest.LogCaptureFixture, which: int
) -> None:
    api = GoneApi(docker_errors()[which])
    caplog.set_level(logging.DEBUG, logger=PTY_LOGGER)

    pty_module._remove_pid_file_blocking(LocalClient(api), "ref", "/tmp/x.pid")

    records = [r for r in caplog.records if r.name == PTY_LOGGER]
    assert records
    assert {r.levelno for r in records} == {logging.DEBUG}


def test_any_other_cleanup_failure_is_still_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    api = GoneApi(RuntimeError("daemon unreachable"))
    caplog.set_level(logging.DEBUG, logger=PTY_LOGGER)

    pty_module._remove_pid_file_blocking(LocalClient(api), "ref", "/tmp/x.pid")

    records = [r for r in caplog.records if r.name == PTY_LOGGER]
    assert [r.levelno for r in records] == [logging.WARNING]


# --- 10: cp stats the local file once --------------------------------------------------------

from sandfort_cli import cp_cmd  # noqa: E402
from sandfort_cli.main import create_app as create_cli  # noqa: E402
from typer.testing import CliRunner  # noqa: E402


class FlakyStat(type(Path())):  # type: ignore[misc]
    """A path whose stat fails the way a file deleted or locked after a check does."""

    error: OSError = FileNotFoundError(2, "No such file or directory")
    calls = 0

    def stat(self, *args: Any, **kwargs: Any) -> os.stat_result:
        type(self).calls += 1
        raise type(self).error


def test_a_local_file_is_stat_ed_once(tmp_path: Path) -> None:
    class Counting(type(Path())):  # type: ignore[misc]
        calls = 0

        def stat(self, *args: Any, **kwargs: Any) -> os.stat_result:
            type(self).calls += 1
            return super().stat(*args, **kwargs)

    source = tmp_path / "f.bin"
    source.write_bytes(b"x")

    assert cp_cmd.upload_problem(Counting(source), "/work/f.bin") is None
    assert Counting.calls == 1


def test_a_file_deleted_before_the_stat_is_the_missing_file_message(tmp_path: Path) -> None:
    FlakyStat.error = FileNotFoundError(2, "No such file or directory")

    problem = cp_cmd.upload_problem(FlakyStat(tmp_path / "gone"), "/w/x", typed="./gone")

    assert problem == "no such file: ./gone"


def test_an_unreadable_file_is_a_message_not_a_traceback(tmp_path: Path) -> None:
    FlakyStat.error = PermissionError(13, "Permission denied")

    problem = cp_cmd.upload_problem(FlakyStat(tmp_path / "locked"), "/w/x")

    assert problem is not None
    assert "Permission denied" in problem


def test_cp_exits_2_when_the_stat_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    FlakyStat.error = PermissionError(13, "Permission denied")
    real = Path(tmp_path / "f.bin")
    real.write_bytes(b"x")
    monkeypatch.setattr(cp_cmd, "Path", FlakyStat)

    result = CliRunner().invoke(create_cli(), ["cp", str(real), f"{SID}:/work/f.bin"])

    assert result.exit_code == 2, result.output
    assert "Permission denied" in result.stderr
    assert "Traceback" not in result.output
