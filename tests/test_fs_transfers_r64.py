# ruff: noqa: F401, F811
"""Round 64: oversize uploads are refused before the body with the limit named; downloads
answer byte ranges and HEAD.

Upload: a declared size (``Content-Length`` or ``size_bytes``) above the limit is 413
``PAYLOAD_TOO_LARGE`` at once, on every path, with the limit in the text and in the details
(``limit_bytes``, ``size_bytes``). The SDK and the CLI refuse a local file over the limit
without sending a request. Download: a single ``Range`` is answered 206 with ``Content-Range``
(416 when unsatisfiable), ``HEAD`` answers the headers alone, a directory tar has no ranges.
"""

import inspect
import json
import sys
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx
from tests.test_toolbox_fs import (
    app,
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

from sandfort.api.schemas import toolbox_fs as fs_schemas
from sandfort.drivers.fake import FakeDriver
from sandfort.toolbox import fs as fs_toolbox

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

from sandfort_cli import cp_cmd  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import AsyncClient, Client, InvalidResponseError  # noqa: E402
from sandfort_sdk import PayloadTooLarge as SdkPayloadTooLarge  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

LIMIT = 256 * 1024 * 1024
OVER = LIMIT + 1
LIMIT_TEXT = "upload limit is 256 MiB (268435456 bytes); this upload is {size} bytes"
CONTENT = b"0123456789" * 10  # 100 bytes: every offset has a distinct neighbour
PATH = "/work/data.bin"
MTIME = 1_700_000_000.0
FILE_MODE = 0o100644
DIR_MODE = 0o040755


def script_stat(driver: FakeDriver, path: str, mode: int, size: int) -> None:
    """Answer ``stat`` from now on (call after the upload, which stats the file itself)."""
    script(driver, stat=out(f"{mode:x}|{size}|{int(MTIME)}|{path}\n"))


# --- server: uploads over the limit ---------------------------------------------------------


async def put_unread(
    client: httpx.AsyncClient, key: str, sandbox_id: str, **kwargs: Any
) -> tuple[httpx.Response, list[bytes]]:
    """PUT whose body must never be pulled; returns the response and the chunks pulled."""
    pulled: list[bytes] = []

    async def body() -> AsyncIterator[bytes]:
        pulled.append(b"x")
        yield b"x"

    headers = {**auth(key), **kwargs.pop("headers", {})}
    response = await client.put(
        fs_path(sandbox_id, "upload"),
        headers=headers,
        params={"path": "/work/big.bin", **kwargs.pop("params", {})},
        content=body(),
    )
    return response, pulled


def assert_limit_refusal(response: httpx.Response, size: int, limit: int = LIMIT) -> None:
    error = response.json()["error"]
    assert response.status_code == 413, response.text
    assert error["code"] == "PAYLOAD_TOO_LARGE"
    assert error["message"] == LIMIT_TEXT.format(size=size)
    assert error["details"] == {"limit_bytes": limit, "size_bytes": size}


async def test_content_length_over_the_limit_is_413_naming_the_limit_before_the_body(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)

    response, pulled = await put_unread(
        client, key, sandbox_id, headers={"Content-Length": str(OVER)}
    )

    assert_limit_refusal(response, OVER)
    assert pulled == []


async def test_size_bytes_over_the_limit_is_the_same_413_before_the_body(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)

    response, pulled = await put_unread(client, key, sandbox_id, params={"size_bytes": str(OVER)})

    assert_limit_refusal(response, OVER)
    assert pulled == []


async def test_size_bytes_and_content_length_over_the_limit_answer_alike(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)

    response, pulled = await put_unread(
        client,
        key,
        sandbox_id,
        headers={"Content-Length": str(OVER)},
        params={"size_bytes": str(OVER)},
    )

    assert_limit_refusal(response, OVER)
    assert pulled == []


async def test_a_far_larger_size_bytes_is_still_413_with_its_size(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    size = 10**15

    response, _ = await put_unread(client, key, sandbox_id, params={"size_bytes": str(size)})

    assert_limit_refusal(response, size)


async def test_the_limit_text_follows_a_tuned_limit(
    client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fs_schemas, "MAX_UPLOAD_BYTES", 8)
    sandbox_id = await create_sandbox(client, key)

    response, _ = await put_unread(client, key, sandbox_id, headers={"Content-Length": "16"})

    error = response.json()["error"]
    assert response.status_code == 413
    assert error["message"] == "upload limit is 8 bytes; this upload is 16 bytes"
    assert error["details"] == {"limit_bytes": 8, "size_bytes": 16}


async def test_a_size_exactly_at_the_limit_is_not_refused_for_size(
    client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fs_schemas, "MAX_UPLOAD_BYTES", 8)
    sandbox_id = await create_sandbox(client, key)

    body = await upload(client, key, sandbox_id, "/work/ok.bin", b"x" * 8)

    assert body["data"]["size_bytes"] == 8


async def test_size_bytes_that_is_not_digits_is_still_422(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)

    response, _ = await put_unread(client, key, sandbox_id, params={"size_bytes": "1e9"})

    assert response.status_code == 422


# --- server: ranged downloads ---------------------------------------------------------------


async def stored(client: httpx.AsyncClient, key: str) -> str:
    sandbox_id = await create_sandbox(client, key)
    await upload(client, key, sandbox_id, PATH, CONTENT)
    return sandbox_id


async def fetch(
    client: httpx.AsyncClient, key: str, sandbox_id: str, method: str = "GET", **headers: str
) -> httpx.Response:
    return await client.request(
        method,
        fs_path(sandbox_id, "download"),
        headers={**auth(key), **headers},
        params={"path": PATH},
    )


async def test_a_plain_download_advertises_byte_ranges(client: httpx.AsyncClient, key: str) -> None:
    sandbox_id = await stored(client, key)

    response = await fetch(client, key, sandbox_id)

    assert response.status_code == 200
    assert response.headers["accept-ranges"] == "bytes"
    assert response.headers["content-length"] == str(len(CONTENT))
    assert response.content == CONTENT


@pytest.mark.parametrize(
    ("spec", "first", "last"),
    [
        ("bytes=10-19", 10, 19),
        ("bytes=0-0", 0, 0),
        ("bytes=90-", 90, 99),
        ("bytes=-5", 95, 99),
        ("bytes=-500", 0, 99),
        ("bytes=95-500", 95, 99),
        ("bytes=0-99", 0, 99),
    ],
)
async def test_a_single_range_is_206_with_the_slice(
    client: httpx.AsyncClient, key: str, spec: str, first: int, last: int
) -> None:
    sandbox_id = await stored(client, key)

    response = await fetch(client, key, sandbox_id, Range=spec)

    assert response.status_code == 206
    assert response.headers["content-range"] == f"bytes {first}-{last}/{len(CONTENT)}"
    assert response.headers["accept-ranges"] == "bytes"
    assert response.headers["content-length"] == str(last - first + 1)
    assert response.content == CONTENT[first : last + 1]


@pytest.mark.parametrize("spec", ["bytes=100-", "bytes=500-600", "bytes=-0"])
async def test_an_unsatisfiable_range_is_416_with_the_size(
    client: httpx.AsyncClient, key: str, spec: str
) -> None:
    sandbox_id = await stored(client, key)

    response = await fetch(client, key, sandbox_id, Range=spec)

    assert response.status_code == 416
    assert response.headers["content-range"] == f"bytes */{len(CONTENT)}"
    assert response.headers["accept-ranges"] == "bytes"
    assert response.json()["success"] is False


@pytest.mark.parametrize(
    "spec",
    ["bytes=0-1,5-6", "items=0-5", "bytes=9-3", "bytes=abc", "bytes=", "garbage", "bytes=--1"],
)
async def test_a_range_the_server_does_not_honour_is_ignored_with_the_full_body(
    client: httpx.AsyncClient, key: str, spec: str
) -> None:
    sandbox_id = await stored(client, key)

    response = await fetch(client, key, sandbox_id, Range=spec)

    assert response.status_code == 200
    assert "content-range" not in response.headers
    assert response.content == CONTENT


async def test_ranged_pieces_join_into_the_whole_file(client: httpx.AsyncClient, key: str) -> None:
    sandbox_id = await stored(client, key)

    first = await fetch(client, key, sandbox_id, Range="bytes=0-39")
    rest = await fetch(client, key, sandbox_id, Range="bytes=40-")

    assert first.content + rest.content == CONTENT


async def test_a_ranged_download_of_a_directory_is_the_whole_tar_without_ranges(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await stored(client, key)

    plain = await client.get(
        fs_path(sandbox_id, "download"), headers=auth(key), params={"path": "/work"}
    )
    ranged = await client.get(
        fs_path(sandbox_id, "download"),
        headers={**auth(key), "Range": "bytes=0-9"},
        params={"path": "/work"},
    )

    assert ranged.status_code == 200
    assert ranged.headers["accept-ranges"] == "none"
    assert "content-range" not in ranged.headers
    assert ranged.content == plain.content
    assert len(ranged.content) > 10


# --- server: HEAD ---------------------------------------------------------------------------


async def test_head_answers_the_headers_alone(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fs_toolbox, "parse_stat_mtime", lambda _stat: MTIME)  # GET; HEAD stats
    sandbox_id = await stored(client, key)
    get = await fetch(client, key, sandbox_id)
    script_stat(driver, PATH, FILE_MODE, len(CONTENT))

    head = await fetch(client, key, sandbox_id, method="HEAD")

    assert head.status_code == 200
    assert head.content == b""
    assert head.headers["content-length"] == str(len(CONTENT))
    assert head.headers["accept-ranges"] == "bytes"
    assert head.headers["content-disposition"] == get.headers["content-disposition"]
    assert head.headers["etag"] == get.headers["etag"]
    assert head.headers["content-type"].startswith("application/octet-stream")


async def test_head_of_a_range_answers_the_206_headers_without_a_body(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await stored(client, key)
    script_stat(driver, PATH, FILE_MODE, len(CONTENT))

    head = await fetch(client, key, sandbox_id, method="HEAD", Range="bytes=10-19")

    assert head.status_code == 206
    assert head.content == b""
    assert head.headers["content-range"] == f"bytes 10-19/{len(CONTENT)}"
    assert head.headers["content-length"] == "10"


async def test_head_of_a_missing_path_is_404(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    script(driver, stat=failed("stat: cannot stat '/work/data.bin': No such file or directory"))

    head = await fetch(client, key, sandbox_id, method="HEAD")

    assert head.status_code == 404


async def test_head_of_a_directory_has_no_ranges_and_no_length(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await stored(client, key)
    script_stat(driver, "/work", DIR_MODE, 4096)

    head = await client.head(
        fs_path(sandbox_id, "download"), headers=auth(key), params={"path": "/work"}
    )

    assert head.status_code == 200
    assert head.headers["accept-ranges"] == "none"
    assert "content-length" not in head.headers
    assert head.headers["content-disposition"].endswith("work.tar")
    assert head.content == b""


async def test_head_without_a_key_is_401(client: httpx.AsyncClient, key: str) -> None:
    sandbox_id = await stored(client, key)

    head = await client.head(fs_path(sandbox_id, "download"), params={"path": PATH})

    assert head.status_code == 401


# --- SDK: local size check and ranged download ----------------------------------------------

BASE = "http://sandfort.test"
API_KEY = "sf_test_key"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
DOWNLOAD_URL = f"/v1/sandboxes/{SID}/toolbox/fs/download"
UPLOAD_URL = f"/v1/sandboxes/{SID}/toolbox/fs/upload"
SANDBOX_BODY = {
    "id": SID,
    "name": "demo",
    "state": "started",
    "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
    "network": {"block_all": False},
}


def envelope(data: object) -> dict[str, object]:
    return {"success": True, "data": data, "error": None, "meta": None}


async def call(fn: Any, *args: Any, **kwargs: Any) -> Any:
    result = fn(*args, **kwargs)
    return await result if inspect.isawaitable(result) else result


@pytest.fixture
def sdk_api() -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        router.get(f"/v1/sandboxes/{SID}").respond(200, json=envelope(SANDBOX_BODY))
        yield router


@pytest.fixture(params=["sync", "async"])
async def sdk_box(request: pytest.FixtureRequest, sdk_api: respx.MockRouter) -> Any:
    sync = request.param == "sync"
    instance = Client(BASE, API_KEY) if sync else AsyncClient(BASE, API_KEY)
    yield await call(instance.get, SID)
    await call(instance.close if sync else instance.aclose)


class Sparse:
    """A seekable binary file of a stated length that holds no data (reads are never made)."""

    def __init__(self, size: int) -> None:
        self._size = size
        self._at = 0

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._at

    def seek(self, offset: int, whence: int = 0) -> int:
        self._at = self._size if whence == 2 else offset
        return self._at

    def read(self, _size: int = -1) -> bytes:
        raise AssertionError("an over-limit file must be refused before it is read")


async def test_sdk_refuses_a_file_object_over_the_limit_without_a_request(
    sdk_box: Any, sdk_api: respx.MockRouter
) -> None:
    route = sdk_api.put(UPLOAD_URL).respond(200, json=envelope({}))

    with pytest.raises(SdkPayloadTooLarge) as caught:
        await call(sdk_box.fs.upload_file, "/w/big", Sparse(OVER))

    assert str(caught.value) == LIMIT_TEXT.format(size=OVER)
    assert caught.value.code == "PAYLOAD_TOO_LARGE"
    assert caught.value.status_code == 413
    assert caught.value.details == {"limit_bytes": LIMIT, "size_bytes": OVER}
    assert not route.called


async def test_sdk_refuses_an_explicit_size_bytes_over_the_limit_without_a_request(
    sdk_box: Any, sdk_api: respx.MockRouter
) -> None:
    route = sdk_api.put(UPLOAD_URL).respond(200, json=envelope({}))

    with pytest.raises(SdkPayloadTooLarge) as caught:
        await call(sdk_box.fs.upload_file, "/w/big", Sparse(1), size_bytes=OVER)

    assert str(caught.value) == LIMIT_TEXT.format(size=OVER)
    assert not route.called


async def test_sdk_sends_a_file_of_exactly_the_limit_size_check(
    sdk_box: Any, sdk_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sandfort_sdk import fs as sdk_fs

    monkeypatch.setattr(sdk_fs, "UPLOAD_LIMIT_BYTES", 5)
    route = sdk_api.put(UPLOAD_URL).respond(200, json=envelope({"path": "/w/f", "size_bytes": 5}))

    result = await call(sdk_box.fs.upload_file, "/w/f", b"hello")

    assert result.size_bytes == 5
    assert route.called


def ranged_reply(request: httpx.Request) -> httpx.Response:
    spec = request.headers.get("range")
    if spec is None:
        return httpx.Response(200, content=CONTENT)
    first, _, last = spec.removeprefix("bytes=").partition("-")
    start = int(first)
    end = int(last) if last else len(CONTENT) - 1
    headers = {"Content-Range": f"bytes {start}-{end}/{len(CONTENT)}"}
    return httpx.Response(206, content=CONTENT[start : end + 1], headers=headers)


@pytest.mark.parametrize(
    ("window", "header", "expected"),
    [
        ((10, 19), "bytes=10-19", CONTENT[10:20]),
        ((40, None), "bytes=40-", CONTENT[40:]),
        ((0, 0), "bytes=0-0", CONTENT[:1]),
    ],
)
async def test_sdk_download_range_sends_one_range_and_streams_the_slice(
    sdk_box: Any,
    sdk_api: respx.MockRouter,
    window: tuple[int, int | None],
    header: str,
    expected: bytes,
) -> None:
    route = sdk_api.get(DOWNLOAD_URL).mock(side_effect=ranged_reply)

    stream = await call(sdk_box.fs.download_file, "/w/f", range=window)
    if hasattr(stream, "__aiter__"):
        body = b"".join([chunk async for chunk in stream])
    else:
        body = b"".join(stream)

    assert route.calls.last.request.headers["range"] == header
    assert body == expected


async def test_sdk_read_bytes_takes_a_range(sdk_box: Any, sdk_api: respx.MockRouter) -> None:
    sdk_api.get(DOWNLOAD_URL).mock(side_effect=ranged_reply)

    assert await call(sdk_box.fs.read_bytes, "/w/f", range=(95, None)) == CONTENT[95:]


async def test_sdk_download_without_a_range_sends_no_range_header(
    sdk_box: Any, sdk_api: respx.MockRouter
) -> None:
    route = sdk_api.get(DOWNLOAD_URL).mock(side_effect=ranged_reply)

    assert await call(sdk_box.fs.read_bytes, "/w/f") == CONTENT
    assert "range" not in route.calls.last.request.headers


async def test_sdk_refuses_a_range_the_server_ignored_instead_of_returning_a_full_body(
    sdk_box: Any, sdk_api: respx.MockRouter
) -> None:
    sdk_api.get(DOWNLOAD_URL).respond(200, content=CONTENT)

    with pytest.raises(InvalidResponseError, match="range"):
        await call(sdk_box.fs.download_file, "/w/f", range=(10, 19))


@pytest.mark.parametrize("window", [(-1, 5), (5, 4), (0, -2)])
async def test_sdk_rejects_a_malformed_range_without_a_request(
    sdk_box: Any, sdk_api: respx.MockRouter, window: tuple[int, int]
) -> None:
    route = sdk_api.get(DOWNLOAD_URL).mock(side_effect=ranged_reply)

    with pytest.raises(ValueError, match="range"):
        await call(sdk_box.fs.download_file, "/w/f", range=window)

    assert not route.called


async def test_sdk_unsatisfiable_range_raises_the_api_error(
    sdk_box: Any, sdk_api: respx.MockRouter
) -> None:
    error = {"code": "RANGE_NOT_SATISFIABLE", "message": "no such range", "details": {}}
    sdk_api.get(DOWNLOAD_URL).respond(
        416, json={"success": False, "data": None, "error": error, "meta": None}
    )

    with pytest.raises(Exception) as caught:
        await call(sdk_box.fs.download_file, "/w/f", range=(500, None))

    assert getattr(caught.value, "status_code", None) == 416


# --- CLI: cp refuses a local file over the limit before any request -------------------------


def sparse_file(path: Path, size: int) -> Path:
    with path.open("wb") as handle:
        handle.truncate(size)
    return path


def forbid_client(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    opened: list[str] = []

    @contextmanager
    def opened_client() -> Iterator[Any]:
        opened.append("open_client")
        raise AssertionError("no request may be sent for an over-limit file")
        yield  # pragma: no cover

    monkeypatch.setattr(cp_cmd, "open_client", opened_client)
    return opened


def test_cp_refuses_a_file_over_the_limit_before_any_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    big = sparse_file(tmp_path / "big.bin", OVER)
    opened = forbid_client(monkeypatch)

    result = CliRunner().invoke(create_app(), ["cp", str(big), f"{SID}:/work/big.bin"])

    assert result.exit_code == 2, result.output
    assert LIMIT_TEXT.format(size=OVER) in result.stderr
    assert opened == []


def test_cp_json_error_carries_the_limit_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    big = sparse_file(tmp_path / "big.bin", OVER)
    forbid_client(monkeypatch)

    result = CliRunner().invoke(create_app(), ["--json", "cp", str(big), f"{SID}:/work/big.bin"])

    assert result.exit_code == 2, result.output
    error = json.loads(result.stdout)["error"]
    assert error["message"] == LIMIT_TEXT.format(size=OVER)


def test_cp_of_a_file_at_the_limit_passes_the_local_check(tmp_path: Path) -> None:
    exactly = sparse_file(tmp_path / "exact.bin", LIMIT)

    cp_cmd.check_copy(str(exactly), f"{SID}:/work/exact.bin")
