"""SDK r67: ``client.volumes.export`` streams a volume to a file and ``client.volumes.restore``
uploads a gzipped tar (sync, plus async cases)."""

import io
import json
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    AsyncClient,
    Client,
    Conflict,
    NotFound,
    PayloadTooLarge,
    TransportError,
    Unprocessable,
    VolumeRestore,
)
from sandfort_sdk._transport import client_kwargs  # noqa: E402
from sandfort_sdk.fs import UPLOAD_LIMIT_BYTES  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
EXPORT = "/v1/volumes/vol_1/export"
RESTORE = "/v1/volumes/vol_1/restore"
GZIP = "application/gzip"
Answer = httpx.Response | Callable[[httpx.Request], httpx.Response]


def failure(status: int, code: str, message: str, details: dict[str, Any]) -> httpx.Response:
    error = {"code": code, "message": message, "details": details, "request_id": "req_1"}
    return httpx.Response(
        status, json={"success": False, "data": None, "error": error, "meta": None}
    )


def restored(size: int = 1234) -> httpx.Response:
    data = {"volume_id": "vol_1", "name": "data", "restored_bytes": size}
    return httpx.Response(200, json={"success": True, "data": data, "error": None, "meta": None})


class BrokenStream(httpx.SyncByteStream):
    def __iter__(self) -> Iterator[bytes]:
        yield b"partial"
        raise httpx.ReadError("connection lost")


class Api:
    """A MockTransport handler: answers by (method, path) and records every request."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], Answer] = {}
        self.requests: list[httpx.Request] = []

    def on(self, method: str, path: str, answer: Answer) -> "Api":
        self.routes[(method, path)] = answer
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.routes.get((request.method, request.url.path))
        if answer is None:
            raise AssertionError(f"unexpected {request.method} {request.url.path}")
        return answer(request) if callable(answer) else answer


def sync_client(api: Api) -> Client:
    client = Client(BASE, KEY)
    client._transport._http.close()
    client._transport._http = httpx.Client(
        transport=httpx.MockTransport(api), **client_kwargs(BASE, KEY, 30.0)
    )
    return client


async def async_client(api: Api) -> AsyncClient:
    client = AsyncClient(BASE, KEY)
    await client._transport._http.aclose()
    client._transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(api), **client_kwargs(BASE, KEY, 30.0)
    )
    return client


def archive_response(chunks: list[bytes]) -> httpx.Response:
    return httpx.Response(200, content=iter(chunks), headers={"Content-Type": GZIP})


# --- export ------------------------------------------------------------------------------------


def test_export_writes_the_streamed_bytes_and_returns_the_count(tmp_path: Path) -> None:
    chunks = [b"a" * 1000, b"b" * 500, b"c"]
    api = Api().on("GET", EXPORT, archive_response(chunks))
    target = tmp_path / "data.tar.gz"

    written = sync_client(api).volumes.export("vol_1", target)

    assert written == 1501
    assert target.read_bytes() == b"".join(chunks)
    assert api.requests[0].headers["Accept"] == GZIP


def test_export_of_an_unknown_volume_raises_and_writes_nothing(tmp_path: Path) -> None:
    api = Api().on("GET", EXPORT, failure(404, "NOT_FOUND", "no such volume", {}))
    target = tmp_path / "data.tar.gz"

    with pytest.raises(NotFound):
        sync_client(api).volumes.export("vol_1", str(target))

    assert not target.exists()


def test_export_answered_409_for_a_driver_without_transfer_raises_conflict(tmp_path: Path) -> None:
    details = {"reason": "unsupported_mode"}
    api = Api().on("GET", EXPORT, failure(409, "CONFLICT", "cannot export", details))

    with pytest.raises(Conflict) as caught:
        sync_client(api).volumes.export("vol_1", tmp_path / "x.tar.gz")

    assert caught.value.details["reason"] == "unsupported_mode"


def test_export_cut_off_mid_stream_removes_the_partial_file(tmp_path: Path) -> None:
    api = Api().on("GET", EXPORT, httpx.Response(200, stream=BrokenStream()))
    target = tmp_path / "data.tar.gz"

    with pytest.raises(TransportError):
        sync_client(api).volumes.export("vol_1", target)

    assert not target.exists()


async def test_async_export_writes_the_streamed_bytes(tmp_path: Path) -> None:
    api = Api().on("GET", EXPORT, httpx.Response(200, content=b"gz-bytes" * 10))
    client = await async_client(api)
    target = tmp_path / "data.tar.gz"

    written = await client.volumes.export("vol_1", target)
    await client.aclose()

    assert written == 80
    assert target.read_bytes() == b"gz-bytes" * 10


# --- restore -----------------------------------------------------------------------------------


def test_restore_uploads_a_file_and_returns_the_result(tmp_path: Path) -> None:
    source = tmp_path / "data.tar.gz"
    source.write_bytes(b"\x1f\x8b" + b"z" * 5000)
    api = Api().on("POST", RESTORE, restored(9000))

    result = sync_client(api).volumes.restore("vol_1", source)

    assert result == VolumeRestore(volume_id="vol_1", name="data", restored_bytes=9000)
    request = api.requests[0]
    assert request.content == source.read_bytes()
    assert request.headers["Content-Type"] == GZIP
    assert request.headers["Content-Length"] == "5002"


def test_restore_uploads_bytes_and_a_file_object() -> None:
    api = Api().on("POST", RESTORE, restored())
    client = sync_client(api)

    client.volumes.restore("vol_1", b"from-bytes")
    client.volumes.restore("vol_1", io.BytesIO(b"from-file-object"))

    assert [r.content for r in api.requests] == [b"from-bytes", b"from-file-object"]


def test_restore_of_a_missing_file_raises_before_any_request(tmp_path: Path) -> None:
    api = Api()

    with pytest.raises(FileNotFoundError):
        sync_client(api).volumes.restore("vol_1", tmp_path / "missing.tar.gz")

    assert api.requests == []


def test_restore_over_the_upload_limit_is_refused_before_any_request() -> None:
    api = Api()

    with pytest.raises(PayloadTooLarge):
        sync_client(api).volumes.restore(
            "vol_1", io.BytesIO(b""), size_bytes=UPLOAD_LIMIT_BYTES + 1
        )

    assert api.requests == []


def test_restore_refused_while_a_sandbox_mounts_the_volume_raises_conflict() -> None:
    details = {"reason": "in_use"}
    api = Api().on("POST", RESTORE, failure(409, "CONFLICT", "volume is mounted", details))

    with pytest.raises(Conflict) as caught:
        sync_client(api).volumes.restore("vol_1", b"x")

    assert caught.value.details["reason"] == "in_use"


def test_restore_that_failed_after_it_began_reports_that_the_volume_was_emptied() -> None:
    details = {"volume_emptied": True}
    message = "the archive is not a readable tar; the volume was emptied"
    api = Api().on("POST", RESTORE, failure(422, "UNPROCESSABLE", message, details))

    with pytest.raises(Unprocessable) as caught:
        sync_client(api).volumes.restore("vol_1", b"x")

    assert caught.value.details["volume_emptied"] is True


def test_restore_is_never_resent_after_a_lost_connection() -> None:
    attempts: list[int] = []

    def drop(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        raise httpx.ConnectError("connection lost")

    api = Api().on("POST", RESTORE, drop)

    with pytest.raises(TransportError):
        sync_client(api).volumes.restore("vol_1", b"x" * 100)

    assert len(attempts) == 1


async def test_async_restore_uploads_a_file(tmp_path: Path) -> None:
    source = tmp_path / "data.tar.gz"
    source.write_bytes(b"async-archive" * 100)
    api = Api().on("POST", RESTORE, restored(77))
    client = await async_client(api)

    result = await client.volumes.restore("vol_1", source)
    await client.aclose()

    assert result.restored_bytes == 77
    assert json.dumps(api.requests[0].headers["Content-Type"]) == json.dumps(GZIP)
    assert api.requests[0].content == source.read_bytes()
