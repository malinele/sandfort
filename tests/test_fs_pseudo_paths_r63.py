# ruff: noqa: F401, F811
"""Round 63: fs writes under /proc, /sys and /dev are refused, never reported as written.

Docker's archive upload (and ``mkdir``/``mv`` into a kernel pseudo-filesystem) silently
drops or fails there; the API used to answer 200 for an upload that wrote nothing. The
refusal is 422 VALIDATION_ERROR naming the path, before any driver call. Pinned decision:
``/dev/shm`` is refused too (a tmpfs, so ``docker cp`` drops the file just like /dev).
"""

from collections.abc import Mapping
from typing import Any

import httpx
import pytest
from tests.test_toolbox_fs import (
    app,
    auth,
    client,
    create_sandbox,
    driver,
    fs_path,
    key,
    org_id,
    out,
    record,
    script,
    send,
)

from sandfort.drivers.base import ExecRequest, ExecResult
from sandfort.drivers.fake import FakeDriver

PSEUDO_PATHS = [
    "/proc/x.txt",
    "/proc",
    "/proc/self/x.txt",
    "/sys/x.txt",
    "/sys/kernel/x.txt",
    "/dev/x.txt",
    "/dev/shm/x.txt",
    "/dev/pts/x",
    "/proc/../proc/x.txt",
    "/tmp/../dev/x.txt",
]
NORMAL_PATHS = ["/tmp/x.txt", "/etc/x.txt", "/root/x.txt", "/procfoo/x.txt", "/devices/x.txt"]


def _assert_refused(body: dict[str, Any], root: str) -> None:
    error = body["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert "pseudo-filesystem" in error["message"]
    assert root in error["message"]
    assert error["details"]["pseudo_filesystem"] == root


def _root_of(path: str) -> str:
    resolved = path.replace("/proc/../proc", "/proc").replace("/tmp/../dev", "/dev")
    return "/" + resolved.split("/")[1]


@pytest.mark.parametrize("path", PSEUDO_PATHS)
async def test_upload_under_a_pseudo_filesystem_is_refused_without_a_driver_call(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, path: str
) -> None:
    handler = script(driver)
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "PUT",
        fs_path(sandbox_id, "upload"),
        key,
        status=422,
        params={"path": path},
        content=b"hi",
    )

    _assert_refused(body, _root_of(path))
    assert handler.seen == []
    assert driver._get(sandbox_driver_ref(driver)).files == {}


def sandbox_driver_ref(driver: FakeDriver) -> str:
    [ref] = list(driver._instances)  # type: ignore[attr-defined]
    return ref


@pytest.mark.parametrize("path", ["/proc/x", "/sys/x", "/dev/x", "/dev/shm/x"])
async def test_mkdir_under_a_pseudo_filesystem_is_refused(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, path: str
) -> None:
    handler = script(driver)
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client, "POST", fs_path(sandbox_id, "mkdir"), key, status=422, json={"path": path}
    )

    _assert_refused(body, "/" + path.split("/")[1])
    assert handler.seen == []


@pytest.mark.parametrize("destination", ["/proc/x", "/sys/x", "/dev/x", "/dev/shm/x"])
async def test_move_into_a_pseudo_filesystem_is_refused(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, destination: str
) -> None:
    handler = script(driver)
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        fs_path(sandbox_id, "move"),
        key,
        status=422,
        json={"source": "/tmp/a", "destination": destination},
    )

    _assert_refused(body, "/" + destination.split("/")[1])
    assert handler.seen == []


@pytest.mark.parametrize("path", NORMAL_PATHS)
async def test_upload_to_a_normal_path_is_unchanged(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, path: str
) -> None:
    script(driver)
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "PUT",
        fs_path(sandbox_id, "upload"),
        key,
        status=200,
        params={"path": path},
        content=b"hi",
    )

    assert body["data"] == {"path": path, "size_bytes": 2}


async def test_reading_a_pseudo_filesystem_is_still_allowed(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    script(driver, stat=out(record(0o100444, 0, "/proc/version")))
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "GET",
        fs_path(sandbox_id, "stat"),
        key,
        status=200,
        params={"path": "/proc/version"},
    )

    assert body["data"]["entry"]["path"] == "/proc/version"


async def test_upload_the_driver_did_not_write_is_an_error_not_a_success(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    def vanished(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        if request.argv[0] == "stat":
            return ExecResult(exit_code=1, stderr=b"stat: cannot statx: No such file or directory")
        return ExecResult(exit_code=0)

    driver.exec_handler = vanished
    sandbox_id = await create_sandbox(client, key)

    response = await client.put(
        fs_path(sandbox_id, "upload"),
        headers=auth(key),
        params={"path": "/mnt/lost.txt"},
        content=b"hi",
    )

    assert response.status_code >= 400
    assert response.json()["success"] is False


async def test_upload_whose_written_size_differs_is_an_error(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    script(driver, stat=out(record(0o100644, 1, "/tmp/short.txt")))
    sandbox_id = await create_sandbox(client, key)

    response = await client.put(
        fs_path(sandbox_id, "upload"),
        headers=auth(key),
        params={"path": "/tmp/short.txt"},
        content=b"hi",
    )

    assert response.status_code >= 400
    assert response.json()["success"] is False


async def test_upload_whose_written_size_matches_succeeds(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    script(driver, stat=out(record(0o100644, 2, "/tmp/ok.txt")))
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "PUT",
        fs_path(sandbox_id, "upload"),
        key,
        status=200,
        params={"path": "/tmp/ok.txt"},
        content=b"hi",
    )

    assert body["data"]["size_bytes"] == 2
