# ruff: noqa: F401, F811
"""Review r63n: mkdir, delete and move into a read-only mount answer 409 READ_ONLY_PATH.

Upload already did; the exec-based operations surfaced the tool's stderr as 502
DRIVER_ERROR. Every operation now maps "Read-only file system" the same way.
"""

from typing import Any

import httpx
import pytest
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
    script_paths,
    send,
)

from sandfort.drivers.fake import FakeDriver

RO_DIR = "/data/ro"
STDERR_TEXTS = [
    "mkdir: cannot create directory '/data/ro/x': Read-only file system",
    "rm: can't remove '/data/ro/x': Read-only file system",
    "mv: cannot move '/work/a' to '/data/ro/x': READ-ONLY FILE SYSTEM",
]


def _assert_read_only(body: dict[str, Any], path: str) -> None:
    error = body["error"]
    assert error["code"] == "READ_ONLY_PATH"
    assert error["details"] == {"path": path}
    assert path in error["message"]
    assert "Read-only file system" not in error["message"]


@pytest.mark.parametrize("stderr", STDERR_TEXTS)
async def test_mkdir_in_a_read_only_mount_answers_409(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, stderr: str
) -> None:
    script_paths(driver, set(), mkdir=failed(stderr))
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client, "POST", fs_path(sandbox_id, "mkdir"), key, status=409, json={"path": f"{RO_DIR}/x"}
    )

    _assert_read_only(body, f"{RO_DIR}/x")


@pytest.mark.parametrize("recursive", [False, True])
async def test_delete_in_a_read_only_mount_answers_409(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, recursive: bool
) -> None:
    script_paths(driver, {f"{RO_DIR}/x"}, rm=failed(STDERR_TEXTS[1]))
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        fs_path(sandbox_id, "delete"),
        key,
        status=409,
        json={"path": f"{RO_DIR}/x", "recursive": recursive},
    )

    _assert_read_only(body, f"{RO_DIR}/x")


async def test_move_into_a_read_only_mount_names_the_destination(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    script_paths(driver, {"/work/a", RO_DIR}, mv=failed(STDERR_TEXTS[2]))
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        fs_path(sandbox_id, "move"),
        key,
        status=409,
        json={"source": "/work/a", "destination": f"{RO_DIR}/x"},
    )

    _assert_read_only(body, f"{RO_DIR}/x")


async def test_move_out_of_a_read_only_mount_names_the_source(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    stderr = "mv: cannot remove '/data/ro/a': Read-only file system"
    script_paths(driver, {f"{RO_DIR}/a", "/work"}, mv=failed(stderr))
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        fs_path(sandbox_id, "move"),
        key,
        status=409,
        json={"source": f"{RO_DIR}/a", "destination": "/work/a"},
    )

    _assert_read_only(body, f"{RO_DIR}/a")


async def test_other_failures_are_still_a_driver_error(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    script_paths(driver, set(), mkdir=failed("mkdir: cannot create directory: Permission denied"))
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client, "POST", fs_path(sandbox_id, "mkdir"), key, status=502, json={"path": "/etc/x"}
    )

    assert body["error"]["code"] == "DRIVER_ERROR"
