# ruff: noqa: F401, F811
"""Round 65: HEAD answers what GET would, for pseudo files and for a missing path."""

from typing import Any

import httpx
import pytest
from tests.test_fs_transfers_r64 import fetch
from tests.test_fs_transfers_r64_review import (
    FILE_MODE,
    PATH,
    SIZE,
    forbid_archive,
    script_stat,
)
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
)

from sandfort.drivers.errors import DriverNotFound
from sandfort.drivers.fake import FakeDriver

PSEUDO_FILES = ["/proc/version", "/dev/null", "/sys/kernel/version", "/dev/shm/x"]


def refuse_pseudo_archives(driver: FakeDriver, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Docker cannot copy a file out of a kernel pseudo-filesystem: its archive answers 404."""
    asked: list[str] = []

    async def archive(ref: str, path: str) -> Any:
        asked.append(path)
        raise DriverNotFound(f"Could not find the file {path}", ref=ref)

    monkeypatch.setattr(driver, "get_archive_with_stat", archive)
    return asked


async def request(
    client: httpx.AsyncClient, key: str, sandbox_id: str, path: str, method: str, **headers: str
) -> httpx.Response:
    return await client.request(
        method,
        fs_path(sandbox_id, "download"),
        headers={**auth(key), **headers},
        params={"path": path},
    )


@pytest.mark.parametrize("path", PSEUDO_FILES)
@pytest.mark.parametrize("headers", [{}, {"Range": "bytes=0-9"}, {"Range": "bytes=5-"}])
async def test_head_of_a_pseudo_file_answers_what_get_answers(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    headers: dict[str, str],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    script_stat(driver, path, FILE_MODE, 0)
    refuse_pseudo_archives(driver, monkeypatch)

    get = await request(client, key, sandbox_id, path, "GET", **headers)
    head = await request(client, key, sandbox_id, path, "HEAD", **headers)

    assert get.status_code == 404
    assert head.status_code == 404
    assert head.headers["content-length"] == get.headers["content-length"]
    assert "content-range" not in head.headers


async def test_head_of_an_ordinary_file_still_does_not_open_the_archive(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox_id = await create_sandbox(client, key)
    script_stat(driver, PATH, FILE_MODE, SIZE)
    opened = forbid_archive(driver, monkeypatch)

    head = await request(client, key, sandbox_id, PATH, "HEAD")

    assert head.status_code == 200
    assert opened == []


async def test_head_error_carries_the_content_length_of_the_get_error(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    script(driver, stat=failed("stat: cannot stat '/work/data.bin': No such file or directory"))

    get = await request(client, key, sandbox_id, PATH, "GET")
    head = await request(client, key, sandbox_id, PATH, "HEAD")

    assert get.status_code == head.status_code == 404
    assert head.headers["content-length"] == get.headers["content-length"]
    assert get.json()["error"]["details"] == {"path": PATH}
