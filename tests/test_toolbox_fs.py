"""``/v1/sandboxes/{id}/toolbox/fs``: FakeDriver, temp SQLite, httpx ASGI transport.

Daemon-free. Listing/stat/mkdir/move/delete go through exec, so the FakeDriver exec handler
is scripted per test; upload and download use the FakeDriver's in-memory archive support.
Assertions go through HTTP status codes and bodies only (the routes sit behind the app
factory, so route tables are never introspected).
"""

import io
import tarfile
from collections.abc import AsyncIterator, Collection, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.schemas import toolbox_fs as fs_schemas
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.base import ExecRequest, ExecResult
from sandfort.drivers.docker.client import DISK_FULL_MESSAGE
from sandfort.drivers.errors import DriverConflict, DriverError, DriverNotFound
from sandfort.drivers.fake import FakeDriver
from sandfort.errors import PayloadTooLarge, Unprocessable
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.toolbox.fs_parse import VARIANTS, FsParseError, parse_stat_output
from sandfort.toolbox.fs_transfer import CHUNK_BYTES, extract_file, tar_upload_stream
from sandfort.toolbox.paths import normalize_path

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
MTIME = 1761825600
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
HEX_FORMAT, SYMBOLIC_FORMAT = VARIANTS[0], VARIANTS[1]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'fs.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


async def add_org(app: FastAPI, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def add_key(app: FastAPI, org_id: str, scopes: frozenset[Scope]) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "acme")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id, FULL_ACCESS)


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def send(
    client: httpx.AsyncClient, method: str, path: str, key: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    response = await client.request(method, path, headers=auth(key), **kwargs)
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    assert body["success"] is (status < 400)
    return body


async def create_sandbox(client: httpx.AsyncClient, key: str) -> str:
    body = await send(client, "POST", BASE, key, status=201, json={})
    sandbox_id: str = body["data"]["id"]
    return sandbox_id


def fs_path(sandbox_id: str, action: str) -> str:
    return f"{BASE}/{sandbox_id}/toolbox/fs/{action}"


async def upload(
    client: httpx.AsyncClient, key: str, sandbox_id: str, path: str, content: bytes
) -> dict[str, Any]:
    return await send(
        client,
        "PUT",
        fs_path(sandbox_id, "upload"),
        key,
        status=200,
        params={"path": path},
        content=content,
    )


async def download(
    client: httpx.AsyncClient, key: str, sandbox_id: str, path: str
) -> httpx.Response:
    return await client.get(
        fs_path(sandbox_id, "download"), headers=auth(key), params={"path": path}
    )


async def get_ok(
    client: httpx.AsyncClient, key: str, sandbox_id: str, action: str, path: str
) -> dict[str, Any]:
    return await send(
        client, "GET", fs_path(sandbox_id, action), key, status=200, params={"path": path}
    )


def record(mode: int, size: int, name: str) -> str:
    return f"{mode:x}|{size}|{MTIME}|{name}\n"


class ScriptedExec:
    """FakeDriver exec handler: canned results by command name, every request recorded."""

    def __init__(self, **results: ExecResult) -> None:
        self.results = results
        self.seen: list[ExecRequest] = []

    def __call__(self, env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        self.seen.append(request)
        return self.results.get(request.argv[0], ExecResult(exit_code=0))

    def argvs(self, command_name: str) -> list[list[str]]:
        return [list(r.argv) for r in self.seen if r.argv[0] == command_name]


class PathAwareExec(ScriptedExec):
    """ScriptedExec whose ``test -e PATH`` succeeds only for the paths in ``present``."""

    def __init__(self, present: Collection[str], **results: ExecResult) -> None:
        super().__init__(**results)
        self.present = frozenset(present)

    def __call__(self, env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        if list(request.argv[:2]) != ["test", "-e"]:
            return super().__call__(env, request)
        self.seen.append(request)
        return ExecResult(exit_code=0 if request.argv[2] in self.present else 1)


def script(driver: FakeDriver, **results: ExecResult) -> ScriptedExec:
    handler = ScriptedExec(**results)
    driver.exec_handler = handler
    return handler


def script_paths(
    driver: FakeDriver, present: Collection[str], **results: ExecResult
) -> PathAwareExec:
    handler = PathAwareExec(present, **results)
    driver.exec_handler = handler
    return handler


def out(text: str) -> ExecResult:
    return ExecResult(exit_code=0, stdout=text.encode())


def failed(stderr: str) -> ExecResult:
    return ExecResult(exit_code=1, stderr=stderr.encode())


async def audit_events(app: FastAPI, org_id: str) -> list[Any]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, limit=200))


# --- auth, scoping -----------------------------------------------------------------


async def test_unauthenticated_request_is_rejected(client: httpx.AsyncClient) -> None:
    response = await client.get(fs_path("sbx_missing", "list"))

    assert response.status_code == 401
    assert response.json()["success"] is False


async def test_foreign_org_gets_not_found(
    app: FastAPI, client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    handler = script(driver)
    sandbox_id = await create_sandbox(client, key)
    other = await add_key(app, await add_org(app, "globex"), FULL_ACCESS)

    body = await send(
        client, "GET", fs_path(sandbox_id, "stat"), other, status=404, params={"path": "/work"}
    )

    assert body["error"]["code"] == "NOT_FOUND"
    assert handler.seen == []


async def test_missing_toolbox_scope_is_forbidden(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    read_only = await add_key(app, org_id, frozenset({Scope.SANDBOXES_READ}))

    body = await send(
        client, "GET", fs_path(sandbox_id, "list"), read_only, status=403, params={"path": "/"}
    )

    assert body["error"]["code"] == "FORBIDDEN"


# --- list and stat -----------------------------------------------------------------


async def test_list_returns_typed_sorted_entries(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    handler = script(
        driver,
        stat=out(record(0o40755, 4096, "/work")),
        find=out(
            record(0o100644, 5, "/work//b.txt")
            + record(0o40750, 4096, "/work/adir")
            + record(0o120777, 7, "/work/link")
        ),
    )
    sandbox_id = await create_sandbox(client, key)

    body = await get_ok(client, key, sandbox_id, "list", "/work")

    entries = body["data"]["entries"]
    assert body["data"]["path"] == "/work"
    assert [(e["name"], e["path"], e["kind"]) for e in entries] == [
        ("adir", "/work/adir", "dir"),
        ("b.txt", "/work/b.txt", "file"),
        ("link", "/work/link", "symlink"),
    ]
    assert [e["mode"] for e in entries] == ["750", "644", "777"]
    assert entries[1]["size_bytes"] == 5
    assert entries[1]["modified_at"].startswith("2025-10-30T12:00:00")
    [find_argv] = handler.argvs("find")
    assert find_argv[:2] == ["find", "/work/"]
    assert all(request.argv[0] != "sh" for request in handler.seen)


async def test_list_of_a_file_is_a_conflict(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    script(driver, stat=out(record(0o100644, 5, "/work/a.txt")))
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client, "GET", fs_path(sandbox_id, "list"), key, status=409, params={"path": "/work/a.txt"}
    )

    assert body["error"]["code"] == "CONFLICT"


async def test_stat_returns_the_entry(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    handler = script(driver, stat=out(record(0o104755, 12, "/work/tool")))
    sandbox_id = await create_sandbox(client, key)

    body = await get_ok(client, key, sandbox_id, "stat", "/work/tool")

    entry = body["data"]["entry"]
    assert (entry["name"], entry["path"], entry["kind"]) == ("tool", "/work/tool", "file")
    assert entry["mode"] == "4755"
    assert handler.argvs("stat") == [["stat", "-c", HEX_FORMAT.format, "/work/tool"]]


async def test_stat_falls_back_to_the_symbolic_format(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    calls: list[str] = []

    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        calls.append(request.argv[2])
        if request.argv[2] == HEX_FORMAT.format:
            return failed("stat: unrecognized option: c")
        return out(f"-rw-r--r--|5|{MTIME}|/work/a.txt\n")

    driver.exec_handler = handler
    sandbox_id = await create_sandbox(client, key)

    body = await get_ok(client, key, sandbox_id, "stat", "/work/a.txt")

    assert body["data"]["entry"]["mode"] == "644"
    assert calls == [HEX_FORMAT.format, SYMBOLIC_FORMAT.format]


async def test_stat_of_a_missing_path_is_not_found(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    script(driver, stat=failed("stat: cannot statx '/nope': No such file or directory"))
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client, "GET", fs_path(sandbox_id, "stat"), key, status=404, params={"path": "/nope"}
    )

    assert body["error"]["code"] == "NOT_FOUND"


# --- mkdir, move, delete -----------------------------------------------------------


async def test_mkdir_uses_an_argv_list_and_reports_creation(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    handler = script(driver, test=ExecResult(exit_code=1))
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        fs_path(sandbox_id, "mkdir"),
        key,
        status=200,
        json={"path": "/work/new dir", "mode": "700"},
    )

    assert body["data"] == {"path": "/work/new dir", "created": True}
    assert handler.argvs("mkdir") == [["mkdir", "-m", "700", "-p", "/work/new dir"]]


async def test_mkdir_of_an_existing_directory_is_not_created(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    script(driver, test=ExecResult(exit_code=0))
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client, "POST", fs_path(sandbox_id, "mkdir"), key, status=200, json={"path": "/work"}
    )

    assert body["data"]["created"] is False


async def test_mkdir_rejects_a_malformed_mode(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    handler = script(driver)
    sandbox_id = await create_sandbox(client, key)

    await send(
        client,
        "POST",
        fs_path(sandbox_id, "mkdir"),
        key,
        status=422,
        json={"path": "/work", "mode": "rwx"},
    )

    assert handler.seen == []


async def test_move_runs_mv_with_argv(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    handler = script_paths(driver, {"/work"})
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        fs_path(sandbox_id, "move"),
        key,
        status=200,
        json={"source": "/work/a.txt", "destination": "/work/b.txt"},
    )

    assert body["data"] == {"source": "/work/a.txt", "destination": "/work/b.txt"}
    assert handler.argvs("mv") == [["mv", "/work/a.txt", "/work/b.txt"]]


async def test_move_into_a_missing_directory_names_the_directory(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    handler = script_paths(driver, {"/work/a.txt"})
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "POST",
        fs_path(sandbox_id, "move"),
        key,
        status=404,
        json={"source": "/work/a.txt", "destination": "/missing/dir/b.txt"},
    )

    error = body["error"]
    assert error["code"] == "NOT_FOUND"
    assert error["message"] == "no such directory: /missing/dir; create it first"
    assert error["details"] == {"path": "/missing/dir"}
    assert "/work/a.txt" not in error["message"]
    assert handler.argvs("mv") == []


async def test_move_onto_an_existing_destination_needs_overwrite(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    handler = script(driver, test=ExecResult(exit_code=0))
    sandbox_id = await create_sandbox(client, key)
    request = {"source": "/a", "destination": "/b"}

    conflict = await send(
        client, "POST", fs_path(sandbox_id, "move"), key, status=409, json=request
    )
    await send(
        client,
        "POST",
        fs_path(sandbox_id, "move"),
        key,
        status=200,
        json={**request, "overwrite": True},
    )

    assert conflict["error"]["code"] == "CONFLICT"
    assert handler.argvs("mv") == [["mv", "-f", "/a", "/b"]]


async def test_delete_honours_the_recursive_flag(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    handler = script(driver)
    sandbox_id = await create_sandbox(client, key)

    plain = await send(
        client, "POST", fs_path(sandbox_id, "delete"), key, status=200, json={"path": "/work/a"}
    )
    deep = await send(
        client,
        "POST",
        fs_path(sandbox_id, "delete"),
        key,
        status=200,
        json={"path": "/work/dir", "recursive": True},
    )

    assert plain["data"] == {"path": "/work/a", "deleted": True}
    assert deep["data"]["deleted"] is True
    assert handler.argvs("rm") == [["rm", "/work/a"], ["rm", "-r", "/work/dir"]]


async def test_delete_of_the_root_is_refused(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    handler = script(driver)
    sandbox_id = await create_sandbox(client, key)

    await send(
        client,
        "POST",
        fs_path(sandbox_id, "delete"),
        key,
        status=422,
        json={"path": "/", "recursive": True},
    )

    assert handler.seen == []


async def test_delete_of_a_missing_path_is_not_found(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    script(driver, rm=failed("rm: can't remove '/x': No such file or directory"))
    sandbox_id = await create_sandbox(client, key)

    await send(client, "POST", fs_path(sandbox_id, "delete"), key, status=404, json={"path": "/x"})


# --- upload and download -----------------------------------------------------------


async def test_upload_then_download_round_trips_bytes(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    payload = bytes(range(256)) * 40

    body = await upload(client, key, sandbox_id, "/work/data.bin", payload)
    response = await download(client, key, sandbox_id, "/work/data.bin")

    assert body["data"] == {"path": "/work/data.bin", "size_bytes": len(payload)}
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/octet-stream")
    assert response.content == payload


async def test_upload_without_a_declared_size_is_rejected(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)

    async def body() -> AsyncIterator[bytes]:
        yield b"abc"

    await send(
        client,
        "PUT",
        fs_path(sandbox_id, "upload"),
        key,
        status=422,
        params={"path": "/work/a.txt"},
        content=body(),
    )


async def test_chunked_upload_with_size_query_is_streamed(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)

    async def body() -> AsyncIterator[bytes]:
        yield b"ab"
        yield b"cde"

    await send(
        client,
        "PUT",
        fs_path(sandbox_id, "upload"),
        key,
        status=200,
        params={"path": "/work/a.txt", "size_bytes": 5},
        content=body(),
    )
    response = await download(client, key, sandbox_id, "/work/a.txt")

    assert response.content == b"abcde"


async def test_upload_over_the_cap_is_413_and_stores_nothing(
    client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fs_schemas, "MAX_UPLOAD_BYTES", 8)
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "PUT",
        fs_path(sandbox_id, "upload"),
        key,
        status=413,
        params={"path": "/work/big.bin"},
        content=b"x" * 16,
    )
    missing = await download(client, key, sandbox_id, "/work/big.bin")

    assert body["error"]["code"] == "PAYLOAD_TOO_LARGE"
    assert missing.status_code == 404


async def test_declared_length_over_the_cap_is_413_before_the_body_is_read(
    client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fs_schemas, "MAX_UPLOAD_BYTES", 8)
    sandbox_id = await create_sandbox(client, key)
    pulled: list[bytes] = []

    async def body() -> AsyncIterator[bytes]:
        pulled.append(b"x")
        yield b"x" * 16

    response = await client.put(
        fs_path(sandbox_id, "upload"),
        headers={**auth(key), "Content-Length": "16"},
        params={"path": "/work/big.bin"},
        content=body(),
    )

    error = response.json()["error"]
    assert response.status_code == 413
    assert error["code"] == "PAYLOAD_TOO_LARGE"
    assert error["message"] == "upload limit is 8 bytes; this upload is 16 bytes"
    assert error["details"] == {"limit_bytes": 8, "size_bytes": 16}
    assert pulled == []


async def test_disk_full_during_upload_discards_the_partial_file_and_reraises(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = script(driver)

    async def full_disk(ref: str, dest_path: str, data: AsyncIterator[bytes]) -> None:
        await anext(data)  # some bytes reach the disk before it fills up
        raise DriverConflict(DISK_FULL_MESSAGE, ref=ref)

    monkeypatch.setattr(driver, "put_archive", full_disk)
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "PUT",
        fs_path(sandbox_id, "upload"),
        key,
        status=409,
        params={"path": "/work/big.bin"},
        content=b"x" * 4096,
    )

    assert body["error"]["message"] == DISK_FULL_MESSAGE
    assert handler.argvs("rm") == [["rm", "-f", "/work/big.bin"]]


async def test_upload_without_overwrite_conflicts_when_the_file_exists(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    script(driver, test=ExecResult(exit_code=0))
    sandbox_id = await create_sandbox(client, key)

    await send(
        client,
        "PUT",
        fs_path(sandbox_id, "upload"),
        key,
        status=409,
        params={"path": "/work/a.txt", "overwrite": "false"},
        content=b"x",
    )


@pytest.mark.parametrize("overwrite", ["true", "false"])
async def test_upload_onto_an_existing_directory_is_a_conflict_and_writes_nothing(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    monkeypatch: pytest.MonkeyPatch,
    overwrite: str,
) -> None:
    script(driver, stat=out(record(0o40755, 4096, "/work/dir")))
    archive_calls: list[str] = []
    real_put_archive = driver.put_archive

    async def spy(ref: str, dest_path: str, data: AsyncIterator[bytes]) -> None:
        archive_calls.append(dest_path)
        await real_put_archive(ref, dest_path, data)

    monkeypatch.setattr(driver, "put_archive", spy)
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "PUT",
        fs_path(sandbox_id, "upload"),
        key,
        status=409,
        params={"path": "/work/dir", "overwrite": overwrite},
        content=b"x",
    )

    error = body["error"]
    assert error["code"] == "CONFLICT"
    assert error["message"] == "is a directory: /work/dir; upload to a file path inside it"
    assert error["details"] == {"reason": "conflict", "path": "/work/dir"}
    assert archive_calls == []


async def test_upload_onto_an_existing_regular_file_overwrites_it(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    script(driver, stat=out(record(0o100644, 3, "/work/a.txt")))
    sandbox_id = await create_sandbox(client, key)

    await upload(client, key, sandbox_id, "/work/a.txt", b"new")
    response = await download(client, key, sandbox_id, "/work/a.txt")

    assert response.content == b"new"


async def test_upload_to_a_new_path_still_works(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    # the stat after the write confirms the file (round 63): five bytes at the new path
    script(driver, stat=out(record(0o100644, 5, "/work/n.txt")))
    sandbox_id = await create_sandbox(client, key)

    body = await upload(client, key, sandbox_id, "/work/n.txt", b"fresh")
    response = await download(client, key, sandbox_id, "/work/n.txt")

    assert body["data"] == {"path": "/work/n.txt", "size_bytes": 5}
    assert response.content == b"fresh"


async def test_download_of_a_directory_is_a_tar(client: httpx.AsyncClient, key: str) -> None:
    sandbox_id = await create_sandbox(client, key)
    await upload(client, key, sandbox_id, "/work/a.txt", b"one")
    await upload(client, key, sandbox_id, "/work/sub/b.txt", b"two")

    response = await download(client, key, sandbox_id, "/work")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-tar")
    contents: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(response.content)) as archive:
        for member in archive.getmembers():
            handle = archive.extractfile(member) if member.isfile() else None
            if handle is not None:
                contents[member.name] = handle.read()
    assert contents == {"work/a.txt": b"one", "work/sub/b.txt": b"two"}


async def test_download_of_a_missing_path_is_not_found(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)

    response = await download(client, key, sandbox_id, "/work/missing")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


async def test_inline_download_returns_text_and_honours_max_bytes(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    await upload(client, key, sandbox_id, "/work/hello.txt", b"hello world")
    path = fs_path(sandbox_id, "download")

    full = await send(
        client,
        "GET",
        path,
        key,
        status=200,
        params={"path": "/work/hello.txt", "inline": "true"},
    )
    cut = await send(
        client,
        "GET",
        path,
        key,
        status=200,
        params={"path": "/work/hello.txt", "inline": "true", "max_bytes": 5},
    )

    assert full["data"] == {
        "path": "/work/hello.txt",
        "size_bytes": 11,
        "content": "hello world",
        "truncated": False,
    }
    assert (cut["data"]["content"], cut["data"]["truncated"]) == ("hello", True)


async def test_inline_read_over_the_cap_is_413(
    client: httpx.AsyncClient, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fs_schemas, "MAX_INLINE_READ_BYTES", 4)
    sandbox_id = await create_sandbox(client, key)
    await upload(client, key, sandbox_id, "/work/hello.txt", b"hello world")
    path = fs_path(sandbox_id, "download")

    too_big_file = await send(
        client, "GET", path, key, status=413, params={"path": "/work/hello.txt", "inline": "true"}
    )
    too_big_file_within_cap = await send(
        client,
        "GET",
        path,
        key,
        status=413,
        params={"path": "/work/hello.txt", "inline": "true", "max_bytes": 4},
    )
    above_cap_request = await send(
        client,
        "GET",
        path,
        key,
        status=422,
        params={"path": "/work/hello.txt", "inline": "true", "max_bytes": 5},
    )

    assert too_big_file["error"]["code"] == "PAYLOAD_TOO_LARGE"
    assert too_big_file_within_cap["error"]["code"] == "PAYLOAD_TOO_LARGE"
    assert above_cap_request["error"]["code"] == "VALIDATION_ERROR"
    issues = above_cap_request["error"]["details"]["errors"]
    assert [(issue["type"], issue["loc"]) for issue in issues] == [
        ("less_than_equal", ["query", "max_bytes"])
    ]


# --- path rejection ----------------------------------------------------------------

BAD_PATHS = ["relative/file", "/a//b", "/a/", "/a/../../etc/passwd", "/a/\x00/b", "/..", ""]


@pytest.mark.parametrize("bad", BAD_PATHS)
async def test_malformed_and_traversal_paths_are_422(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, bad: str
) -> None:
    handler = script(driver)
    sandbox_id = await create_sandbox(client, key)

    for action in ("stat", "list", "download"):
        await send(
            client, "GET", fs_path(sandbox_id, action), key, status=422, params={"path": bad}
        )
    await send(client, "POST", fs_path(sandbox_id, "mkdir"), key, status=422, json={"path": bad})
    await send(
        client,
        "POST",
        fs_path(sandbox_id, "move"),
        key,
        status=422,
        json={"source": bad, "destination": "/ok"},
    )
    await send(client, "POST", fs_path(sandbox_id, "delete"), key, status=422, json={"path": bad})
    await send(
        client,
        "PUT",
        fs_path(sandbox_id, "upload"),
        key,
        status=422,
        params={"path": bad},
        content=b"x",
    )
    assert handler.seen == []


async def test_uploading_to_the_root_is_422(client: httpx.AsyncClient, key: str) -> None:
    sandbox_id = await create_sandbox(client, key)

    await send(
        client,
        "PUT",
        fs_path(sandbox_id, "upload"),
        key,
        status=422,
        params={"path": "/"},
        content=b"x",
    )


async def test_upload_to_a_missing_parent_directory_names_the_directory(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    async def parent_missing(ref: str, dest_path: str, data: AsyncIterator[bytes]) -> None:
        raise DriverNotFound(f"Could not find the file {dest_path} in the sandbox container")

    driver.put_archive = parent_missing  # type: ignore[method-assign]
    sandbox_id = await create_sandbox(client, key)

    body = await send(
        client,
        "PUT",
        fs_path(sandbox_id, "upload"),
        key,
        status=404,
        params={"path": "/missing/dir/a.txt"},
        content=b"x",
    )

    error = body["error"]
    assert error["code"] == "NOT_FOUND"
    assert error["message"] == "no such directory: /missing/dir; create it first"
    assert error["details"]["path"] == "/missing/dir"
    assert "file" not in error["message"]
    assert "container" not in error["message"]


def test_normalize_path_resolves_dots_inside_the_root() -> None:
    assert normalize_path("/a/./b/../c") == "/a/c"
    assert normalize_path("/") == "/"
    assert normalize_path("/work/x", root="/work") == "/work/x"


@pytest.mark.parametrize("raw", ["/other/x", "/work/../etc", "/workshop"])
def test_normalize_path_rejects_escaping_the_given_root(raw: str) -> None:
    with pytest.raises(Unprocessable):
        normalize_path(raw, root="/work")


# --- audit -------------------------------------------------------------------------


async def test_every_operation_is_audited_without_contents(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str, driver: FakeDriver
) -> None:
    script_paths(
        driver,
        {"/w"},
        stat=out(record(0o40755, 4096, "/work")),
        find=out(""),
    )
    sandbox_id = await create_sandbox(client, key)
    secret = b"TOP-SECRET-FILE-CONTENT"

    await get_ok(client, key, sandbox_id, "list", "/work")
    await get_ok(client, key, sandbox_id, "stat", "/work")
    await send(
        client, "POST", fs_path(sandbox_id, "mkdir"), key, status=200, json={"path": "/w/n"}
    )
    await send(
        client,
        "POST",
        fs_path(sandbox_id, "move"),
        key,
        status=200,
        json={"source": "/w/n", "destination": "/w/m"},
    )
    await send(
        client, "POST", fs_path(sandbox_id, "delete"), key, status=200, json={"path": "/w/m"}
    )
    script(driver, stat=out(record(0o100644, len(secret), "/work/s.txt")))
    await upload(client, key, sandbox_id, "/work/s.txt", secret)
    await download(client, key, sandbox_id, "/work/s.txt")

    events = [e for e in await audit_events(app, org_id) if e.action.startswith("toolbox.fs.")]
    by_action = {event.action: event for event in events}
    assert set(by_action) == {
        "toolbox.fs.list",
        "toolbox.fs.stat",
        "toolbox.fs.mkdir",
        "toolbox.fs.move",
        "toolbox.fs.delete",
        "toolbox.fs.upload",
        "toolbox.fs.download",
    }
    assert by_action["toolbox.fs.mkdir"].details["path"] == "/w/n"
    assert by_action["toolbox.fs.move"].details["destination"] == "/w/m"
    assert by_action["toolbox.fs.upload"].details["size_bytes"] == len(secret)
    assert all(event.target_id == sandbox_id for event in events)
    assert all(secret.decode() not in str(event.details) for event in events)


# --- streaming boundedness ---------------------------------------------------------


async def test_upload_reaches_the_driver_in_bounded_chunks(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sizes: list[int] = []
    original = driver.put_archive

    async def counting(ref: str, dest_path: str, data: AsyncIterator[bytes]) -> None:
        async def counted() -> AsyncIterator[bytes]:
            async for chunk in data:
                sizes.append(len(chunk))
                yield chunk

        await original(ref, dest_path, counted())

    driver.put_archive = counting  # type: ignore[method-assign]
    sandbox_id = await create_sandbox(client, key)
    payload = b"z" * (3 * CHUNK_BYTES + 17)  # may arrive as one oversized ASGI chunk

    await upload(client, key, sandbox_id, "/work/big.bin", payload)

    assert max(sizes) <= CHUNK_BYTES
    assert sum(sizes) >= len(payload)
    assert len(sizes) >= 5


async def test_tar_stream_pulls_the_source_lazily_and_stays_bounded() -> None:
    pulled = 0
    piece = b"q" * (CHUNK_BYTES // 2)

    async def source() -> AsyncIterator[bytes]:
        nonlocal pulled
        for _ in range(8):
            pulled += 1
            yield piece

    total = 8 * len(piece)
    stream = tar_upload_stream(
        source(), name="f.bin", size=total, mode=0o644, mtime=MTIME, max_bytes=total
    )
    sizes: list[int] = []
    pulled_at_first_body_chunk = -1
    async for chunk in stream:
        sizes.append(len(chunk))
        if len(sizes) == 2:
            pulled_at_first_body_chunk = pulled

    assert pulled_at_first_body_chunk == 1
    assert max(sizes) <= CHUNK_BYTES
    assert sum(sizes) == 512 + total + (-total % 512) + 1024


async def collect(stream: AsyncIterator[bytes]) -> bytes:
    return b"".join([chunk async for chunk in stream])


async def one_chunk(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def test_tar_stream_is_a_valid_one_file_archive() -> None:
    payload = b"hello tar" * 100

    tar_bytes = await collect(
        tar_upload_stream(
            one_chunk(payload),
            name="héllo.txt",
            size=len(payload),
            mode=0o600,
            mtime=MTIME,
            max_bytes=1024 * 1024,
        )
    )

    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as archive:
        [member] = archive.getmembers()
        handle = archive.extractfile(member)
        assert handle is not None
        assert (member.name, member.mode, handle.read()) == ("héllo.txt", 0o600, payload)


async def test_tar_stream_aborts_over_the_cap_and_on_length_mismatch() -> None:
    def build(body: bytes, *, size: int, max_bytes: int) -> AsyncIterator[bytes]:
        return tar_upload_stream(
            one_chunk(body), name="f", size=size, mode=0o644, mtime=MTIME, max_bytes=max_bytes
        )

    with pytest.raises(PayloadTooLarge):
        await collect(build(b"x" * 20, size=10, max_bytes=10))
    with pytest.raises(PayloadTooLarge):
        await collect(build(b"x", size=20, max_bytes=10))
    with pytest.raises(Unprocessable):
        await collect(build(b"x" * 20, size=10, max_bytes=100))
    with pytest.raises(Unprocessable):
        await collect(build(b"x" * 5, size=10, max_bytes=100))


async def test_extract_file_handles_pax_headers_and_tiny_chunks() -> None:
    payload = b"p" * 1500
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("ünïcode-" + "n" * 120 + ".txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    raw = buffer.getvalue()

    async def tiny() -> AsyncIterator[bytes]:
        for start in range(0, len(raw), 7):
            yield raw[start : start + 7]

    assert await collect(extract_file(tiny())) == payload


async def test_extract_file_rejects_a_truncated_archive() -> None:
    tar_bytes = await collect(
        tar_upload_stream(
            one_chunk(b"abcdef"), name="f", size=6, mode=0o644, mtime=MTIME, max_bytes=10
        )
    )

    with pytest.raises(DriverError):
        await collect(extract_file(one_chunk(tar_bytes[:515])))


# --- parsers -----------------------------------------------------------------------


def test_symbolic_modes_parse_special_bits() -> None:
    [entry] = parse_stat_output(f"drwxrwxrwt|4096|{MTIME}|/tmp\n", SYMBOLIC_FORMAT)

    assert (entry.kind, format(entry.mode, "o")) == ("dir", "1777")


def test_names_with_pipes_and_newlines_survive_parsing() -> None:
    text = record(0o100644, 1, "/d/a|b") + f"{0o100644:x}|2|{MTIME}|/d/line\nbreak\n"

    entries = parse_stat_output(text, HEX_FORMAT, directory="/d")

    assert [e.name for e in entries] == ["a|b", "line\nbreak"]


def test_unrecognized_output_is_a_parse_error() -> None:
    with pytest.raises(FsParseError):
        parse_stat_output("not a stat record\n", HEX_FORMAT)
