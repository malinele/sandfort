"""Round 58: a repeated single-value query parameter answers 422, not the last value.

The sandbox list refuses a repeated parameter since round 57; this covers the audit-events,
jobs, snapshots, volumes, api-keys, sandbox-logs, fs, git-status and code-contexts routes. The
worst case was the fs download: ``?path=/a&path=/b`` served ``/b`` without a word.

FakeDriver, temp SQLite migrated to head, httpx over ASGI (no network, no sockets).
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import NamedTuple

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
OK_STATUS = 200
CREATED_STATUS = 201
UNAUTHORIZED_STATUS = 401
VALIDATION_STATUS = 422
SANDBOXES = "/v1/sandboxes"
AUDIT = "/v1/audit-events"
LOGS = SANDBOXES + "/{sbx}/logs"
FS = SANDBOXES + "/{sbx}/toolbox/fs"
GIT = SANDBOXES + "/{sbx}/toolbox/git"
CONTEXTS = SANDBOXES + "/{sbx}/toolbox/code-contexts"
FIRST_PATH = "/tmp/r58-first.txt"
SECOND_PATH = "/tmp/r58-second.txt"
FIRST_BODY = b"first-file-content"
SECOND_BODY = b"second-file-content"
OCTET = {"Content-Type": "application/octet-stream"}
REPEATED_ONCE = "must be given once"


class Route(NamedTuple):
    """One guarded route: how to call it with a repeated and with a single-value parameter."""

    id: str
    method: str
    path: str
    repeated: str
    single: str
    name: str


ROUTES = [
    Route("audit-list", "GET", AUDIT, "limit=1&limit=2", "limit=1", "limit"),
    Route("audit-list-from", "GET", AUDIT, "from=a&from=b", "", "from"),
    Route("audit-list-order", "GET", AUDIT, "order=asc&order=desc", "order=asc", "order"),
    Route(
        "audit-export",
        "GET",
        AUDIT + "/export",
        "outcome=success&outcome=denied",
        "outcome=success",
        "outcome",
    ),
    Route(
        "audit-verify",
        "GET",
        AUDIT + "/verify",
        "from_id=a&from_id=b",
        "from_id=a",
        "from_id",
    ),
    Route("jobs", "GET", "/v1/jobs", "limit=1&limit=2", "limit=1", "limit"),
    Route("snapshots", "GET", "/v1/snapshots", "cursor=a&cursor=b", "", "cursor"),
    Route("volumes", "GET", "/v1/volumes", "limit=1&limit=2", "limit=1", "limit"),
    Route(
        "api-keys",
        "GET",
        "/v1/api-keys",
        "status=active&status=revoked",
        "status=active",
        "status",
    ),
    Route("sandbox-logs", "GET", LOGS, "tail=1&tail=2", "tail=1", "tail"),
    Route("sandbox-logs-follow", "GET", LOGS, "follow=true&follow=false", "", "follow"),
    Route("fs-list", "GET", FS + "/list", "path=/tmp&path=/etc", "path=/tmp", "path"),
    Route(
        "fs-stat",
        "GET",
        FS + "/stat",
        f"path={FIRST_PATH}&path={SECOND_PATH}",
        f"path={FIRST_PATH}",
        "path",
    ),
    Route(
        "fs-download",
        "GET",
        FS + "/download",
        f"path={FIRST_PATH}&path={SECOND_PATH}",
        f"path={FIRST_PATH}",
        "path",
    ),
    Route(
        "fs-download-inline",
        "GET",
        FS + "/download",
        f"path={FIRST_PATH}&inline=true&inline=false",
        f"path={FIRST_PATH}&inline=true",
        "inline",
    ),
    Route(
        "fs-download-max-bytes",
        "GET",
        FS + "/download",
        f"path={FIRST_PATH}&inline=true&max_bytes=1&max_bytes=2",
        f"path={FIRST_PATH}&inline=true&max_bytes=2",
        "max_bytes",
    ),
    Route(
        "fs-upload",
        "PUT",
        FS + "/upload",
        "path=/tmp/r58-a.txt&path=/tmp/r58-b.txt",
        "path=/tmp/r58-a.txt",
        "path",
    ),
    Route("git-status", "GET", GIT + "/status", "path=/tmp&path=/etc", "path=/tmp", "path"),
    Route("code-contexts", "GET", CONTEXTS, "name=a&name=b", "name=a", "name"),
]
IDS = [route.id for route in ROUTES]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'repeated58.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
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
async def headers(app: FastAPI) -> dict[str, str]:
    org = Org(id=new_org_id(), name="Repeated", slug="repeated58", created_at=NOW)
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="repeated58",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset(Scope),
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(key)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}"}


@pytest.fixture
async def sandbox_id(client: httpx.AsyncClient, headers: dict[str, str]) -> str:
    response = await client.post(SANDBOXES, json={}, headers=headers)
    assert response.status_code == CREATED_STATUS, response.text
    value: str = response.json()["data"]["id"]
    return value


async def write_file(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, path: str, body: bytes
) -> None:
    response = await client.put(
        f"{SANDBOXES}/{sandbox_id}/toolbox/fs/upload",
        params={"path": path},
        content=body,
        headers={**headers, **OCTET},
    )
    assert response.status_code == OK_STATUS, response.text


async def call(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    route: Route,
    sandbox_id: str,
    query: str,
) -> httpx.Response:
    url = route.path.format(sbx=sandbox_id) + (f"?{query}" if query else "")
    if route.method == "PUT":
        return await client.put(url, content=b"x", headers={**headers, **OCTET})
    return await client.get(url, headers=headers)


@pytest.mark.parametrize("route", ROUTES, ids=IDS)
async def test_repeated_parameter_answers_422(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, route: Route
) -> None:
    response = await call(client, headers, route, sandbox_id, route.repeated)

    assert response.status_code == VALIDATION_STATUS, response.text
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert f"{route.name} {REPEATED_ONCE}" in error["message"]
    assert error["details"]["errors"][0]["loc"] == ["query", route.name]


@pytest.mark.parametrize("route", ROUTES, ids=IDS)
async def test_single_value_is_not_refused_as_repeated(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str, route: Route
) -> None:
    await write_file(client, headers, sandbox_id, FIRST_PATH, FIRST_BODY)

    response = await call(client, headers, route, sandbox_id, route.single)

    # The handler may answer its own status (e.g. git status outside a repository); what must
    # not happen is the repeated-parameter refusal.
    assert REPEATED_ONCE not in response.text, response.text


async def test_repeated_download_path_does_not_serve_either_file(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    await write_file(client, headers, sandbox_id, FIRST_PATH, FIRST_BODY)
    await write_file(client, headers, sandbox_id, SECOND_PATH, SECOND_BODY)
    url = f"{SANDBOXES}/{sandbox_id}/toolbox/fs/download"

    repeated = await client.get(f"{url}?path={FIRST_PATH}&path={SECOND_PATH}", headers=headers)
    inline = await client.get(
        f"{url}?path={FIRST_PATH}&path={SECOND_PATH}&inline=true", headers=headers
    )
    single = await client.get(f"{url}?path={FIRST_PATH}", headers=headers)

    for refused in (repeated, inline):
        assert refused.status_code == VALIDATION_STATUS, refused.text
        assert FIRST_BODY not in refused.content
        assert SECOND_BODY not in refused.content
    assert single.status_code == OK_STATUS, single.text
    assert single.content == FIRST_BODY


async def test_repeated_upload_path_writes_neither_file(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    url = f"{SANDBOXES}/{sandbox_id}/toolbox/fs"

    response = await client.put(
        f"{url}/upload?path=/tmp/r58-a.txt&path=/tmp/r58-b.txt",
        content=b"x",
        headers={**headers, **OCTET},
    )
    stat = await client.get(f"{url}/stat?path=/tmp/r58-b.txt", headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert stat.status_code != OK_STATUS, stat.text


async def test_repeated_parameter_without_credentials_is_401(client: httpx.AsyncClient) -> None:
    response = await client.get("/v1/jobs?limit=1&limit=2")

    assert response.status_code == UNAUTHORIZED_STATUS, response.text
