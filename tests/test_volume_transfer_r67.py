"""Round 67: ``GET /v1/volumes/{id}/export`` and ``POST /v1/volumes/{id}/restore``.

The API on the fake driver and a temp SQLite database. The fake driver keeps the files a
sandbox wrote under a mount path per volume. Export is a gzipped tar, restore empties the volume
and extracts a tar after the same archive policy the docker driver applies (see
``test_volume_restore_policy_r67``); the docker driver itself runs in
``test_docker_volume_transfer_r67`` (real daemon) and its unit twin.
"""

import gzip
import io
import tarfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.schemas.toolbox_fs import MAX_UPLOAD_BYTES
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent, AuditOutcome
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
VOLUMES = "/v1/volumes"
SANDBOXES = "/v1/sandboxes"
MOUNT = "/data"
LIMIT = 64 * 1024  # a restore counts tar bytes: headers and the 10 KiB record padding included
MIB = 1024 * 1024
STEP_LIMIT = MIB + MIB // 2  # past the first decompressed step (1 MiB), under the second
GZIP_TYPE = "application/gzip"
EXPORT_ACTION = "volume.export"
RESTORE_ACTION = "volume.restore"
OWNER = {"team": "infra"}
SHARED = {"pool": "datasets"}
SANDBOX_SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
READ = frozenset({Scope.VOLUMES_READ})
WRITE = frozenset({Scope.VOLUMES_WRITE})
FULL = SANDBOX_SCOPES | READ | WRITE
FILES = {"a.txt": b"alpha\n", "sub/b.bin": bytes(range(256)) * 8, "sub/deep/c.txt": b"c" * 3000}


@pytest.fixture
async def make_app(tmp_path: Path) -> AsyncIterator[Any]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    built: list[FastAPI] = []

    def build(
        max_bytes: int = 0, body_limit: int | None = None, faults: tuple[str, ...] = ()
    ) -> FastAPI:
        url = f"sqlite+aiosqlite:///{tmp_path / f'transfer{len(built)}.db'}"
        config = Config(str(ROOT / "alembic.ini"))
        config.set_main_option("sqlalchemy.url", url)
        command.upgrade(config, "head")
        extra: dict[str, Any] = {} if body_limit is None else {"max_request_body_bytes": body_limit}
        settings = Settings(
            driver="fake",
            database_url=url,
            api_key_pepper=PEPPER,
            volume_max_bytes=max_bytes,
            fault_injection=faults,
            **extra,
        )
        application = create_app(settings)
        built.append(application)
        return application

    yield build
    for application in built:
        await application.state.engine.dispose()


@pytest.fixture
async def app(make_app: Any) -> FastAPI:
    built: FastAPI = make_app()
    return built


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with http_client(app) as http:
        yield http


def http_client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


@pytest.fixture
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


async def add_org(app: FastAPI, slug: str = "acme") -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def add_key(
    app: FastAPI,
    org_id: str,
    scopes: frozenset[Scope] = FULL,
    labels: dict[str, str] | None = None,
    shared: dict[str, str] | None = None,
) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
        created_at=NOW,
        sandbox_labels=labels,
        shared_volume_labels=shared,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app)


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id)


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def error(response: httpx.Response) -> dict[str, Any]:
    body: dict[str, Any] = response.json()["error"]
    return body


async def new_volume(
    client: httpx.AsyncClient, key: str, name: str = "data", labels: dict[str, str] | None = None
) -> str:
    body: dict[str, Any] = {"name": name, **({} if labels is None else {"labels": labels})}
    response = await client.post(VOLUMES, headers=auth(key), json=body)
    assert response.status_code == 201, response.text
    volume_id: str = response.json()["data"]["id"]
    return volume_id


async def mounting_sandbox(client: httpx.AsyncClient, key: str, volume_id: str) -> str:
    body = {"volumes": [{"volume_id": volume_id, "mount_path": MOUNT}]}
    response = await client.post(SANDBOXES, headers=auth(key), json=body)
    assert response.status_code == 201, response.text
    sandbox_id: str = response.json()["data"]["id"]
    return sandbox_id


async def write_files(
    client: httpx.AsyncClient, key: str, sandbox_id: str, files: dict[str, bytes]
) -> None:
    for name, content in files.items():
        response = await client.put(
            f"{SANDBOXES}/{sandbox_id}/toolbox/fs/upload",
            headers=auth(key),
            params={"path": f"{MOUNT}/{name}"},
            content=content,
        )
        assert response.status_code == 200, response.text


async def seeded_volume(
    client: httpx.AsyncClient,
    key: str,
    name: str = "data",
    labels: dict[str, str] | None = None,
    files: dict[str, bytes] | None = None,
) -> str:
    """A volume holding ``files``, written through a sandbox that is deleted afterwards."""
    volume_id = await new_volume(client, key, name, labels)
    sandbox_id = await mounting_sandbox(client, key, volume_id)
    await write_files(client, key, sandbox_id, FILES if files is None else files)
    deleted = await client.delete(f"{SANDBOXES}/{sandbox_id}", headers=auth(key))
    assert deleted.status_code == 200, deleted.text
    return volume_id


def make_archive(files: dict[str, bytes], *, prefix: str = "") -> bytes:
    """A gzipped tar of ``files`` (names may carry a ``./`` prefix, as ``tar -C dir .`` writes)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(prefix + name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def read_archive(data: bytes) -> dict[str, bytes]:
    """The regular files of a gzipped tar, names without a ``./`` prefix."""
    found: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive.getmembers():
            handle = archive.extractfile(member) if member.isfile() else None
            if handle is not None:
                found[member.name.removeprefix("./")] = handle.read()
    return found


async def export(client: httpx.AsyncClient, key: str, volume_id: str) -> httpx.Response:
    return await client.get(f"{VOLUMES}/{volume_id}/export", headers=auth(key))


async def restore(
    client: httpx.AsyncClient,
    key: str,
    volume_id: str,
    body: bytes,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return await client.post(
        f"{VOLUMES}/{volume_id}/restore", headers={**auth(key), **(headers or {})}, content=body
    )


async def audit_rows(app: FastAPI, org_id: str, action: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        rows = await uow.audit.list(org_id, limit=200)
    return [row for row in rows if row.action == action]


# -- export ----------------------------------------------------------------------------------


async def test_export_streams_a_gzipped_tar_of_the_volume(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key, name="my_data.v1")

    response = await export(client, key, volume_id)

    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == GZIP_TYPE
    assert response.headers["content-disposition"] == 'attachment; filename="my_data.v1.tar.gz"'
    assert read_archive(response.content) == FILES


async def test_export_of_an_empty_volume_is_a_valid_empty_archive(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await new_volume(client, key)

    response = await export(client, key, volume_id)

    assert response.status_code == 200
    assert read_archive(response.content) == {}


async def test_export_works_while_a_running_sandbox_mounts_the_volume(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await new_volume(client, key)
    sandbox_id = await mounting_sandbox(client, key, volume_id)
    await write_files(client, key, sandbox_id, {"live.txt": b"still running"})

    response = await export(client, key, volume_id)

    assert response.status_code == 200
    assert read_archive(response.content) == {"live.txt": b"still running"}


async def test_export_is_audited_with_the_name_before_the_bytes_flow(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    volume_id = await seeded_volume(client, key, name="ledger")

    await export(client, key, volume_id)

    (row,) = await audit_rows(app, org_id, EXPORT_ACTION)
    assert (row.target_type, row.target_id, row.outcome) == (
        "volume",
        volume_id,
        AuditOutcome.SUCCESS,
    )
    assert row.details == {"name": "ledger"}


async def test_export_of_a_missing_or_foreign_volume_is_not_found(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    other_org = await add_org(app, "other")
    other_key = await add_key(app, other_org)
    foreign = await new_volume(client, other_key)

    assert (await export(client, key, foreign)).status_code == 404
    assert (await export(client, key, "vol_missing")).status_code == 404


async def test_export_needs_the_volumes_read_scope(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    volume_id = await new_volume(client, key)
    writer_only = await add_key(app, org_id, WRITE)

    refused = await export(client, writer_only, volume_id)

    assert refused.status_code == 403


async def test_export_without_driver_support_is_a_409(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await new_volume(client, key)
    app.state.volume_transfer.driver = object()  # a driver with no transfer methods

    response = await export(client, key, volume_id)

    assert response.status_code == 409
    assert error(response)["details"]["reason"] == "unsupported_mode"


# -- export: label scopes --------------------------------------------------------------------


async def test_scoped_key_exports_only_a_volume_it_owns(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    mine = await seeded_volume(client, key, name="mine", labels=OWNER, files={"m": b"1"})
    theirs = await seeded_volume(client, key, name="theirs", labels={"team": "ops"})
    scoped = await add_key(app, org_id, FULL, OWNER)

    allowed = await export(client, scoped, mine)
    hidden = await export(client, scoped, theirs)

    assert allowed.status_code == 200
    assert read_archive(allowed.content) == {"m": b"1"}
    assert hidden.status_code == 404


async def test_shared_labels_reach_is_not_an_export_right(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    pool = await seeded_volume(client, key, name="pool", labels=SHARED)
    reader = await add_key(app, org_id, SANDBOX_SCOPES | READ, {"student": "3"}, SHARED)

    seen = await client.get(f"{VOLUMES}/{pool}", headers=auth(reader))
    refused = await export(client, reader, pool)

    assert seen.status_code == 200  # the key can read it, just not take it away
    assert refused.status_code == 403
    assert "shared_volume_labels" in error(refused)["message"]
    assert "cannot be exported" in error(refused)["message"]
    assert error(refused)["details"] == {"volume_ids": [pool]}
    assert await audit_rows(app, org_id, EXPORT_ACTION) == []


# -- restore ---------------------------------------------------------------------------------


async def test_restore_replaces_the_contents_and_the_export_round_trips(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files={"old.txt": b"old", "keep/old2": b"x"})
    archive = make_archive(FILES, prefix="./")

    response = await restore(client, key, volume_id, archive)

    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["volume_id"] == volume_id
    assert data["name"] == "data"
    assert data["restored_bytes"] >= sum(len(content) for content in FILES.values())
    exported = await export(client, key, volume_id)
    assert read_archive(exported.content) == FILES  # the old files are gone


async def test_restore_into_a_fresh_volume_then_mount_and_read(
    client: httpx.AsyncClient, key: str
) -> None:
    source = await seeded_volume(client, key, name="source")
    target = await new_volume(client, key, "target")
    archive = (await export(client, key, source)).content

    assert (await restore(client, key, target, archive)).status_code == 200

    sandbox_id = await mounting_sandbox(client, key, target)
    for name, content in FILES.items():
        read = await client.get(
            f"{SANDBOXES}/{sandbox_id}/toolbox/fs/download",
            headers=auth(key),
            params={"path": f"{MOUNT}/{name}"},
        )
        assert read.status_code == 200, read.text
        assert read.content == content


async def test_restore_is_audited_with_the_name_and_the_bytes(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    volume_id = await new_volume(client, key, "ledger")

    response = await restore(client, key, volume_id, make_archive({"f": b"12345"}))

    (row,) = await audit_rows(app, org_id, RESTORE_ACTION)
    assert row.action == "volume.restore"
    assert (row.target_type, row.target_id, row.outcome) == (
        "volume",
        volume_id,
        AuditOutcome.SUCCESS,
    )
    assert row.details["name"] == "ledger"
    assert row.details["restored_bytes"] == response.json()["data"]["restored_bytes"]


async def test_restore_is_refused_while_a_sandbox_mounts_the_volume(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    volume_id = await new_volume(client, key)
    sandbox_id = await mounting_sandbox(client, key, volume_id)
    await write_files(client, key, sandbox_id, {"mine.txt": b"keep me"})

    refused = await restore(client, key, volume_id, make_archive({"x": b"y"}))

    assert refused.status_code == 409, refused.text
    assert error(refused)["details"] == {"reason": "in_use", "sandbox_id": sandbox_id}
    assert read_archive((await export(client, key, volume_id)).content) == {"mine.txt": b"keep me"}
    assert await audit_rows(app, org_id, RESTORE_ACTION) == []

    await client.delete(f"{SANDBOXES}/{sandbox_id}", headers=auth(key))
    assert (await restore(client, key, volume_id, make_archive({"x": b"y"}))).status_code == 200


async def test_restore_over_the_limit_found_before_anything_is_emptied_changes_nothing(
    make_app: Any,
) -> None:
    app = make_app(max_bytes=LIMIT)
    key = await add_key(app, await add_org(app))
    async with http_client(app) as client:
        volume_id = await seeded_volume(client, key, files={"old": b"kept"})

        refused = await restore(client, key, volume_id, make_archive({"big": bytes(LIMIT * 4)}))

        assert refused.status_code == 413, refused.text
        assert error(refused)["code"] == "PAYLOAD_TOO_LARGE"
        assert error(refused)["details"]["limit_bytes"] == LIMIT
        assert read_archive((await export(client, key, volume_id)).content) == {"old": b"kept"}


async def test_restore_over_the_volume_size_limit_is_413_and_leaves_the_volume_empty(
    make_app: Any,
) -> None:
    app = make_app(max_bytes=STEP_LIMIT)
    org_id = await add_org(app)
    key = await add_key(app, org_id)
    async with http_client(app) as client:
        volume_id = await seeded_volume(client, key, files={"old": b"will be lost"})
        too_big = make_archive({"big.bin": bytes(3 * MIB)})  # zeros: small when compressed

        refused = await restore(client, key, volume_id, too_big)

        assert refused.status_code == 413, refused.text
        body = error(refused)
        assert body["code"] == "PAYLOAD_TOO_LARGE"
        assert "the volume was emptied" in body["message"]
        assert body["details"]["limit_bytes"] == STEP_LIMIT
        assert body["details"]["volume_emptied"] is True
        assert read_archive((await export(client, key, volume_id)).content) == {}
        (row,) = await audit_rows(app, org_id, RESTORE_ACTION)
        assert row.outcome is AuditOutcome.ERROR
        assert row.details["volume_emptied"] is True
        assert row.details["reason"].startswith("the archive holds more than")


async def test_restore_within_the_limit_still_works(make_app: Any) -> None:
    app = make_app(max_bytes=LIMIT)
    key = await add_key(app, await add_org(app))
    async with http_client(app) as client:
        volume_id = await new_volume(client, key)

        response = await restore(client, key, volume_id, make_archive({"f": b"x" * 100}))

        assert response.status_code == 200, response.text


async def test_restore_with_a_declared_length_over_the_upload_limit_is_413_before_the_body(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files={"keep": b"safe"})
    headers = {"Content-Length": str(MAX_UPLOAD_BYTES + 1)}

    refused = await restore(client, key, volume_id, b"tiny", headers=headers)

    assert refused.status_code == 413
    assert error(refused)["details"]["limit_bytes"] == MAX_UPLOAD_BYTES
    assert read_archive((await export(client, key, volume_id)).content) == {"keep": b"safe"}


async def test_restore_of_something_that_is_not_gzip_is_422_and_changes_nothing(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files={"keep": b"safe"})

    for body in (b"", b"plain text, not gzip", make_archive({"f": b"1"})[:-1] + b"?"):
        refused = await restore(client, key, volume_id, body)
        assert refused.status_code == 422, refused.text

    assert read_archive((await export(client, key, volume_id)).content) == {"keep": b"safe"}


async def test_restore_of_gzip_that_is_not_a_tar_is_422_and_leaves_the_volume_empty(
    client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await seeded_volume(client, key, files={"gone": b"soon"})

    refused = await restore(client, key, volume_id, gzip.compress(b"this is not a tar" * 100))

    assert refused.status_code == 422, refused.text
    assert "the volume was emptied" in error(refused)["message"]
    assert error(refused)["details"]["volume_emptied"] is True
    assert read_archive((await export(client, key, volume_id)).content) == {}


async def test_restore_needs_the_volumes_write_scope(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    volume_id = await new_volume(client, key)
    reader = await add_key(app, org_id, READ)

    refused = await restore(client, reader, volume_id, make_archive({"f": b"1"}))

    assert refused.status_code == 403


async def test_restore_of_a_missing_or_foreign_volume_is_not_found(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    other_key = await add_key(app, await add_org(app, "other"))
    foreign = await new_volume(client, other_key)
    archive = make_archive({"f": b"1"})

    assert (await restore(client, key, foreign, archive)).status_code == 404
    assert (await restore(client, key, "vol_missing", archive)).status_code == 404


async def test_restore_body_is_exempt_from_the_json_body_limit(make_app: Any) -> None:
    app = make_app(body_limit=1024)
    key = await add_key(app, await add_org(app))
    async with http_client(app) as client:
        volume_id = await new_volume(client, key)
        noisy = bytes(range(256)) * 64  # 16 KiB, past the 1 KiB limit once archived

        response = await restore(client, key, volume_id, make_archive({"noise": noisy}))

        assert response.status_code == 200, response.text


# -- restore: label scopes -------------------------------------------------------------------


async def test_scoped_key_restores_only_a_volume_it_owns(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    mine = await new_volume(client, key, "mine", OWNER)
    theirs = await new_volume(client, key, "theirs", {"team": "ops"})
    scoped = await add_key(app, org_id, FULL, OWNER)
    archive = make_archive({"f": b"1"})

    allowed = await restore(client, scoped, mine, archive)
    hidden = await restore(client, scoped, theirs, archive)

    assert allowed.status_code == 200, allowed.text
    assert hidden.status_code == 404


async def test_shared_labels_reach_is_not_a_restore_right(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, key: str
) -> None:
    pool = await seeded_volume(client, key, name="pool", labels=SHARED, files={"p": b"pool"})
    writer = await add_key(app, org_id, FULL, {"student": "3"}, SHARED)

    refused = await restore(client, writer, pool, make_archive({"evil": b"1"}))

    assert refused.status_code == 403
    assert "shared_volume_labels" in error(refused)["message"]
    assert "cannot be restored" in error(refused)["message"]
    assert read_archive((await export(client, key, pool)).content) == {"p": b"pool"}
    assert await audit_rows(app, org_id, RESTORE_ACTION) == []


async def test_a_second_restore_of_the_same_volume_is_refused_while_one_runs(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    volume_id = await new_volume(client, key)
    claims = app.state.volume_transfer.claims
    assert claims.try_claim(volume_id)

    refused = await restore(client, key, volume_id, make_archive({"f": b"1"}))
    exporting = await export(client, key, volume_id)

    assert refused.status_code == 409
    assert error(refused)["details"]["reason"] == "restore_in_progress"
    assert exporting.status_code == 409
    claims.release(volume_id)
    assert (await restore(client, key, volume_id, make_archive({"f": b"1"}))).status_code == 200
