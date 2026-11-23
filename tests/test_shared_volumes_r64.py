"""Shared read-only volumes for label-scoped keys (``shared_volume_labels``), round 64.

A teacher gives each student a key scoped to ``{persona: beatriz, student: 3}`` and wants the
class dataset volume (``{persona: beatriz, course: cs101}``) mounted read-only by every student.
Through the API on the fake driver and a temp SQLite database: a scoped key whose
``shared_volume_labels`` are contained in a volume's labels may list and get it and mount it
read-only, and nothing more. Then the SDK body and the CLI flag.
"""

import json
import sqlite3
import sys
from collections.abc import AsyncIterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from sandfort_cli import config as cli_config  # noqa: E402
from sandfort_cli.main import create_app as create_cli  # noqa: E402
from sandfort_sdk import Client  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

from sandfort.api.app import create_app  # noqa: E402
from sandfort.auth.api_keys import generate_api_key  # noqa: E402
from sandfort.config import Settings  # noqa: E402
from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.org import ApiKey, Org, Scope  # noqa: E402
from sandfort.ids import new_api_key_id, new_org_id  # noqa: E402
from sandfort.services.volumes import decode_mounts  # noqa: E402

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
VOLUMES = "/v1/volumes"
SANDBOXES = "/v1/sandboxes"
KEYS = "/v1/api-keys"
COURSE = {"course": "cs101"}
TEACHER = {"persona": "beatriz"}
DATASET_LABELS = {**TEACHER, **COURSE}
STUDENT = {**TEACHER, "student": "3"}
SANDBOX_SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
STUDENT_SCOPES = SANDBOX_SCOPES | {Scope.VOLUMES_READ}
FULL_ACCESS = SANDBOX_SCOPES | {Scope.VOLUMES_READ, Scope.VOLUMES_WRITE}
KEY_ADMIN = FULL_ACCESS | {Scope.API_KEYS_ADMIN}


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'shared.db'}"
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
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="School", slug="school", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def add_key(
    app: FastAPI,
    org_id: str,
    scopes: frozenset[Scope],
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


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def error(response: httpx.Response) -> dict[str, Any]:
    body: dict[str, Any] = response.json()["error"]
    return body


async def new_volume(
    client: httpx.AsyncClient, key: str, labels: dict[str, str] | None = None, name: str = "data"
) -> str:
    body: dict[str, Any] = {"name": name}
    if labels is not None:
        body["labels"] = labels
    response = await client.post(VOLUMES, headers=auth(key), json=body)
    assert response.status_code == 201, response.text
    volume_id: str = response.json()["data"]["id"]
    return volume_id


async def mount(
    client: httpx.AsyncClient, key: str, volume_id: str, **extra: Any
) -> httpx.Response:
    volumes = [{"volume_id": volume_id, "mount_path": "/data", **extra}]
    return await client.post(
        SANDBOXES, headers=auth(key), json={"labels": STUDENT, "volumes": volumes}
    )


@pytest.fixture
async def admin(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id, KEY_ADMIN)


@pytest.fixture
async def dataset(client: httpx.AsyncClient, admin: str) -> str:
    return await new_volume(client, admin, DATASET_LABELS, "cs101-data")


@pytest.fixture
async def student(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id, STUDENT_SCOPES, STUDENT, COURSE)


async def sandbox_count(app: FastAPI, org_id: str) -> int:
    async with UnitOfWork(app.state.session_factory) as uow:
        return len(await uow.sandboxes.list(org_id, limit=200))


# -- visibility ------------------------------------------------------------------------------


async def test_scoped_key_with_shared_labels_lists_and_gets_the_shared_volume(
    client: httpx.AsyncClient, dataset: str, student: str
) -> None:
    listed = await client.get(VOLUMES, headers=auth(student))
    assert [item["id"] for item in listed.json()["data"]] == [dataset]
    fetched = await client.get(f"{VOLUMES}/{dataset}", headers=auth(student))
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["data"]["labels"] == DATASET_LABELS


async def test_listing_merges_own_scope_and_shared_volumes_across_pages(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, dataset: str, student: str
) -> None:
    writer = await add_key(app, org_id, FULL_ACCESS, STUDENT, COURSE)
    own = await new_volume(client, writer, None, "scratch")
    ids = sorted([own, dataset])
    first = await client.get(VOLUMES, headers=auth(student), params={"limit": 1})
    assert [item["id"] for item in first.json()["data"]] == ids[:1]
    cursor = first.json()["meta"]["next_cursor"]
    assert cursor is not None
    second = await client.get(VOLUMES, headers=auth(student), params={"limit": 1, "cursor": cursor})
    assert [item["id"] for item in second.json()["data"]] == ids[1:]
    assert second.json()["meta"]["next_cursor"] is None


async def test_label_filter_applies_to_the_shared_volumes_too(
    client: httpx.AsyncClient, dataset: str, student: str
) -> None:
    hit = await client.get(VOLUMES, headers=auth(student), params={"label": "course=cs101"})
    assert [item["id"] for item in hit.json()["data"]] == [dataset]
    miss = await client.get(VOLUMES, headers=auth(student), params={"label": "course=cs202"})
    assert miss.json()["data"] == []


async def test_key_without_the_field_still_sees_nothing_of_the_dataset(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, dataset: str
) -> None:
    plain = await add_key(app, org_id, STUDENT_SCOPES, STUDENT)
    assert (await client.get(VOLUMES, headers=auth(plain))).json()["data"] == []
    assert (await client.get(f"{VOLUMES}/{dataset}", headers=auth(plain))).status_code == 404
    writer = await add_key(app, org_id, FULL_ACCESS, STUDENT)
    # r65: a volume the key cannot see at all stays a 404 on delete (no shared labels to name)
    assert (await client.delete(f"{VOLUMES}/{dataset}", headers=auth(writer))).status_code == 404
    refused = await mount(client, plain, dataset, read_only=True)
    assert refused.status_code == 403
    assert "cannot mount volumes outside that scope" in error(refused)["message"]


async def test_other_volumes_stay_hidden_and_unmountable(
    client: httpx.AsyncClient, admin: str, dataset: str, student: str
) -> None:
    other_course = await new_volume(client, admin, {**TEACHER, "course": "cs202"}, "other")
    unlabelled = await new_volume(client, admin, None, "bare")
    partial = await new_volume(client, admin, TEACHER, "teacher-only")
    listed = await client.get(VOLUMES, headers=auth(student))
    assert [item["id"] for item in listed.json()["data"]] == [dataset]
    for hidden in (other_course, unlabelled, partial):
        assert (await client.get(f"{VOLUMES}/{hidden}", headers=auth(student))).status_code == 404
        refused = await mount(client, student, hidden, read_only=True)
        assert refused.status_code == 403, refused.text
        assert "outside that scope" in error(refused)["message"]


# -- mounting --------------------------------------------------------------------------------


async def test_shared_volume_mounts_read_only(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, dataset: str, student: str
) -> None:
    response = await mount(client, student, dataset, read_only=True)
    assert response.status_code == 201, response.text
    async with UnitOfWork(app.state.session_factory) as uow:
        sandbox = await uow.sandboxes.get(org_id, response.json()["data"]["id"])
    assert sandbox is not None
    (recorded,) = decode_mounts(sandbox.labels)
    assert (recorded.volume_id, recorded.read_only) == (dataset, True)


async def test_read_write_mount_of_a_shared_volume_is_refused_naming_the_rule(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, dataset: str
) -> None:
    writer = await add_key(app, org_id, FULL_ACCESS, STUDENT, COURSE)
    for extra in ({}, {"read_only": False}):
        refused = await mount(client, writer, dataset, **extra)
        assert refused.status_code == 403, refused.text
        message = error(refused)["message"]
        assert "shared_volume_labels" in message
        assert "read-only" in message
        assert "course=cs101" in message
        assert dataset in message
    assert await sandbox_count(app, org_id) == 0


async def test_own_scope_volume_still_mounts_read_write(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    writer = await add_key(app, org_id, FULL_ACCESS, STUDENT, COURSE)
    own = await new_volume(client, writer, None, "scratch")
    assert (await mount(client, writer, own)).status_code == 201


async def test_volume_in_both_scope_and_shared_labels_keeps_read_write(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, admin: str
) -> None:
    writer = await add_key(app, org_id, FULL_ACCESS, STUDENT, {"student": "3"})
    own = await new_volume(client, admin, STUDENT, "scratch")  # the key itself cannot publish it
    assert (await mount(client, writer, own)).status_code == 201


async def test_mounting_the_shared_volume_still_needs_volumes_read(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, dataset: str
) -> None:
    blind = await add_key(app, org_id, SANDBOX_SCOPES, STUDENT, COURSE)
    refused = await mount(client, blind, dataset, read_only=True)
    assert refused.status_code == 403
    assert "volumes:read" in error(refused)["message"]


# -- no write access -------------------------------------------------------------------------


async def test_shared_volume_cannot_be_deleted_or_updated_by_the_scoped_key(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, dataset: str
) -> None:
    writer = await add_key(app, org_id, FULL_ACCESS, STUDENT, COURSE)
    deleted = await client.delete(f"{VOLUMES}/{dataset}", headers=auth(writer))
    # r65: the key sees the volume, so a delete is a 403 naming the shared labels (was 404)
    assert deleted.status_code == 403
    message = error(deleted)["message"]
    assert f"volume {dataset} is shared with this API key" in message
    assert "shared_volume_labels course=cs101" in message
    assert "cannot be deleted; only a key that owns its labels can delete it" in message
    for verb in ("PATCH", "PUT"):
        sent = await client.request(verb, f"{VOLUMES}/{dataset}", headers=auth(writer), json={})
        assert sent.status_code in (404, 405)
    still_there = await client.get(f"{VOLUMES}/{dataset}", headers=auth(writer))
    assert still_there.status_code == 200
    assert still_there.json()["data"]["name"] == "cs101-data"


async def test_created_volume_does_not_inherit_the_shared_labels(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    writer = await add_key(app, org_id, FULL_ACCESS, STUDENT, COURSE)
    own = await new_volume(client, writer, None, "scratch")
    labels = (await client.get(f"{VOLUMES}/{own}", headers=auth(writer))).json()["data"]["labels"]
    assert labels == STUDENT


# -- publishing into the shared pool --------------------------------------------------------


async def test_key_with_shared_labels_cannot_create_a_volume_carrying_them(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, student: str
) -> None:
    writer = await add_key(app, org_id, FULL_ACCESS, STUDENT, COURSE)
    response = await client.post(
        VOLUMES, headers=auth(writer), json={"name": "planted", "labels": COURSE}
    )
    assert response.status_code == 403
    body = error(response)
    assert body["code"] == "FORBIDDEN"
    assert "cannot create volumes carrying its shared_volume_labels (course=cs101)" in (
        body["message"]
    )
    assert "only a key without them can publish shared data" in body["message"]
    listed = await client.get(VOLUMES, headers=auth(student))
    assert listed.json()["data"] == []


async def test_refused_create_leaves_no_volume_behind(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, admin: str
) -> None:
    writer = await add_key(app, org_id, FULL_ACCESS, STUDENT, COURSE)
    await client.post(VOLUMES, headers=auth(writer), json={"name": "planted", "labels": COURSE})
    listed = await client.get(VOLUMES, headers=auth(admin))
    assert listed.json()["data"] == []


async def test_key_with_shared_labels_may_create_a_volume_with_other_labels(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    writer = await add_key(app, org_id, FULL_ACCESS, STUDENT, COURSE)
    response = await client.post(
        VOLUMES, headers=auth(writer), json={"name": "mine", "labels": {"course": "cs102"}}
    )
    assert response.status_code == 201


async def test_key_with_only_some_of_its_shared_labels_may_create(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    shared = {**COURSE, "share": "cs101-data"}
    writer = await add_key(app, org_id, FULL_ACCESS, STUDENT, shared)
    response = await client.post(
        VOLUMES, headers=auth(writer), json={"name": "mine", "labels": COURSE}
    )
    assert response.status_code == 201


async def test_scope_labels_inside_the_shared_labels_are_refused_too(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    writer = await add_key(app, org_id, FULL_ACCESS, STUDENT, {"student": "3"})
    response = await client.post(VOLUMES, headers=auth(writer), json={"name": "mine"})
    assert response.status_code == 403


async def test_unscoped_key_still_publishes_shared_data(
    client: httpx.AsyncClient, admin: str, dataset: str
) -> None:
    assert dataset.startswith("vol_")


# -- the field on the key API ----------------------------------------------------------------


async def make_key(client: httpx.AsyncClient, creator: str, **extra: Any) -> httpx.Response:
    body = {
        "name": "student-3",
        "scopes": ["sandboxes:read", "sandboxes:write", "volumes:read"],
        **extra,
    }
    return await client.post(KEYS, headers=auth(creator), json=body)


async def test_admin_creates_a_key_with_shared_labels_and_it_works(
    client: httpx.AsyncClient, admin: str, dataset: str
) -> None:
    created = await make_key(client, admin, sandbox_labels=STUDENT, shared_volume_labels=COURSE)
    assert created.status_code == 201, created.text
    data = created.json()["data"]
    assert data["shared_volume_labels"] == COURSE
    listed = await client.get(KEYS, headers=auth(admin))
    by_id = {row["id"]: row for row in listed.json()["data"]}
    assert by_id[data["id"]]["shared_volume_labels"] == COURSE
    assert (await mount(client, data["key"], dataset, read_only=True)).status_code == 201


async def test_key_without_the_field_reports_null(client: httpx.AsyncClient, admin: str) -> None:
    created = await make_key(client, admin, sandbox_labels=STUDENT)
    assert created.status_code == 201, created.text
    assert created.json()["data"]["shared_volume_labels"] is None
    bare = await make_key(client, admin)
    assert bare.json()["data"]["shared_volume_labels"] is None


async def test_empty_shared_labels_mean_none(client: httpx.AsyncClient, admin: str) -> None:
    created = await make_key(client, admin, sandbox_labels=STUDENT, shared_volume_labels={})
    assert created.status_code == 201, created.text
    assert created.json()["data"]["shared_volume_labels"] is None


@pytest.mark.parametrize(
    "shared",
    [
        {f"k{i}": "v" for i in range(9)},
        {"k" * 64: "v"},
        {"course": "v" * 257},
        {"sandfort.secret": "x"},
        {"course": 3},
        ["course=cs101"],
        {"": "v"},
    ],
    ids=["too-many", "long-key", "long-value", "reserved", "non-string", "not-a-map", "empty-key"],
)
async def test_shared_labels_are_validated_like_sandbox_labels(
    client: httpx.AsyncClient, admin: str, shared: Any
) -> None:
    response = await make_key(client, admin, sandbox_labels=STUDENT, shared_volume_labels=shared)
    assert response.status_code == 422, response.text


async def test_shared_labels_need_a_label_scope(client: httpx.AsyncClient, admin: str) -> None:
    response = await make_key(client, admin, shared_volume_labels=COURSE)
    assert response.status_code == 422, response.text
    assert "sandbox_labels" in json.dumps(response.json())


async def test_key_that_cannot_create_keys_cannot_set_the_field(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    plain = await add_key(app, org_id, FULL_ACCESS)
    response = await make_key(client, plain, sandbox_labels=STUDENT, shared_volume_labels=COURSE)
    assert response.status_code == 403, response.text


async def test_scoped_creator_cannot_share_volumes_beyond_its_own_reach(
    app: FastAPI, client: httpx.AsyncClient, org_id: str
) -> None:
    creator = await add_key(app, org_id, KEY_ADMIN, STUDENT, COURSE)
    child_labels = {**STUDENT, "group": "x"}
    # Inside the creator's reach: narrower than its own scope or than its own shared labels.
    inside_scope = await make_key(
        client, creator, sandbox_labels=child_labels, shared_volume_labels=STUDENT
    )
    assert inside_scope.status_code == 201, inside_scope.text
    inside_shared = await make_key(
        client,
        creator,
        sandbox_labels=child_labels,
        shared_volume_labels={**COURSE, "unit": "1"},
    )
    assert inside_shared.status_code == 201, inside_shared.text
    # Outside: any volume labelled only with another course would be newly reachable.
    outside = await make_key(
        client, creator, sandbox_labels=child_labels, shared_volume_labels={"course": "cs202"}
    )
    assert outside.status_code == 403, outside.text
    assert "shared_volume_labels" in error(outside)["message"]


async def test_creating_the_key_is_audited_with_the_shared_labels(
    app: FastAPI, client: httpx.AsyncClient, org_id: str, admin: str
) -> None:
    created = await make_key(client, admin, sandbox_labels=STUDENT, shared_volume_labels=COURSE)
    key_id = created.json()["data"]["id"]
    reader = await add_key(app, org_id, frozenset({Scope.AUDIT_READ}))
    listed = await client.get(
        "/v1/audit-events", headers=auth(reader), params={"target_id": key_id, "limit": 10}
    )
    assert listed.status_code == 200, listed.text
    (event,) = listed.json()["data"]
    assert event["details"]["shared_volume_labels"] == COURSE


# -- migration -------------------------------------------------------------------------------


def column_names(db_path: Path) -> set[str]:
    with closing(sqlite3.connect(db_path)) as connection:
        return {row[1] for row in connection.execute("PRAGMA table_info(api_keys)")}


def test_migration_adds_and_drops_the_column(tmp_path: Path) -> None:
    db_path = tmp_path / "migration.db"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    command.upgrade(config, "0022")
    assert "shared_volume_labels" not in column_names(db_path)
    command.upgrade(config, "0023")
    assert "shared_volume_labels" in column_names(db_path)
    command.downgrade(config, "0022")
    assert "shared_volume_labels" not in column_names(db_path)
    assert {"sandbox_labels", "max_sandboxes"} <= column_names(db_path)


# -- SDK and CLI -----------------------------------------------------------------------------

BASE = "http://sandfort.test"
SECRET = "sf_new_secret_shown_once"


def key_payload(**extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "key_1",
        "name": "student-3",
        "prefix": "sf_abcd",
        "scopes": ["sandboxes:read", "volumes:read"],
        "sandbox_labels": STUDENT,
        "max_sandboxes": None,
        "shared_volume_labels": COURSE,
        "created_at": "2026-11-11T10:00:00+00:00",
        "last_used_at": None,
        "expires_at": None,
        "revoked_at": None,
        "created_by": None,
        "key": SECRET,
    }
    return {**base, **extra}


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def test_sdk_create_api_key_sends_and_reads_shared_volume_labels() -> None:
    with respx.mock(base_url=BASE) as api:
        route = api.post(KEYS).respond(201, json=envelope(key_payload()))
        created = Client(BASE, "sf_key").create_api_key(
            "student-3",
            ["sandboxes:read", "volumes:read"],
            sandbox_labels=STUDENT,
            shared_volume_labels=COURSE,
        )
    assert json.loads(route.calls.last.request.content)["shared_volume_labels"] == COURSE
    assert created.shared_volume_labels == COURSE


def test_sdk_omits_the_field_when_not_given_and_reads_null() -> None:
    with respx.mock(base_url=BASE) as api:
        route = api.post(KEYS).respond(201, json=envelope(key_payload(shared_volume_labels=None)))
        created = Client(BASE, "sf_key").create_api_key("ci", ["toolbox"])
    assert "shared_volume_labels" not in json.loads(route.calls.last.request.content)
    assert created.shared_volume_labels is None


def test_sdk_reads_a_server_that_predates_the_field() -> None:
    payload = key_payload()
    del payload["shared_volume_labels"]
    with respx.mock(base_url=BASE) as api:
        api.post(KEYS).respond(201, json=envelope(payload))
        created = Client(BASE, "sf_key").create_api_key("ci", ["toolbox"])
    assert created.shared_volume_labels is None


def test_sdk_refuses_shared_labels_without_sandbox_labels_before_sending() -> None:
    with respx.mock(base_url=BASE, assert_all_called=False) as api:
        route = api.post(KEYS).respond(201, json=envelope(key_payload()))
        with pytest.raises(ValueError, match="sandbox_labels"):
            Client(BASE, "sf_key").create_api_key("ci", ["toolbox"], shared_volume_labels=COURSE)
    assert not route.called


@pytest.fixture
def cli_profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(cli_config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(cli_config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(cli_config.API_KEY_ENV, raising=False)
    cli_config.save_profile(BASE, "sf_profile_key")


@pytest.mark.usefixtures("cli_profile")
def test_cli_key_create_takes_repeatable_shared_volume_label_flags() -> None:
    with respx.mock(base_url=BASE) as api:
        route = api.post(KEYS).respond(
            201, json=envelope(key_payload(shared_volume_labels={**COURSE, "unit": "1"}))
        )
        result = CliRunner().invoke(
            create_cli(),
            [
                "--json", "key", "create", "student-3", "-s", "volumes:read",
                "--label", "persona=beatriz", "--label", "student=3",
                "--shared-volume-label", "course=cs101", "--shared-volume-label", "unit=1",
            ],
        )  # fmt: skip
    assert result.exit_code == 0, result.output
    body = json.loads(route.calls.last.request.content)
    assert body["shared_volume_labels"] == {"course": "cs101", "unit": "1"}
    assert json.loads(result.stdout)["shared_volume_labels"] == {"course": "cs101", "unit": "1"}


@pytest.mark.usefixtures("cli_profile")
def test_cli_shared_volume_label_needs_a_label_and_a_pair() -> None:
    runner = CliRunner()
    bare = runner.invoke(
        create_cli(), ["key", "create", "ci", "-s", "volumes:read", "--shared-volume-label", "a=b"]
    )
    assert bare.exit_code == 2
    assert "--label" in bare.output
    malformed = runner.invoke(
        create_cli(),
        ["key", "create", "ci", "-s", "x", "-l", "t=a", "--shared-volume-label", "nope"],
    )
    assert malformed.exit_code == 2
