"""Auth tests: key format and hashing, Bearer dependency (401/403), admin bootstrap.

Daemon-free. Dependency tests drive a tiny FastAPI app in-process through the real
async SQLite repositories; they skip when ``aiosqlite``/``greenlet`` are missing.
"""

import asyncio
import hmac
import inspect
import json
import re
import sqlite3
from collections.abc import AsyncIterator, Callable
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from typer.testing import CliRunner

from sandfort import admin_cli
from sandfort.auth import api_keys
from sandfort.auth.api_keys import generate_api_key, hash_api_key, parse_prefix, verify_api_key
from sandfort.auth.authenticate import AuthContext, authenticate, install_auth
from sandfort.auth.label_scope import current_label_scope, matches, set_label_scope
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import ALL_SCOPES, check_scopes, require_scopes
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.errors import Forbidden, SandfortError, ValidationFailed
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
KEY_PATTERN = re.compile(r"sf_live_[a-z0-9]{8}_[A-Za-z0-9_-]{43}")
SECRET_43 = "a" * 43
READ_ONLY = frozenset({Scope.SANDBOXES_READ})
BOOTSTRAP_ACME = ["bootstrap", "--org-name", "Acme", "--org-slug", "acme"]
CREATE_OTHER = ["create-org", "--org-name", "Other", "--org-slug", "other"]
BOOTSTRAP_OTHER = ["bootstrap", "--org-name", "Other", "--org-slug", "other"]

Factory = async_sessionmaker[AsyncSession]


# --- fixtures and helpers -------------------------------------------------------


def requires_async_sqlite() -> None:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")


@pytest.fixture
async def factory(tmp_path: Path) -> AsyncIterator[Factory]:
    requires_async_sqlite()
    db_path = tmp_path / "sandfort.db"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    command.upgrade(config, "head")
    engine = create_engine(Settings(database_url=f"sqlite+aiosqlite:///{db_path}"))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(NOW)


@pytest.fixture
async def org(factory: Factory) -> Org:
    created = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(factory) as uow:
        await uow.orgs.add(created)
        await uow.commit()
    return created


def build_app(context: AuthContext | None) -> FastAPI:
    app = FastAPI()
    if context is not None:
        install_auth(app, context)

    @app.exception_handler(SandfortError)
    async def handle(_request: Request, exc: SandfortError) -> JSONResponse:
        body = {"code": exc.code, "message": exc.message, "details": exc.details}
        return JSONResponse(status_code=exc.status, content=body)

    @app.get("/whoami")
    async def whoami(principal: Annotated[Principal, Depends(authenticate)]) -> dict[str, Any]:
        return {
            "org_id": principal.org_id,
            "key_id": principal.key_id,
            "scopes": sorted(scope.value for scope in principal.scopes),
            "is_platform_admin": principal.is_platform_admin,
        }

    @app.get("/label-scope")
    async def label_scope_route(
        principal: Annotated[Principal, Depends(require_scopes(Scope.SANDBOXES_READ))],
    ) -> dict[str, Any]:
        held, scope = principal.sandbox_labels, current_label_scope()
        return {
            "principal": None if held is None else dict(held),
            "context": None if scope is None else dict(scope),
        }

    @app.post("/sandboxes")
    async def create_sandbox(
        principal: Annotated[Principal, Depends(require_scopes(Scope.SANDBOXES_WRITE))],
    ) -> dict[str, str]:
        return {"org_id": principal.org_id}

    return app


def open_client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


@pytest.fixture
async def client(factory: Factory, clock: FrozenClock) -> AsyncIterator[httpx.AsyncClient]:
    context = AuthContext(pepper=PEPPER, uow_factory=lambda: UnitOfWork(factory), clock=clock)
    async with open_client(build_app(context)) as http:
        yield http


async def seed_key(
    factory: Factory,
    org_id: str,
    *,
    scopes: frozenset[Scope] = READ_ONLY,
    revoked_at: datetime | None = None,
    expires_at: datetime | None = None,
    sandbox_labels: dict[str, str] | None = None,
) -> tuple[str, ApiKey]:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
        sandbox_labels=sandbox_labels,
        revoked_at=revoked_at,
        expires_at=expires_at,
        created_at=NOW - timedelta(days=1),
    )
    async with UnitOfWork(factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key, stored


async def stored_key(factory: Factory, prefix: str) -> ApiKey:
    async with UnitOfWork(factory) as uow:
        found = await uow.api_keys.get_by_prefix(prefix)
    assert found is not None
    return found


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def assert_error(response: httpx.Response, status: int, code: str) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    assert body["code"] == code
    return body


# --- key format, hashing, verification ------------------------------------------


def test_generated_key_has_documented_format_and_prefix() -> None:
    generated = generate_api_key(PEPPER)

    assert KEY_PATTERN.fullmatch(generated.key)
    assert parse_prefix(generated.key) == generated.prefix
    assert generated.key.startswith(generated.prefix + "_")
    assert generated.key not in generated.secret_hash
    assert verify_api_key(PEPPER, generated.key, generated.secret_hash)
    assert generate_api_key(PEPPER, env="test").key.startswith("sf_test_")
    assert generate_api_key(PEPPER).key != generated.key


def test_generate_rejects_invalid_env() -> None:
    with pytest.raises(ValueError):
        generate_api_key(PEPPER, env="Live_1")


@pytest.mark.parametrize(
    "key",
    [
        "",
        "not-a-key",
        f"xx_live_abcdefgh_{SECRET_43}",
        f"sf_live_abcdefg_{SECRET_43}",
        f"sf_live_ABCDEFGH_{SECRET_43}",
        f"sf_live_abcdefgh_{SECRET_43[:-1]}",
        f"sf_live_abcdefgh_{SECRET_43}!",
    ],
)
def test_parse_prefix_rejects_malformed_keys(key: str) -> None:
    with pytest.raises(ValueError):
        parse_prefix(key)


def test_hash_is_salted_peppered_and_fits_column() -> None:
    key = generate_api_key(PEPPER).key

    first, second = hash_api_key(PEPPER, key), hash_api_key(PEPPER, key)

    assert first != second
    assert first.startswith("v1$") and len(first) <= 128
    assert verify_api_key(PEPPER, key, first)
    assert verify_api_key(PEPPER, key, second)
    assert not verify_api_key("other-pepper", key, first)
    assert not verify_api_key(PEPPER, generate_api_key(PEPPER).key, first)


@pytest.mark.parametrize(
    "stored_hash",
    ["", "plain", "v1$00", "v2$00$ab", "v1$zz$ab", "v1$abc$ab", "v1$00$é", "v1$$ab"],
)
def test_verify_rejects_malformed_stored_hash(stored_hash: str) -> None:
    assert not verify_api_key(PEPPER, generate_api_key(PEPPER).key, stored_hash)


def test_verification_uses_hmac_compare_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    source = inspect.getsource(api_keys.verify_api_key)
    assert "hmac.compare_digest(" in source
    assert "==" not in source

    calls: list[tuple[bytes, bytes]] = []
    real_compare = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return real_compare(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    generated = generate_api_key(PEPPER)
    assert verify_api_key(PEPPER, generated.key, generated.secret_hash)
    assert len(calls) == 1


def test_check_scopes_reports_every_missing_scope() -> None:
    principal = Principal(org_id="org_x", key_id="key_x", scopes=frozenset({Scope.TOOLBOX}))

    check_scopes(principal, [Scope.TOOLBOX])
    with pytest.raises(Forbidden) as caught:
        check_scopes(principal, [Scope.TOOLBOX, Scope.SANDBOXES_WRITE, Scope.AUDIT_READ])

    assert caught.value.details == {"missing_scopes": ["audit:read", "sandboxes:write"]}
    assert ALL_SCOPES == frozenset(Scope)


# --- Bearer dependency ----------------------------------------------------------


async def test_valid_key_resolves_principal_and_touches_last_used(
    factory: Factory, org: Org, client: httpx.AsyncClient
) -> None:
    key, stored = await seed_key(factory, org.id)

    response = await client.get("/whoami", headers=bearer(key))

    assert response.status_code == 200, response.text
    assert response.json() == {
        "org_id": org.id,
        "key_id": stored.id,
        "scopes": ["sandboxes:read"],
        "is_platform_admin": False,
    }
    assert (await stored_key(factory, stored.prefix)).last_used_at == NOW


async def test_a_scoped_key_principal_carries_the_labels_and_sets_the_context_var(
    factory: Factory, org: Org, client: httpx.AsyncClient
) -> None:
    labels = {"team": "gov", "bot": "a1"}
    key, stored = await seed_key(factory, org.id, sandbox_labels=labels)

    response = await client.get("/label-scope", headers=bearer(key))

    assert response.status_code == 200, response.text
    assert response.json() == {"principal": labels, "context": labels}
    assert (await stored_key(factory, stored.prefix)).sandbox_labels == labels


async def test_an_unscoped_key_principal_has_no_label_scope(
    factory: Factory, org: Org, client: httpx.AsyncClient
) -> None:
    key, stored = await seed_key(factory, org.id)

    response = await client.get("/label-scope", headers=bearer(key))

    assert response.status_code == 200, response.text
    assert response.json() == {"principal": None, "context": None}
    assert (await stored_key(factory, stored.prefix)).sandbox_labels is None


async def test_an_empty_label_dict_is_stored_as_unscoped(factory: Factory, org: Org) -> None:
    key, stored = await seed_key(factory, org.id, sandbox_labels={})

    assert stored.sandbox_labels is None
    assert (await stored_key(factory, stored.prefix)).sandbox_labels is None
    assert key


def test_set_label_scope_returns_a_token_that_restores_the_previous_scope() -> None:
    assert current_label_scope() is None

    token = set_label_scope({"team": "gov"})
    assert current_label_scope() == {"team": "gov"}
    inner = set_label_scope(None)
    assert current_label_scope() is None
    inner.var.reset(inner)
    assert current_label_scope() == {"team": "gov"}
    token.var.reset(token)

    assert current_label_scope() is None


@pytest.mark.parametrize(
    ("labels", "scope", "expected"),
    [
        ({"team": "gov"}, None, True),
        ({}, None, True),
        ({"team": "gov"}, {"team": "gov"}, True),
        ({"team": "gov", "env": "prod"}, {"team": "gov"}, True),
        ({"team": "gov", "env": "prod"}, {"team": "gov", "env": "prod"}, True),
        ({"team": "gov"}, {"team": "ops"}, False),
        ({"team": "gov"}, {"team": "gov", "env": "prod"}, False),
        ({"env": "prod"}, {"team": "gov"}, False),
        ({}, {"team": "gov"}, False),
        ({"team": ""}, {"team": ""}, True),
        ({}, {}, True),
    ],
)
def test_matches_truth_table(
    labels: dict[str, str], scope: dict[str, str] | None, expected: bool
) -> None:
    assert matches(labels, scope) is expected


async def test_last_used_is_debounced(
    factory: Factory, org: Org, clock: FrozenClock, client: httpx.AsyncClient
) -> None:
    key, stored = await seed_key(factory, org.id)
    assert (await client.get("/whoami", headers=bearer(key))).status_code == 200

    clock.advance(timedelta(seconds=30))
    assert (await client.get("/whoami", headers=bearer(key))).status_code == 200
    assert (await stored_key(factory, stored.prefix)).last_used_at == NOW

    later = clock.advance(timedelta(seconds=60))
    assert (await client.get("/whoami", headers=bearer(key))).status_code == 200
    assert (await stored_key(factory, stored.prefix)).last_used_at == later


def _tamper(key: str) -> dict[str, str]:
    return bearer(key[:-1] + ("B" if key[-1] == "A" else "A"))


@pytest.mark.parametrize(
    "headers_for",
    [
        pytest.param(_tamper, id="wrong-secret"),
        pytest.param(lambda _key: bearer(generate_api_key(PEPPER).key), id="unknown-prefix"),
        pytest.param(lambda _key: bearer("not-a-key"), id="malformed"),
        pytest.param(lambda _key: {}, id="missing-header"),
        pytest.param(lambda key: {"Authorization": f"Basic {key}"}, id="wrong-scheme"),
        pytest.param(lambda _key: {"Authorization": "Bearer"}, id="empty-token"),
    ],
)
async def test_wrong_key_yields_401(
    factory: Factory,
    org: Org,
    client: httpx.AsyncClient,
    headers_for: Callable[[str], dict[str, str]],
) -> None:
    key, _ = await seed_key(factory, org.id)

    response = await client.get("/whoami", headers=headers_for(key))

    assert_error(response, 401, "UNAUTHORIZED")


async def test_revoked_key_yields_401(
    factory: Factory, org: Org, client: httpx.AsyncClient
) -> None:
    key, _ = await seed_key(factory, org.id, revoked_at=NOW - timedelta(hours=1))

    body = assert_error(await client.get("/whoami", headers=bearer(key)), 401, "UNAUTHORIZED")

    assert "revoked" in body["message"]


@pytest.mark.parametrize("offset", [timedelta(seconds=-1), timedelta(0)])
async def test_expired_key_yields_401(
    factory: Factory, org: Org, client: httpx.AsyncClient, offset: timedelta
) -> None:
    key, _ = await seed_key(factory, org.id, expires_at=NOW + offset)

    body = assert_error(await client.get("/whoami", headers=bearer(key)), 401, "UNAUTHORIZED")

    assert "expired" in body["message"]


async def test_key_with_future_expiry_is_accepted(
    factory: Factory, org: Org, client: httpx.AsyncClient
) -> None:
    key, _ = await seed_key(factory, org.id, expires_at=NOW + timedelta(hours=1))

    assert (await client.get("/whoami", headers=bearer(key))).status_code == 200


async def test_missing_scope_yields_403(
    factory: Factory, org: Org, client: httpx.AsyncClient
) -> None:
    read_only, _ = await seed_key(factory, org.id)
    writer, _ = await seed_key(factory, org.id, scopes=frozenset({Scope.SANDBOXES_WRITE}))

    denied = await client.post("/sandboxes", headers=bearer(read_only))
    allowed = await client.post("/sandboxes", headers=bearer(writer))

    body = assert_error(denied, 403, "FORBIDDEN")
    assert body["details"] == {"missing_scopes": ["sandboxes:write"]}
    assert allowed.status_code == 200
    assert allowed.json() == {"org_id": org.id}


async def test_scope_check_requires_authentication_first(client: httpx.AsyncClient) -> None:
    assert_error(await client.post("/sandboxes"), 401, "UNAUTHORIZED")


async def test_unconfigured_app_fails_closed() -> None:
    async with open_client(build_app(None)) as http:
        response = await http.get("/whoami", headers=bearer(generate_api_key(PEPPER).key))

    assert_error(response, 500, "INTERNAL")


# --- sandfort-admin bootstrap ---------------------------------------------------


@pytest.fixture
def admin_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    requires_async_sqlite()
    db_path = tmp_path / "admin.db"
    monkeypatch.setenv("SANDFORT_DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("SANDFORT_API_KEY_PEPPER", PEPPER)
    return db_path


def read_rows(db_path: Path, table: str) -> list[sqlite3.Row]:
    with closing(sqlite3.connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        return list(connection.execute(f"SELECT * FROM {table}"))


def test_bootstrap_prints_key_once_and_second_bootstrap_refuses(admin_env: Path) -> None:
    runner = CliRunner()
    migrated = runner.invoke(admin_cli.app, ["migrate"])
    assert migrated.exit_code == 0, migrated.output

    first = runner.invoke(admin_cli.app, BOOTSTRAP_ACME)
    second = runner.invoke(admin_cli.app, BOOTSTRAP_OTHER)

    assert first.exit_code == 0, first.output
    keys = KEY_PATTERN.findall(first.stdout)
    assert len(keys) == 1
    assert first.output.count(keys[0]) == 1
    assert second.exit_code == 1
    assert KEY_PATTERN.findall(second.output) == []
    assert "already bootstrapped" in second.output

    [org_row] = read_rows(admin_env, "organizations")
    [key_row] = read_rows(admin_env, "api_keys")
    assert org_row["slug"] == "acme"
    assert key_row["org_id"] == org_row["id"]
    assert key_row["is_platform_admin"] == 1
    assert key_row["prefix"] == parse_prefix(keys[0])
    assert set(json.loads(key_row["scopes"])) == {scope.value for scope in Scope}
    assert all(keys[0] not in str(value) for value in tuple(key_row))
    assert verify_api_key(PEPPER, keys[0], key_row["secret_hash"])


def test_bootstrap_requires_pepper(admin_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SANDFORT_API_KEY_PEPPER")

    result = CliRunner().invoke(admin_cli.app, BOOTSTRAP_ACME)

    assert result.exit_code == 1
    assert "SANDFORT_API_KEY_PEPPER" in result.output
    assert KEY_PATTERN.findall(result.output) == []


@pytest.mark.parametrize(
    ("name", "slug"), [("Acme", "Not A Slug"), ("Acme", "-acme"), ("   ", "acme")]
)
def test_bootstrap_validates_org_input(name: str, slug: str) -> None:
    with pytest.raises(ValidationFailed):
        admin_cli.bootstrap(name, slug)


def whoami_org_id(db_path: Path, key: str) -> tuple[int, str | None]:
    async def call() -> tuple[int, str | None]:
        engine = create_engine(Settings(database_url=f"sqlite+aiosqlite:///{db_path}"))
        try:
            factory = create_session_factory(engine)
            context = AuthContext(
                pepper=PEPPER, uow_factory=lambda: UnitOfWork(factory), clock=FrozenClock(NOW)
            )
            async with open_client(build_app(context)) as http:
                response = await http.get("/whoami", headers=bearer(key))
        finally:
            await engine.dispose()
        body = response.json()
        return response.status_code, body.get("org_id") if response.is_success else None

    return asyncio.run(call())


def test_create_org_adds_isolated_org_and_refuses_duplicate_slug(admin_env: Path) -> None:
    runner = CliRunner()
    assert runner.invoke(admin_cli.app, ["migrate"]).exit_code == 0
    first = runner.invoke(admin_cli.app, BOOTSTRAP_ACME)
    second = runner.invoke(admin_cli.app, CREATE_OTHER)
    duplicate = runner.invoke(admin_cli.app, CREATE_OTHER)
    rebootstrap = runner.invoke(admin_cli.app, BOOTSTRAP_OTHER)

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    [acme_key] = KEY_PATTERN.findall(first.stdout)
    [other_key] = KEY_PATTERN.findall(second.stdout)
    assert second.output.count(other_key) == 1
    assert "Store this key now" in second.output
    assert duplicate.exit_code == 1
    assert "already exists" in duplicate.output
    assert KEY_PATTERN.findall(duplicate.output) == []
    assert rebootstrap.exit_code == 1
    assert "already bootstrapped" in rebootstrap.output

    org_ids = {row["slug"]: row["id"] for row in read_rows(admin_env, "organizations")}
    assert set(org_ids) == {"acme", "other"}
    assert len(read_rows(admin_env, "api_keys")) == 2
    assert whoami_org_id(admin_env, acme_key) == (200, org_ids["acme"])
    assert whoami_org_id(admin_env, other_key) == (200, org_ids["other"])
