"""``SANDFORT_DEFAULT_BLOCK_NETWORK``: the deployment default for a create naming no policy.

Through the api (FakeDriver, temp SQLite). Only an unset ``network.block_all`` takes the
default; an explicit value, and a create with a non-empty egress allowlist, keep what they
asked for. An empty allowlist always blocks the network.
"""

from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
PROXY_SETTINGS = {"egress_proxy_address": "proxy.internal:3128", "egress_secret": "e" * 40}

AppFactory = Callable[..., FastAPI]


@pytest.fixture
async def make_app(tmp_path: Path) -> AsyncIterator[AppFactory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    built: list[FastAPI] = []

    def build(**overrides: Any) -> FastAPI:
        url = f"sqlite+aiosqlite:///{tmp_path / f'default-net-{len(built)}.db'}"
        config = Config(str(ROOT / "alembic.ini"))
        config.set_main_option("sqlalchemy.url", url)
        command.upgrade(config, "head")
        settings = Settings(
            driver="fake",
            database_url=url,
            api_key_pepper=PEPPER,
            autostop_enabled=False,
            **overrides,
        )
        app = create_app(settings)
        built.append(app)
        return app

    yield build
    for app in built:
        await app.state.engine.dispose()


async def connect(app: FastAPI) -> str:
    """A fresh org and a plaintext read-write API key for it."""
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=READ_WRITE,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def create(app: FastAPI, key: str, **body: Any) -> dict[str, Any]:
    """Create a sandbox, check it was accepted, and return its response data."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        response = await http.post(BASE, headers={"Authorization": f"Bearer {key}"}, json=body)
    assert response.status_code == 201, response.text
    data: dict[str, Any] = response.json()["data"]
    return data


# -- the default is on ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [{}, {"network": {}}, {"network": None}, {"network": {"block_all": None}}],
    ids=["no-network", "empty-network", "null-network", "null-block-all"],
)
async def test_with_the_default_on_an_unset_block_all_is_blocked(
    make_app: AppFactory, body: dict[str, Any]
) -> None:
    app = make_app(default_block_network=True)
    key = await connect(app)

    sandbox = await create(app, key, name="unset", **body)

    assert sandbox["network"] == {"block_all": True}


async def test_with_the_default_on_an_explicit_false_keeps_the_network_open(
    make_app: AppFactory,
) -> None:
    app = make_app(default_block_network=True)
    key = await connect(app)

    sandbox = await create(app, key, name="open", network={"block_all": False})

    assert sandbox["network"] == {"block_all": False}


async def test_with_the_default_on_an_explicit_true_stays_blocked(make_app: AppFactory) -> None:
    app = make_app(default_block_network=True)
    key = await connect(app)

    sandbox = await create(app, key, name="blocked", network={"block_all": True})

    assert sandbox["network"] == {"block_all": True}


async def test_with_the_default_on_a_non_empty_allowlist_create_is_unaffected(
    make_app: AppFactory,
) -> None:
    app = make_app(default_block_network=True, **PROXY_SETTINGS)
    key = await connect(app)

    listed = await create(app, key, name="listed", egress_allowlist=["api.example.com"])
    closed = await create(app, key, name="closed", egress_allowlist=[])

    assert listed["network"] == {"block_all": False}
    assert listed["egress_allowlist"] == ["api.example.com"]
    assert closed["network"] == {"block_all": True}  # an empty allowlist fails closed
    assert closed["egress_allowlist"] == []


async def test_the_blocked_default_is_what_get_returns(make_app: AppFactory) -> None:
    app = make_app(default_block_network=True)
    key = await connect(app)
    sandbox = await create(app, key, name="stored")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        fetched = await http.get(
            f"{BASE}/{sandbox['id']}", headers={"Authorization": f"Bearer {key}"}
        )

    assert fetched.json()["data"]["network"] == {"block_all": True}


# -- the default is off --------------------------------------------------------------------


@pytest.mark.parametrize("settings", [{}, {"default_block_network": False}], ids=["unset", "false"])
async def test_with_the_default_off_behavior_is_unchanged(
    make_app: AppFactory, settings: dict[str, Any]
) -> None:
    app = make_app(**settings)
    key = await connect(app)

    unset = await create(app, key, name="unset")
    null_flag = await create(app, key, name="null", network={"block_all": None})
    blocked = await create(app, key, name="blocked", network={"block_all": True})
    listed_app = make_app(**PROXY_SETTINGS, **settings)
    listed_key = await connect(listed_app)
    listed = await create(listed_app, listed_key, name="listed", egress_allowlist=["a.example"])

    assert unset["network"] == {"block_all": False}
    assert null_flag["network"] == {"block_all": False}
    assert blocked["network"] == {"block_all": True}
    assert listed["network"] == {"block_all": False}
