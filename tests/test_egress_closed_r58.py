"""An empty egress allowlist fails closed: no network at all, never the open bridge.

Through the api (FakeDriver, temp SQLite), then through the driver spec the stored sandbox
yields. A non-empty allowlist keeps the allowlist network; the operator default block is
never bypassed by an empty list.
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
from sandfort.domain.sandbox import (
    EGRESS_RESTRICTED_LABEL,
    NetworkPolicy,
    Sandbox,
    egress_spec_labels,
)
from sandfort.drivers.docker.hardening import build_host_config
from sandfort.drivers.docker.networks import EGRESS_NETWORK_NAME
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.sandboxes import MountingLifecycle

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
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
        url = f"sqlite+aiosqlite:///{tmp_path / f'egress-closed-{len(built)}.db'}"
        config = Config(str(ROOT / "alembic.ini"))
        config.set_main_option("sqlalchemy.url", url)
        command.upgrade(config, "head")
        settings = Settings(
            driver="fake",
            database_url=url,
            api_key_pepper=PEPPER,
            autostop_enabled=False,
            **PROXY_SETTINGS,
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


def stored_sandbox(data: dict[str, Any]) -> Sandbox:
    """The domain record a create response describes, enough to build its driver spec."""
    return Sandbox(
        id="sbx_1",
        org_id="org_1",
        name="n",
        image_ref="alpine:3.20",
        driver="docker",
        created_at=NOW,
        updated_at=NOW,
        network=NetworkPolicy(**data["network"]),
        egress_allowlist=tuple(data["egress_allowlist"]),
    )


async def test_an_empty_allowlist_create_is_block_all_with_restricted_spec_labels(
    make_app: AppFactory,
) -> None:
    app = make_app()
    key = await connect(app)

    data = await create(app, key, name="closed", egress_allowlist=[])

    assert data["network"] == {"block_all": True}
    assert data["egress_allowlist"] == []
    spec = MountingLifecycle.spec(stored_sandbox(data))
    assert spec.network.block_all
    assert spec.labels[EGRESS_RESTRICTED_LABEL] == "true"
    assert build_host_config(spec, Settings())["network_mode"] == "none"


async def test_an_empty_allowlist_beats_an_explicit_open_network(make_app: AppFactory) -> None:
    app = make_app()
    key = await connect(app)

    data = await create(app, key, name="closed", egress_allowlist=[], network={"block_all": False})

    assert data["network"] == {"block_all": True}


async def test_a_non_empty_allowlist_still_yields_the_allowlist_network(
    make_app: AppFactory,
) -> None:
    app = make_app()
    key = await connect(app)

    data = await create(app, key, name="listed", egress_allowlist=["api.example.com"])

    assert data["network"] == {"block_all": False}
    spec = MountingLifecycle.spec(stored_sandbox(data))
    assert spec.labels[EGRESS_RESTRICTED_LABEL] == "true"
    assert build_host_config(spec, Settings())["network_mode"] == EGRESS_NETWORK_NAME


@pytest.mark.parametrize("network", [None, {"block_all": False}, {"block_all": True}])
async def test_the_operator_default_block_is_not_bypassed_by_an_empty_list(
    make_app: AppFactory, network: dict[str, bool] | None
) -> None:
    app = make_app(default_block_network=True)
    key = await connect(app)
    body: dict[str, Any] = {"name": "closed", "egress_allowlist": []}
    if network is not None:
        body["network"] = network

    data = await create(app, key, **body)

    assert data["network"] == {"block_all": True}


def test_the_spec_labels_leave_an_unset_allowlist_unrestricted() -> None:
    sandbox = Sandbox(
        id="sbx_1",
        org_id="org_1",
        name="n",
        image_ref="alpine:3.20",
        driver="docker",
        created_at=NOW,
        updated_at=NOW,
    )

    assert egress_spec_labels(sandbox) == {}
    assert egress_spec_labels(sandbox.model_copy(update={"egress_allowlist": ()})) == {
        EGRESS_RESTRICTED_LABEL: "true"
    }
