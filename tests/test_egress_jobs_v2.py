"""Egress v2 round 5: allowlisted sandboxes in jobs mode (docs/egress-v2-design.md 7.1, 7.2, 7.5).

Cases J1, J3, J4, J5 and J6 of section 12.5 (J2 is the placement half). Hermetic: FakeDriver,
temp SQLite migrated with alembic, httpx ASGITransport, and the create job driven by hand
through ``handle_create``. The api stores the sandbox without proxy variables in jobs mode; the
node that runs the job mints the token and commits it before the driver call.
"""

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx
import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.deps import DRIVER_ATTR
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.node import Node, NodeState
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import (
    EGRESS_RESTRICTED_LABEL,
    ERROR_CODES,
    ERROR_EGRESS_UNAVAILABLE,
    Sandbox,
    SandboxState,
)
from sandfort.drivers.base import SandboxSpec
from sandfort.drivers.fake import FakeDriver
from sandfort.egress.env import PROXY_VARIABLES
from sandfort.egress.tokens_v2 import verify_egress_token_v2
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.egress_provision import needs_egress_env, provision_egress_env
from sandfort.services.sandbox_jobs import handle_create, install_job_egress
from sandfort.wiring import egress_reminting
from sandfort.workers.handlers import JobContext

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
SCOPES = frozenset(
    {Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.VOLUMES_READ, Scope.VOLUMES_WRITE}
)
SECRET = "e" * 40
PROXY_SETTINGS = {"egress_proxy_address": "proxy.internal:3128", "egress_secret": SECRET}
ALLOWED = ["api.example.com"]
EGRESS_NODE = "node-egress"


@dataclass
class Harness:
    app: FastAPI
    settings: Settings
    driver: FakeDriver
    org_id: str
    key: str
    creates: list[SandboxSpec] = field(default_factory=list)
    env_at_create: list[dict[str, str]] = field(default_factory=list)

    def context(self) -> JobContext:
        factory: Any = lambda: UnitOfWork(self.app.state.session_factory)  # noqa: E731
        return JobContext(factory, self.driver, FrozenClock(NOW))

    async def stored(self, sandbox_id: str) -> Sandbox:
        async with UnitOfWork(self.app.state.session_factory) as uow:
            row = await uow.sandboxes.get(self.org_id, sandbox_id)
        assert row is not None
        return row

    async def send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.app, raise_app_exceptions=False)
        headers = {"Authorization": f"Bearer {self.key}"}
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            return await http.request(method, path, headers=headers, **kwargs)

    async def create(self, **payload: Any) -> httpx.Response:
        return await self.send("POST", BASE, json={"name": "egress", **payload})

    async def drop_all_nodes(self) -> None:
        """Leave the registry empty: no node is egress-ready."""
        async with self.app.state.session_factory() as session:
            await session.execute(sa.text("DELETE FROM nodes"))
            await session.commit()

    async def run_create_job(self, sandbox_id: str) -> None:
        payload = {"org_id": self.org_id, "sandbox_id": sandbox_id, "actor_id": None}
        await handle_create(payload, self.context())


@pytest.fixture
async def harness(tmp_path: Path) -> AsyncIterator[Harness]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'egress-jobs.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(
        driver="fake",
        database_url=url,
        api_key_pepper=PEPPER,
        autostop_enabled=False,
        sandbox_jobs_enabled=True,
        **PROXY_SETTINGS,
    )
    app = create_app(settings)
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored_key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored_key)
        await uow.nodes.upsert_heartbeat(  # an egress-ready node, or an allowlisted create is a 409
            Node(
                id=EGRESS_NODE,
                name=EGRESS_NODE,
                state=NodeState.ACTIVE,
                last_heartbeat_at=datetime.now(UTC),
                egress_ready=True,
            )
        )
        await uow.commit()
    driver = getattr(app.state, DRIVER_ATTR)
    assert isinstance(driver, FakeDriver)
    state = Harness(app, settings, driver, org.id, generated.key)
    install_job_egress(egress_reminting(settings))
    _record_creates(state)
    try:
        yield state
    finally:
        install_job_egress(None)
        await app.state.engine.dispose()


def _record_creates(state: Harness) -> None:
    """Wrap ``driver.create``: keep the spec, and the env the database held at that moment."""
    original: Callable[[SandboxSpec], Any] = state.driver.create

    async def recording(spec: SandboxSpec) -> Any:
        state.creates.append(spec)
        row = await state.stored(spec.sandbox_id)  # what a crash right now would leave behind
        state.env_at_create.append(dict(row.env))
        return await original(spec)

    state.driver.create = recording  # type: ignore[method-assign]


def token_of(env: dict[str, str]) -> str:
    password = urlsplit(env["https_proxy"]).password
    assert password is not None
    return unquote(password)


def has_proxy_variables(env: dict[str, str]) -> bool:
    return any(name in env for name in PROXY_VARIABLES)


# -- J1: allowlisted create in jobs mode ------------------------------------------------------
async def test_j1_the_api_stores_the_sandbox_without_proxy_variables(harness: Harness) -> None:
    response = await harness.create(egress_allowlist=ALLOWED)

    assert response.status_code == 201, response.text
    row = await harness.stored(response.json()["data"]["id"])
    assert row.state is SandboxState.PENDING
    assert row.egress_allowlist == tuple(ALLOWED)
    assert not has_proxy_variables(row.env)
    assert harness.creates == []


async def test_j1_the_job_mints_and_commits_before_the_driver_create(harness: Harness) -> None:
    sandbox_id = (await harness.create(egress_allowlist=ALLOWED)).json()["data"]["id"]

    await harness.run_create_job(sandbox_id)

    (spec,) = harness.creates
    assert spec.labels[EGRESS_RESTRICTED_LABEL] == "true"
    assert has_proxy_variables(spec.env)
    (env_in_database,) = harness.env_at_create  # committed before the driver call ran
    assert env_in_database == dict(spec.env)
    claims = verify_egress_token_v2(SECRET, token_of(dict(spec.env)), NOW)
    assert (claims.sandbox_id, claims.epoch) == (sandbox_id, 0)
    row = await harness.stored(sandbox_id)
    assert row.state is SandboxState.STARTED
    assert row.env == dict(spec.env)


async def test_j1_a_sandbox_without_an_allowlist_gets_no_marker_and_no_proxy(
    harness: Harness,
) -> None:
    sandbox_id = (await harness.create()).json()["data"]["id"]

    await harness.run_create_job(sandbox_id)

    (spec,) = harness.creates
    assert EGRESS_RESTRICTED_LABEL not in spec.labels
    assert not has_proxy_variables(dict(spec.env))


async def test_j1_a_blocked_sandbox_is_marked_and_gets_no_proxy_variables(
    harness: Harness,
) -> None:
    sandbox_id = (await harness.create(egress_allowlist=[])).json()["data"]["id"]

    await harness.run_create_job(sandbox_id)

    (spec,) = harness.creates
    assert spec.labels[EGRESS_RESTRICTED_LABEL] == "true"
    assert not has_proxy_variables(dict(spec.env))


async def test_j1_a_user_proxy_variable_does_not_pass_for_a_minted_one(harness: Harness) -> None:
    env = {"http_proxy": "http://user.example:1", "KEEP": "1"}
    sandbox_id = (await harness.create(egress_allowlist=ALLOWED, env=env)).json()["data"]["id"]

    await harness.run_create_job(sandbox_id)

    (spec,) = harness.creates
    assert spec.env["KEEP"] == "1"
    assert "user.example" not in spec.env["http_proxy"]
    verify_egress_token_v2(SECRET, token_of(dict(spec.env)), NOW)


async def test_j1_a_create_with_an_empty_allowlist_needs_no_egress_node(harness: Harness) -> None:
    """An empty list is a blocked sandbox that mints nothing, so an empty registry is no 409."""
    await harness.drop_all_nodes()

    blocked = await harness.create(egress_allowlist=[])
    plain = await harness.create(name="plain")
    allowlisted = await harness.create(name="listed", egress_allowlist=ALLOWED)

    assert blocked.status_code == 201, blocked.text
    assert plain.status_code == 201, plain.text
    assert allowlisted.status_code == 409, allowlisted.text
    assert "egress" in allowlisted.json()["error"]["message"]


# -- J3: a node with no egress settings --------------------------------------------------------
async def test_j3_a_node_without_egress_settings_fails_closed_before_the_driver(
    harness: Harness,
) -> None:
    sandbox_id = (await harness.create(egress_allowlist=ALLOWED)).json()["data"]["id"]
    install_job_egress(None)

    await harness.run_create_job(sandbox_id)

    row = await harness.stored(sandbox_id)
    assert row.state is SandboxState.ERROR
    assert row.error_code == ERROR_EGRESS_UNAVAILABLE
    assert row.error_reason
    assert not has_proxy_variables(row.env)
    assert harness.creates == []
    assert await harness.driver.list_managed() == []


def test_j3_the_new_code_is_part_of_the_error_vocabulary() -> None:
    assert ERROR_EGRESS_UNAVAILABLE == "egress_unavailable"
    assert ERROR_EGRESS_UNAVAILABLE in ERROR_CODES


# -- J4: a retry does not mint again -----------------------------------------------------------
async def test_j4_a_retry_after_the_mint_committed_keeps_the_same_token(
    harness: Harness,
) -> None:
    sandbox_id = (await harness.create(egress_allowlist=ALLOWED)).json()["data"]["id"]
    reminting = egress_reminting(harness.settings)
    assert reminting is not None
    factory: Any = harness.context().uow_factory
    first = await provision_egress_env(
        factory, reminting, FrozenClock(NOW), await harness.stored(sandbox_id)
    )  # the worker died after this commit and before the driver call
    minted = token_of(dict(first.env))

    await harness.run_create_job(sandbox_id)  # the retried job, a minute later in spirit

    (spec,) = harness.creates
    assert token_of(dict(spec.env)) == minted
    row = await harness.stored(sandbox_id)
    assert token_of(dict(row.env)) == minted
    assert row.egress_credential_epoch == 0
    assert row.version > first.version  # only the job's own transitions wrote after the mint


async def test_j4_provisioning_a_sandbox_that_already_has_the_variables_writes_nothing(
    harness: Harness,
) -> None:
    sandbox_id = (await harness.create(egress_allowlist=ALLOWED)).json()["data"]["id"]
    reminting = egress_reminting(harness.settings)
    assert reminting is not None
    factory: Any = harness.context().uow_factory
    first = await provision_egress_env(
        factory, reminting, FrozenClock(NOW), await harness.stored(sandbox_id)
    )

    again = await provision_egress_env(factory, reminting, FrozenClock(NOW), first)

    assert again == first
    assert await harness.stored(sandbox_id) == first


# -- J5: PATCH in jobs mode ---------------------------------------------------------------------
async def test_j5_patch_works_in_jobs_mode_with_no_driver_call(harness: Harness) -> None:
    sandbox_id = (await harness.create(egress_allowlist=ALLOWED)).json()["data"]["id"]

    response = await harness.send(
        "PATCH", f"{BASE}/{sandbox_id}", json={"egress_allowlist": ["b.example.net"]}
    )

    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["egress_allowlist"] == ["b.example.net"]
    assert data["egress_policy_generation"] == 2
    assert harness.creates == []
    assert await harness.driver.list_managed() == []


# -- J5b: a PATCH to an empty allowlist while the create job is queued -------------------------
async def test_j5_patch_to_empty_before_the_job_still_mints_and_can_be_widened_again(
    harness: Harness,
) -> None:
    sandbox_id = (await harness.create(egress_allowlist=ALLOWED)).json()["data"]["id"]
    emptied = await harness.send("PATCH", f"{BASE}/{sandbox_id}", json={"egress_allowlist": []})
    assert emptied.status_code == 200, emptied.text
    queued = await harness.stored(sandbox_id)
    assert queued.egress_allowlist == ()
    assert not queued.network.block_all  # the create stored an open network, the PATCH kept it

    await harness.run_create_job(sandbox_id)

    (spec,) = harness.creates
    assert has_proxy_variables(dict(spec.env))  # the container has its proxy, denying everything
    assert spec.labels[EGRESS_RESTRICTED_LABEL] == "true"
    minted = token_of(dict(spec.env))
    claims = verify_egress_token_v2(SECRET, minted, NOW)
    assert (claims.sandbox_id, claims.epoch) == (sandbox_id, 0)

    widened = await harness.send(
        "PATCH", f"{BASE}/{sandbox_id}", json={"egress_allowlist": ["b.example.net"]}
    )

    assert widened.status_code == 200, widened.text
    assert widened.json()["data"]["egress_allowlist"] == ["b.example.net"]
    row = await harness.stored(sandbox_id)
    assert token_of(dict(row.env)) == minted  # the stored credential serves the new policy
    assert len(harness.creates) == 1


async def test_j5_an_empty_create_is_blocked_and_never_needs_a_credential(
    harness: Harness,
) -> None:
    sandbox_id = (await harness.create(egress_allowlist=[])).json()["data"]["id"]
    row = await harness.stored(sandbox_id)

    assert row.network.block_all
    assert not needs_egress_env(row)


# -- J6: volumes stay refused in jobs mode ------------------------------------------------------
async def test_j6_volumes_in_jobs_mode_are_still_refused(harness: Harness) -> None:
    volumes = [{"volume_id": "vol_missing", "mount_path": "/data"}]

    response = await harness.create(egress_allowlist=ALLOWED, volumes=volumes)

    assert response.status_code == 422, response.text
    assert "volume mounts are not supported" in response.json()["error"]["message"]
    assert harness.creates == []


async def test_reset_stays_unavailable_in_jobs_mode(harness: Harness) -> None:
    sandbox_id = (await harness.create(egress_allowlist=ALLOWED)).json()["data"]["id"]

    response = await harness.send("POST", f"{BASE}/{sandbox_id}/reset")

    assert response.status_code == 409, response.text
    assert "jobs" in response.json()["error"]["message"]
