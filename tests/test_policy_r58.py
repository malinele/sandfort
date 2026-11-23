"""Round 58, M4: operator-enforced policy.

Four settings that an operator, not a tenant, decides: a network policy tenants cannot
override, default quotas for new orgs, a prod refusal of an unguarded host, and host-wide
admission that two orgs cannot pass at once.
"""

import asyncio
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort import admin_cli
from sandfort.api.app import IsolationUnavailableError, check_host_capacity, create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import SystemClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.quota import OrgQuota
from sandfort.domain.sandbox import ResourceSpec
from sandfort.errors import CapacityExceeded
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.admission import host_lock_for_loop
from sandfort.services.quota import QuotaService

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
PROXY_SETTINGS = {"egress_proxy_address": "proxy.internal:3128", "egress_secret": "e" * 40}
POLICY_MESSAGE = "network egress is disabled by operator policy"

AppFactory = Callable[..., FastAPI]


def sqlite_url(tmp_path: Path, name: str) -> str:
    url = f"sqlite+aiosqlite:///{tmp_path / name}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    return url


@pytest.fixture
async def make_app(tmp_path: Path) -> AsyncIterator[AppFactory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    built: list[FastAPI] = []

    def build(**overrides: Any) -> FastAPI:
        url = sqlite_url(tmp_path, f"policy-{len(built)}.db")
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


async def post(app: FastAPI, key: str, **body: Any) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        return await http.post(BASE, headers={"Authorization": f"Bearer {key}"}, json=body)


def assert_refused_by_policy(response: httpx.Response) -> None:
    assert response.status_code == 403, response.text
    error = response.json()["error"]
    assert error["code"] == "FORBIDDEN"
    assert error["message"] == POLICY_MESSAGE


# -- 1: enforce block network ---------------------------------------------------------------


def test_the_enforcement_setting_is_off_by_default_and_read_from_the_environment() -> None:
    assert Settings().enforce_block_network is False
    assert Settings.from_env({}).enforce_block_network is False
    assert Settings.from_env({"SANDFORT_ENFORCE_BLOCK_NETWORK": "true"}).enforce_block_network


async def test_enforced_policy_refuses_an_explicit_open_network(make_app: AppFactory) -> None:
    app = make_app(enforce_block_network=True)
    key = await connect(app)

    response = await post(app, key, name="open", network={"block_all": False})

    assert_refused_by_policy(response)


async def test_enforced_policy_refuses_a_non_empty_allowlist(make_app: AppFactory) -> None:
    app = make_app(enforce_block_network=True, **PROXY_SETTINGS)
    key = await connect(app)

    response = await post(app, key, name="listed", egress_allowlist=["api.example.com"])

    assert_refused_by_policy(response)


@pytest.mark.parametrize(
    "body",
    [{}, {"network": {"block_all": True}}, {"egress_allowlist": []}],
    ids=["unset", "explicit-true", "empty-allowlist"],
)
async def test_enforced_policy_shows_the_blocked_network_on_the_object(
    make_app: AppFactory, body: dict[str, Any]
) -> None:
    app = make_app(enforce_block_network=True, **PROXY_SETTINGS)
    key = await connect(app)

    response = await post(app, key, name="closed", **body)

    assert response.status_code == 201, response.text
    created = response.json()["data"]
    assert created["network"] == {"block_all": True}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        fetched = await http.get(
            f"{BASE}/{created['id']}", headers={"Authorization": f"Bearer {key}"}
        )
    assert fetched.json()["data"]["network"] == {"block_all": True}


async def test_without_enforcement_a_tenant_may_still_open_the_network(
    make_app: AppFactory,
) -> None:
    app = make_app(default_block_network=True)
    key = await connect(app)

    response = await post(app, key, name="open", network={"block_all": False})

    assert response.status_code == 201, response.text
    assert response.json()["data"]["network"] == {"block_all": False}


# -- 2: default org quota -------------------------------------------------------------------


def test_the_default_quota_is_unset_and_read_from_the_environment() -> None:
    unset = Settings.from_env({})
    configured = Settings.from_env(
        {
            "SANDFORT_DEFAULT_ORG_MAX_SANDBOXES": "5",
            "SANDFORT_DEFAULT_ORG_MAX_VCPUS": "2.5",
            "SANDFORT_DEFAULT_ORG_MAX_MEMORY_MIB": "4096",
            "SANDFORT_DEFAULT_ORG_MAX_DISK_GIB": "20",
        }
    )

    assert unset.default_org_quota() == OrgQuota()
    assert configured.default_org_quota() == OrgQuota(
        max_sandboxes=5, max_vcpus=2.5, max_memory_mib=4096, max_disk_gib=20
    )


def test_a_negative_default_quota_is_rejected() -> None:
    with pytest.raises(ValueError, match="DEFAULT_ORG_MAX_SANDBOXES"):
        Settings.from_env({"SANDFORT_DEFAULT_ORG_MAX_SANDBOXES": "-1"})


async def quota_of(url: str, slug: str) -> OrgQuota:
    engine = create_engine(Settings(database_url=url))
    try:
        async with UnitOfWork(create_session_factory(engine)) as uow:
            org = await uow.orgs.get_by_slug(slug)
            assert org is not None
            return await uow.quotas.get_or_default(org.id)
    finally:
        await engine.dispose()


async def test_create_org_applies_the_default_quota(tmp_path: Path) -> None:
    pytest.importorskip("aiosqlite")
    url = sqlite_url(tmp_path, "quota.db")
    settings = Settings(
        database_url=url,
        api_key_pepper=PEPPER,
        default_org_max_sandboxes=3,
        default_org_max_vcpus=1.5,
        default_org_max_memory_mib=2048,
        default_org_max_disk_gib=10,
    )

    await admin_cli._provision_async(settings, "Acme", "acme", first_org=True)
    await admin_cli._provision_async(settings, "Beta", "beta", first_org=False)

    expected = OrgQuota(max_sandboxes=3, max_vcpus=1.5, max_memory_mib=2048, max_disk_gib=10)
    assert await quota_of(url, "acme") == expected  # bootstrap
    assert await quota_of(url, "beta") == expected  # create-org


async def test_create_org_without_a_default_quota_stays_unlimited(tmp_path: Path) -> None:
    pytest.importorskip("aiosqlite")
    url = sqlite_url(tmp_path, "unlimited.db")
    settings = Settings(database_url=url, api_key_pepper=PEPPER)

    await admin_cli._provision_async(settings, "Acme", "acme", first_org=False)

    assert await quota_of(url, "acme") == OrgQuota()


# -- 3: the prod gate on host capacity ------------------------------------------------------


def test_the_capacity_gate_is_off_in_dev() -> None:
    check_host_capacity(Settings(environment="dev"))  # does not raise


@pytest.mark.parametrize(
    "capacity",
    [
        {},
        {"host_capacity_cpu_millicores": 4000},
        {"host_capacity_memory_mib": 8192},
        {"host_capacity_cpu_millicores": 0, "host_capacity_memory_mib": 0},
    ],
    ids=["both-unset", "memory-unset", "cpu-unset", "both-zero"],
)
def test_prod_refuses_a_host_without_both_capacities(capacity: dict[str, int]) -> None:
    with pytest.raises(IsolationUnavailableError, match="host capacity"):
        check_host_capacity(Settings(environment="prod", **capacity))


def test_prod_accepts_a_host_with_both_capacities() -> None:
    settings = Settings(
        environment="prod", host_capacity_cpu_millicores=4000, host_capacity_memory_mib=8192
    )

    check_host_capacity(settings)  # does not raise


def test_prod_accepts_an_unguarded_host_when_the_operator_allows_it() -> None:
    check_host_capacity(Settings(environment="prod", allow_unbounded_host=True))


def test_the_unbounded_host_flag_is_read_from_the_environment() -> None:
    assert Settings.from_env({}).allow_unbounded_host is False
    assert Settings.from_env({"SANDFORT_ALLOW_UNBOUNDED_HOST": "true"}).allow_unbounded_host


# -- 4: host-wide admission -----------------------------------------------------------------

SHAPE = ResourceSpec(cpu_millicores=1000, memory_mib=512, disk_gib=1)


async def seed_orgs(url: str, slugs: list[str]) -> list[str]:
    engine = create_engine(Settings(database_url=url))
    ids: list[str] = []
    try:
        async with UnitOfWork(create_session_factory(engine)) as uow:
            for slug in slugs:
                org = Org(id=new_org_id(), name=slug, slug=slug, created_at=NOW)
                await uow.orgs.add(org)
                ids.append(org.id)
            await uow.commit()
    finally:
        await engine.dispose()
    return ids


async def test_two_orgs_cannot_both_take_the_last_slot_of_the_host(tmp_path: Path) -> None:
    pytest.importorskip("aiosqlite")
    url = sqlite_url(tmp_path, "admission.db")
    org_a, org_b = await seed_orgs(url, ["org-a", "org-b"])
    settings = Settings(
        database_url=url, host_capacity_cpu_millicores=1000, host_capacity_memory_mib=1024
    )
    engine = create_engine(settings)
    factory = create_session_factory(engine)
    service = QuotaService(lambda: UnitOfWork(factory), settings, SystemClock())

    async def reserve(org_id: str, sandbox_id: str) -> str:
        async with UnitOfWork(factory) as uow:
            try:
                await service.reserve(uow, org_id, sandbox_id, SHAPE)
            except CapacityExceeded:
                return "refused"
            await uow.commit()
            return "admitted"

    try:
        outcomes = await asyncio.gather(reserve(org_a, "sbx_a"), reserve(org_b, "sbx_b"))
    finally:
        await engine.dispose()

    assert sorted(outcomes) == ["admitted", "refused"]


async def test_the_sqlite_host_lock_is_held_until_the_transaction_ends(tmp_path: Path) -> None:
    pytest.importorskip("aiosqlite")
    url = sqlite_url(tmp_path, "held.db")
    [org_id] = await seed_orgs(url, ["org-a"])
    settings = Settings(
        database_url=url, host_capacity_cpu_millicores=4000, host_capacity_memory_mib=4096
    )
    engine = create_engine(settings)
    factory = create_session_factory(engine)
    service = QuotaService(lambda: UnitOfWork(factory), settings, SystemClock())
    lock = host_lock_for_loop()

    try:
        async with UnitOfWork(factory) as uow:
            await service.reserve(uow, org_id, "sbx_1", SHAPE)
            held_inside = lock.locked()
            await uow.commit()
        released_after = not lock.locked()
        async with UnitOfWork(factory) as uow:  # a second reserve is not blocked by the first
            await service.reserve(uow, org_id, "sbx_2", SHAPE)
            await uow.commit()
    finally:
        await engine.dispose()

    assert held_inside is True
    assert released_after is True


async def test_an_unguarded_host_takes_no_host_lock(tmp_path: Path) -> None:
    pytest.importorskip("aiosqlite")
    url = sqlite_url(tmp_path, "unguarded.db")
    [org_id] = await seed_orgs(url, ["org-a"])
    settings = Settings(database_url=url)
    engine = create_engine(settings)
    factory = create_session_factory(engine)
    service = QuotaService(lambda: UnitOfWork(factory), settings, SystemClock())

    try:
        async with UnitOfWork(factory) as uow:
            await service.reserve(uow, org_id, "sbx_1", SHAPE)
            locked = host_lock_for_loop().locked()
            await uow.commit()
    finally:
        await engine.dispose()

    assert locked is False
