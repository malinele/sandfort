"""Egress allowlist, slice one (docs/egress-allowlist-design.md): data model and validation.

Covers the domain helper's accepted and refused shapes, the setting that caps the entry count,
the create-to-get roundtrip through the api (FakeDriver, temp SQLite) and the warm-pool bypass.
Normalization rule under test: there is none. Entries must already be lowercase ASCII, so an
uppercase entry is refused rather than folded. Nothing here enforces egress yet.
"""

from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.deps import SANDBOX_SERVICE_ATTR
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import SystemClock
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import (
    EGRESS_ALLOWLIST_LABEL,
    MAX_HOSTNAME_LENGTH,
    NetworkPolicy,
    Sandbox,
    check_egress_allowlist,
    encode_egress_allowlist,
    take_egress_allowlist,
)
from sandfort.drivers.fake import FakeDriver
from sandfort.egress.env import NO_PROXY_VARIABLES, PROXY_VARIABLES
from sandfort.egress.tokens_v2 import EGRESS_V2_PREFIX, verify_egress_token_v2
from sandfort.errors import InvalidState, Unprocessable
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.sandboxes import CreateSandboxCommand, SandboxService
from sandfort.services.volumes import is_reserved_label
from sandfort.services.warm_pool import WARM_POOL_REFILL, is_eligible
from sandfort.workers.handlers import JobContext, lookup

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
ACTOR = "key_test"
LEASE = timedelta(minutes=1)
LIMIT = 16
OPEN = NetworkPolicy()
BLOCKED = NetworkPolicy(block_all=True)
READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
PROXY_ADDRESS = "proxy.internal:3128"
EGRESS_SECRET = "e" * 40
PROXY_SETTINGS = {"egress_proxy_address": PROXY_ADDRESS, "egress_secret": EGRESS_SECRET}

AppFactory = Callable[..., FastAPI]


def longest_name() -> str:
    """A hostname of exactly 253 characters: labels of 63, 63, 63 and 61 plus three dots."""
    return ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])


# -- the validation helper -----------------------------------------------------------------


@pytest.mark.parametrize(
    "entry",
    [
        "example.com",
        "api.example-provider.com",
        ".example.com",  # the domain and all its subdomains
        "xn--bcher-kva.example",  # IDNA form of an internationalized label
        "localhost",
        "1password.com",  # a leading digit is fine while the last label is not a number
        "a" * 63 + ".com",
        longest_name(),
        "." + longest_name(),  # the domain marker is not counted
    ],
)
def test_accepts_lowercase_hostnames_and_the_leading_dot(entry: str) -> None:
    check_egress_allowlist((entry,), OPEN, LIMIT)


def test_the_longest_accepted_name_is_the_hostname_limit() -> None:
    assert len(longest_name()) == MAX_HOSTNAME_LENGTH


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        ("Example.com", "lowercase"),
        ("API.EXAMPLE.COM", "lowercase"),
        ("10.0.0.1", "IP literal"),
        ("127.1", "IP literal"),
        ("0x7f000001", "IP literal"),
        ("::1", "IP literal"),
        ("[2001:db8::1]", "IP literal"),
        ("example.com:443", "port"),
        ("https://example.com", "scheme"),
        ("example.com/v1", "path"),
        ("a" * 64 + ".com", "labels of 1 to 63"),
        (longest_name() + "d", f"longer than {MAX_HOSTNAME_LENGTH}"),
        ("", "labels of 1 to 63"),
        (".", "labels of 1 to 63"),
        ("example.com.", "labels of 1 to 63"),  # no trailing-dot normalization either
        ("a..example.com", "labels of 1 to 63"),
        ("-a.example.com", "labels of 1 to 63"),
        (" example.com", "labels of 1 to 63"),
        ("*.example.com", "wildcards"),
        ("bücher.example", "ASCII"),
    ],
)
def test_refuses_entries_that_are_not_plain_hostnames(entry: str, reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        check_egress_allowlist((entry,), OPEN, LIMIT)


def test_refuses_more_entries_than_the_cap() -> None:
    entries = tuple(f"host{index}.example.com" for index in range(3))
    check_egress_allowlist(entries[:2], OPEN, 2)  # exactly at the cap

    with pytest.raises(ValueError, match="at most 2 entries, got 3"):
        check_egress_allowlist(entries, OPEN, 2)


def test_block_all_with_a_non_empty_allowlist_is_contradictory() -> None:
    with pytest.raises(ValueError, match="contradicts network.block_all"):
        check_egress_allowlist(("example.com",), BLOCKED, LIMIT)


def test_no_allowlist_and_an_empty_one_both_pass_with_block_all() -> None:
    check_egress_allowlist(None, BLOCKED, LIMIT)
    check_egress_allowlist((), BLOCKED, LIMIT)


def test_the_caller_chooses_the_error_type() -> None:
    with pytest.raises(Unprocessable, match="IP literal"):
        check_egress_allowlist(("10.0.0.1",), OPEN, LIMIT, Unprocessable)


def test_entry_cap_defaults_to_sixteen_and_reads_the_environment() -> None:
    assert Settings().egress_allowlist_max_entries == LIMIT
    environ = {"SANDFORT_EGRESS_ALLOWLIST_MAX_ENTRIES": "4"}
    assert Settings.from_env(environ).egress_allowlist_max_entries == 4
    with pytest.raises(ValueError, match="must be an integer"):
        Settings.from_env({"SANDFORT_EGRESS_ALLOWLIST_MAX_ENTRIES": "many"})


def test_the_carrier_label_is_reserved_and_round_trips() -> None:
    assert is_reserved_label(EGRESS_ALLOWLIST_LABEL)
    assert encode_egress_allowlist(None) == {}
    assert take_egress_allowlist({"team": "a"}) == ({"team": "a"}, None)
    for entries in ((), ("example.com", ".example.org")):
        labels = {"team": "a", **encode_egress_allowlist(entries)}
        assert take_egress_allowlist(labels) == ({"team": "a"}, entries)


@pytest.mark.parametrize("raw", ["not json", '{"a": 1}', "[1, 2]"])
def test_a_malformed_carrier_is_refused(raw: str) -> None:
    with pytest.raises(ValueError):
        take_egress_allowlist({EGRESS_ALLOWLIST_LABEL: raw})


# -- api roundtrip -------------------------------------------------------------------------


@pytest.fixture
async def make_app(tmp_path: Path) -> AsyncIterator[AppFactory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    built: list[FastAPI] = []

    def build(**overrides: Any) -> FastAPI:
        url = f"sqlite+aiosqlite:///{tmp_path / f'egress-{len(built)}.db'}"
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


async def connect(app: FastAPI) -> tuple[str, str]:
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
    return org.id, generated.key


async def send(app: FastAPI, key: str, method: str, path: str, **kwargs: Any) -> httpx.Response:
    headers = {"Authorization": f"Bearer {key}"}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        return await http.request(method, path, headers=headers, **kwargs)


async def test_create_with_an_allowlist_stores_it_and_get_returns_it(
    make_app: AppFactory,
) -> None:
    app = make_app(**PROXY_SETTINGS)
    org_id, key = await connect(app)
    allowlist = ["api.example-provider.com", ".example.org"]

    created = await send(
        app, key, "POST", BASE, json={"name": "egress", "egress_allowlist": allowlist}
    )
    assert created.status_code == 201, created.text
    sandbox = created.json()["data"]
    fetched = await send(app, key, "GET", f"{BASE}/{sandbox['id']}")

    assert sandbox["egress_allowlist"] == allowlist
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["data"]["egress_allowlist"] == allowlist
    async with UnitOfWork(app.state.session_factory) as uow:
        stored = await uow.sandboxes.get(org_id, sandbox["id"])
        audit = await uow.audit.list(org_id, action="sandbox.create")
    assert stored is not None
    assert stored.egress_allowlist == tuple(allowlist)
    assert EGRESS_ALLOWLIST_LABEL not in stored.labels  # the carrier is never stored
    assert [event.details["egress_allowlist"] for event in audit] == [allowlist]


async def test_create_without_an_allowlist_returns_none_and_an_empty_one_stays_empty(
    make_app: AppFactory,
) -> None:
    app = make_app()
    _, key = await connect(app)

    plain = await send(app, key, "POST", BASE, json={"name": "plain"})
    closed = await send(app, key, "POST", BASE, json={"name": "closed", "egress_allowlist": []})

    assert plain.status_code == 201, plain.text
    assert closed.status_code == 201, closed.text
    assert plain.json()["data"]["egress_allowlist"] is None
    assert closed.json()["data"]["egress_allowlist"] == []
    fetched = await send(app, key, "GET", f"{BASE}/{plain.json()['data']['id']}")
    assert fetched.json()["data"]["egress_allowlist"] is None


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        ({"egress_allowlist": ["10.0.0.1"]}, "IP literal"),
        ({"egress_allowlist": ["Example.com"]}, "lowercase"),
        ({"egress_allowlist": ["example.com:443"]}, "port"),
        ({"egress_allowlist": ["example.com"], "network": {"block_all": True}}, "contradicts"),
    ],
)
async def test_invalid_allowlists_are_refused_before_anything_is_stored(
    make_app: AppFactory, payload: dict[str, Any], reason: str
) -> None:
    app = make_app()
    org_id, key = await connect(app)

    response = await send(app, key, "POST", BASE, json={"name": "bad", **payload})

    assert response.status_code == Unprocessable.status, response.text
    error = response.json()["error"]
    assert error["code"] == Unprocessable.code
    assert reason in error["message"]
    async with UnitOfWork(app.state.session_factory) as uow:
        assert list(await uow.sandboxes.list(org_id)) == []
    driver = app.state.driver
    assert isinstance(driver, FakeDriver)
    assert await driver.list_managed() == []


async def test_the_entry_cap_comes_from_the_settings(make_app: AppFactory) -> None:
    app = make_app(egress_allowlist_max_entries=2)
    _, key = await connect(app)
    allowlist = ["a.example", "b.example", "c.example"]

    response = await send(app, key, "POST", BASE, json={"egress_allowlist": allowlist})

    assert response.status_code == Unprocessable.status, response.text
    assert "at most 2 entries, got 3" in response.json()["error"]["message"]


async def test_a_client_cannot_send_the_carrier_label_itself(make_app: AppFactory) -> None:
    app = make_app()
    _, key = await connect(app)

    response = await send(
        app, key, "POST", BASE, json={"labels": {EGRESS_ALLOWLIST_LABEL: '["example.com"]'}}
    )

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


# -- warm pool bypass ----------------------------------------------------------------------


def service_of(app: FastAPI) -> SandboxService:
    service = getattr(app.state, SANDBOX_SERVICE_ATTR)
    assert isinstance(service, SandboxService)
    return service


async def run_refills(app: FastAPI) -> int:
    """Lease and run every queued refill job the way the job runner would; returns how many."""
    context = JobContext(
        lambda: UnitOfWork(app.state.session_factory), app.state.driver, SystemClock()
    )
    handler = lookup(WARM_POOL_REFILL)
    ran = 0
    while True:
        now = datetime.now(UTC)
        async with UnitOfWork(app.state.session_factory) as uow:
            job = await uow.jobs.lease_next(
                [WARM_POOL_REFILL], now=now, lease_expires_at=now + LEASE
            )
            await uow.commit()
        if job is None:
            return ran
        await handler(job.payload, context)
        async with UnitOfWork(app.state.session_factory) as uow:
            await uow.jobs.complete(job.id, datetime.now(UTC))
            await uow.commit()
        ran += 1


async def standbys(app: FastAPI, org_id: str) -> list[Sandbox]:
    async with UnitOfWork(app.state.session_factory) as uow:
        rows = await uow.sandboxes.list_for_reconciler()  # the system view keeps standbys
    return [row for row in rows if row.org_id == org_id and row.standby]


def test_any_allowlist_makes_a_create_ineligible_for_the_pool() -> None:
    assert is_eligible(CreateSandboxCommand())
    assert not is_eligible(CreateSandboxCommand(egress_allowlist=()))
    assert not is_eligible(CreateSandboxCommand(egress_allowlist=("example.com",)))


async def test_an_allowlisted_create_never_claims_a_standby(make_app: AppFactory) -> None:
    app = make_app(warm_pool_size=1, **PROXY_SETTINGS)
    org_id, _ = await connect(app)
    service = service_of(app)
    await service.create(org_id, ACTOR, CreateSandboxCommand(name="seed"))
    assert await run_refills(app) == 1
    (standby,) = await standbys(app, org_id)

    allowlisted = CreateSandboxCommand(name="egress", egress_allowlist=("example.com",))
    built = await service.create(org_id, ACTOR, allowlisted)

    assert built.id != standby.id  # built for this create, not taken from the pool
    assert built.standby is False
    assert built.spec_hash is None
    assert built.egress_allowlist == ("example.com",)
    assert [row.id for row in await standbys(app, org_id)] == [standby.id]
    assert await run_refills(app) == 0  # and no refill was queued for it


async def test_an_allowlisted_create_does_not_seed_the_pool(make_app: AppFactory) -> None:
    app = make_app(warm_pool_size=1)
    org_id, _ = await connect(app)

    built = await service_of(app).create(
        org_id, ACTOR, CreateSandboxCommand(name="closed", egress_allowlist=())
    )

    assert built.egress_allowlist == ()
    assert await run_refills(app) == 0
    assert await standbys(app, org_id) == []


# -- proxy environment wiring --------------------------------------------------------------


@pytest.mark.parametrize(
    "settings",
    [
        {},
        {"egress_proxy_address": PROXY_ADDRESS},
        {"egress_secret": EGRESS_SECRET},
    ],
)
async def test_an_allowlisted_create_with_unconfigured_proxy_settings_is_refused(
    make_app: AppFactory, settings: dict[str, str]
) -> None:
    app = make_app(**settings)
    org_id, _ = await connect(app)
    command = CreateSandboxCommand(name="egress", egress_allowlist=("example.com",))

    with pytest.raises(InvalidState):
        await service_of(app).create(org_id, ACTOR, command)

    async with UnitOfWork(app.state.session_factory) as uow:
        assert list(await uow.sandboxes.list(org_id)) == []


async def test_an_allowlisted_create_gets_the_proxy_environment_with_a_valid_token(
    make_app: AppFactory,
) -> None:
    app = make_app(**PROXY_SETTINGS)
    org_id, _ = await connect(app)
    allowlist = ("api.example-provider.com", ".example.org")

    created = await service_of(app).create(
        org_id, ACTOR, CreateSandboxCommand(name="egress", egress_allowlist=allowlist)
    )

    assert len(PROXY_VARIABLES) == 4
    for name in PROXY_VARIABLES:
        proxy = urlsplit(created.env[name])
        assert proxy.scheme == "http"
        assert proxy.hostname == "proxy.internal"
        assert proxy.port == 3128
        assert proxy.username == created.id
        assert proxy.password is not None
        token = unquote(proxy.password)
        assert token.startswith(EGRESS_V2_PREFIX)
        claims = verify_egress_token_v2(EGRESS_SECRET, token, datetime.now(UTC))
        assert claims.sandbox_id == created.id
        assert claims.epoch == 0
    for name in NO_PROXY_VARIABLES:
        assert created.env[name] == "localhost,127.0.0.1"


async def test_a_create_without_an_allowlist_gains_no_proxy_variables(
    make_app: AppFactory,
) -> None:
    app = make_app(**PROXY_SETTINGS)
    org_id, _ = await connect(app)

    created = await service_of(app).create(
        org_id, ACTOR, CreateSandboxCommand(name="plain", env={"KEEP": "1"})
    )

    assert created.env == {"KEEP": "1"}
