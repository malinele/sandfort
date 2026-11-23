"""Round 63: a label-scoped key sees its own cap and count in ``GET /v1/org/quota``.

Server side: through the app on the fake driver and a temp SQLite database. An org-wide key
keeps the org snapshot (``scope`` null); a scoped key sees the org limits, its own cap, its own
live count and the reservation of its own scope, and never another team's numbers. SDK side:
``client.quota.get()`` sync and async over an ``httpx.MockTransport``. CLI side:
``sandfort quota`` (table and ``--json``) against ``respx``. No socket is opened.
"""

import json
import sys
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
import sandfort_sdk  # noqa: E402
import sandfort_sdk.quota as quota_module  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app as create_cli  # noqa: E402
from sandfort_sdk import AsyncClient, Client, InvalidResponseError  # noqa: E402
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402
from sandfort_sdk.quota import AsyncQuota, Quota, QuotaSnapshot  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

from sandfort.api.app import create_app  # noqa: E402
from sandfort.auth.api_keys import generate_api_key  # noqa: E402
from sandfort.config import Settings  # noqa: E402
from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.org import ApiKey, Org, Scope  # noqa: E402
from sandfort.ids import new_api_key_id, new_org_id  # noqa: E402

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
QUOTA = "/v1/org/quota"
SANDBOXES = "/v1/sandboxes"
KEYS = "/v1/api-keys"
BASE = "http://sandfort.test"
KEY = "sf_test_key"
PROFILE_KEY = "sf_test_key_do_not_print"
TIMEOUT_S = 30.0
READER = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.ORG_READ})
ADMIN = READER | {Scope.API_KEYS_ADMIN}
TEAM_A = {"team": "a"}
TEAM_B = {"team": "b"}
A_CAP = 3
B_COUNT = 2
ORG_SANDBOX_LIMIT = 20
RUNNER = CliRunner()
Handler = Callable[[httpx.Request], httpx.Response]


# --- server ----------------------------------------------------------------------------------


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'scoped_quota.db'}"
    alembic = Config(str(ROOT / "alembic.ini"))
    alembic.set_main_option("sqlalchemy.url", url)
    command.upgrade(alembic, "head")
    application = create_app(
        Settings(driver="fake", database_url=url, api_key_pepper=PEPPER, rate_limit_enabled=False)
    )
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as http:
        yield http


@pytest.fixture
async def admin_key(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="School", slug="school", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="seed",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=ADMIN,
        is_platform_admin=True,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def mint(
    client: httpx.AsyncClient, admin: str, labels: dict[str, str], cap: int | None
) -> str:
    body: dict[str, Any] = {
        "name": f"team-{labels['team']}",
        "scopes": [scope.value for scope in READER],
        "sandbox_labels": labels,
    }
    if cap is not None:
        body["max_sandboxes"] = cap
    response = await client.post(KEYS, json=body, headers=bearer(admin))
    assert response.status_code == 201, response.text
    return str(response.json()["data"]["key"])


async def make_sandboxes(client: httpx.AsyncClient, key: str, count: int) -> None:
    for _ in range(count):
        created = await client.post(SANDBOXES, json={}, headers=bearer(key))
        assert created.status_code == 201, created.text


async def view(client: httpx.AsyncClient, key: str) -> dict[str, Any]:
    response = await client.get(QUOTA, headers=bearer(key))
    assert response.status_code == 200, response.text
    data: dict[str, Any] = response.json()["data"]
    return data


@pytest.fixture
async def teams(client: httpx.AsyncClient, admin_key: str) -> tuple[str, str]:
    """Team A (cap 3, one sandbox) and team B (no cap, two sandboxes) in one org."""
    limits = {"max_sandboxes": ORG_SANDBOX_LIMIT, "max_vcpus": 40, "max_memory_mib": 65536}
    put = await client.put(QUOTA, json=limits, headers=bearer(admin_key))
    assert put.status_code == 200, put.text
    team_a = await mint(client, admin_key, TEAM_A, A_CAP)
    team_b = await mint(client, admin_key, TEAM_B, None)
    await make_sandboxes(client, team_a, 1)
    await make_sandboxes(client, team_b, B_COUNT)
    return team_a, team_b


async def test_an_org_wide_key_keeps_the_org_snapshot(
    client: httpx.AsyncClient, admin_key: str, teams: tuple[str, str]
) -> None:
    data = await view(client, admin_key)

    assert data["limits"] == {
        "max_vcpus": 40.0, "max_memory_mib": 65536, "max_disk_gib": None,
        "max_sandboxes": ORG_SANDBOX_LIMIT,
    }  # fmt: skip
    assert data["reserved"]["sandboxes"] == 1 + B_COUNT
    assert data["scope"] is None


async def test_a_scoped_key_sees_its_cap_and_its_count(
    client: httpx.AsyncClient, teams: tuple[str, str]
) -> None:
    data = await view(client, teams[0])

    assert data["scope"] == {
        "labels": TEAM_A, "max_sandboxes": A_CAP, "sandboxes": 1, "remaining": A_CAP - 1,
    }  # fmt: skip
    assert data["limits"]["max_sandboxes"] == ORG_SANDBOX_LIMIT


async def test_a_scoped_key_never_sees_another_teams_numbers(
    client: httpx.AsyncClient, teams: tuple[str, str]
) -> None:
    team_a, team_b = teams

    a_view = await view(client, team_a)
    b_view = await view(client, team_b)

    assert a_view["reserved"]["sandboxes"] == 1
    assert a_view["reserved"]["memory_mib"] == 512
    assert a_view["reserved"]["vcpus"] == 1.0
    assert b_view["reserved"]["sandboxes"] == B_COUNT
    assert b_view["scope"] == {
        "labels": TEAM_B, "max_sandboxes": None, "sandboxes": B_COUNT, "remaining": None,
    }  # fmt: skip
    assert a_view["scope"]["labels"] == TEAM_A
    assert (1 + B_COUNT) not in (a_view["reserved"]["sandboxes"], a_view["scope"]["sandboxes"])


async def test_the_count_follows_creates_and_deletes_and_remaining_stops_at_zero(
    client: httpx.AsyncClient, teams: tuple[str, str]
) -> None:
    team_a = teams[0]
    await make_sandboxes(client, team_a, A_CAP - 1)

    full = await view(client, team_a)
    assert full["scope"]["sandboxes"] == A_CAP
    assert full["scope"]["remaining"] == 0
    refused = await client.post(SANDBOXES, json={}, headers=bearer(team_a))
    assert refused.status_code == 429

    listing = await client.get(SANDBOXES, headers=bearer(team_a))
    first = listing.json()["data"][0]["id"]
    deleted = await client.delete(f"{SANDBOXES}/{first}", headers=bearer(team_a))
    assert deleted.status_code in (200, 202, 204), deleted.text
    after = await view(client, team_a)
    assert after["scope"]["sandboxes"] == A_CAP - 1
    assert after["scope"]["remaining"] == 1
    assert after["reserved"]["sandboxes"] == A_CAP - 1


# --- SDK -------------------------------------------------------------------------------------


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def org_json() -> dict[str, Any]:
    return {
        "limits": {
            "max_vcpus": 8.0, "max_memory_mib": None, "max_disk_gib": None, "max_sandboxes": 20,
        },
        "reserved": {"vcpus": 3.0, "memory_mib": 1536, "disk_gib": 9, "sandboxes": 3},
        "scope": None,
    }  # fmt: skip


def scoped_json() -> dict[str, Any]:
    return {
        **org_json(),
        "reserved": {"vcpus": 1.0, "memory_mib": 512, "disk_gib": 3, "sandboxes": 1},
        "scope": {"labels": TEAM_A, "max_sandboxes": 3, "sandboxes": 1, "remaining": 2},
    }


def sync_quota(handler: Handler) -> Quota:
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return Quota(transport)


def async_quota(handler: Handler) -> AsyncQuota:
    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return AsyncQuota(transport)


def answering(data: Any) -> tuple[Handler, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=envelope(data))

    return handler, seen


def test_sdk_org_wide_view_has_no_scope() -> None:
    handler, seen = answering(org_json())

    snapshot = sync_quota(handler).get()

    assert isinstance(snapshot, QuotaSnapshot)
    assert (seen[0].method, seen[0].url.path) == ("GET", QUOTA)
    assert snapshot.scope is None
    assert snapshot.limits.max_sandboxes == 20
    assert snapshot.limits.max_memory_mib is None
    assert snapshot.reserved.vcpus == 3.0
    assert snapshot.reserved.sandboxes == 3


def test_sdk_scoped_view_carries_cap_count_and_remaining() -> None:
    handler, _ = answering(scoped_json())

    snapshot = sync_quota(handler).get()

    assert snapshot.scope is not None
    assert snapshot.scope.labels == TEAM_A
    assert (snapshot.scope.max_sandboxes, snapshot.scope.sandboxes) == (3, 1)
    assert snapshot.scope.remaining == 2
    assert snapshot.reserved.sandboxes == 1


def test_sdk_an_older_server_without_scope_loads_as_org_wide() -> None:
    legacy = {key: value for key, value in org_json().items() if key != "scope"}
    handler, _ = answering(legacy)

    assert sync_quota(handler).get().scope is None


@pytest.mark.parametrize(
    "payload",
    [[], {"limits": {}}, {**org_json(), "reserved": {"vcpus": True, "memory_mib": 1,
                                                       "disk_gib": 1, "sandboxes": 1}}],
)  # fmt: skip
def test_sdk_refuses_a_reply_of_the_wrong_shape(payload: Any) -> None:
    handler, _ = answering(payload)

    with pytest.raises(InvalidResponseError):
        sync_quota(handler).get()


async def test_sdk_async_twin_matches() -> None:
    handler, seen = answering(scoped_json())

    snapshot = await async_quota(handler).get()

    assert snapshot == sync_quota(answering(scoped_json())[0]).get()
    assert seen[0].url.path == QUOTA


def test_sdk_clients_expose_the_quota_facade() -> None:
    client = Client(BASE, KEY)
    try:
        assert isinstance(client.quota, Quota)
        assert client.quota is client.quota
    finally:
        client.close()


async def test_sdk_async_client_exposes_the_quota_facade() -> None:
    client = AsyncClient(BASE, KEY)
    try:
        assert isinstance(client.quota, AsyncQuota)
    finally:
        await client.aclose()


@pytest.mark.parametrize("name", ["Quota", "AsyncQuota", "QuotaSnapshot", "QuotaScope"])
def test_sdk_package_exports_the_quota_types(name: str) -> None:
    assert name in sandfort_sdk.__all__
    assert getattr(sandfort_sdk, name) is getattr(quota_module, name)


# --- CLI -------------------------------------------------------------------------------------


@pytest.fixture
def router(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, PROFILE_KEY)
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


def invoke(*, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_cli(), (["--json"] if as_json else []) + ["quota"])


def test_cli_org_wide_table(router: Any) -> None:
    router.get(QUOTA).respond(200, json=envelope(org_json()))

    result = invoke()

    assert result.exit_code == 0, result.output
    for text in ("RESOURCE", "LIMIT", "RESERVED", "sandboxes", "memory_mib", "20", "1536"):
        assert text in result.stdout
    assert "unlimited" in result.stdout
    assert "IN SCOPE" not in result.stdout


def test_cli_scoped_table_shows_the_key_cap_and_count(router: Any) -> None:
    router.get(QUOTA).respond(200, json=envelope(scoped_json()))

    result = invoke()

    assert result.exit_code == 0, result.output
    assert "team=a" in result.stdout
    for text in ("CAP", "IN SCOPE", "REMAINING"):
        assert text in result.stdout.upper()


def test_cli_json_prints_the_view_as_the_server_sent_it(router: Any) -> None:
    router.get(QUOTA).respond(200, json=envelope(scoped_json()))

    result = invoke(as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == scoped_json()


def test_cli_json_org_wide_has_a_null_scope(router: Any) -> None:
    router.get(QUOTA).respond(200, json=envelope(org_json()))

    result = invoke(as_json=True)

    assert json.loads(result.stdout)["scope"] is None


def test_cli_strips_terminal_sequences_from_labels(router: Any) -> None:
    data = scoped_json()
    data["scope"]["labels"] = {"team": "a\x1b[31mred"}
    router.get(QUOTA).respond(200, json=envelope(data))

    result = invoke()

    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.stdout


def test_cli_api_error_exits_nonzero_and_never_prints_the_key(router: Any) -> None:
    body = {"success": False, "data": None, "error": {"code": "FORBIDDEN", "message": "no"}}
    router.get(QUOTA).respond(403, json=body)

    result = invoke()

    assert result.exit_code != 0
    assert PROFILE_KEY not in result.output
