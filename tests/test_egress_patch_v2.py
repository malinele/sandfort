"""Egress v2 round 3 (round 86a): PATCH ``egress_allowlist`` (docs/egress-v2-design.md 3.4, 10.1).

Cases A1 to A9 and the response half of A11 of section 12.4. Hermetic: FakeDriver, temp SQLite
migrated with alembic, httpx ASGITransport. The PATCH writes only to the database; the audit row
``sandbox.egress_updated`` shares the unit of work with the row update.
"""

from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from sqlalchemy import text

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import Sandbox
from sandfort.egress.env import PROXY_VARIABLES
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.services.sandbox_jobs import Lifecycle

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
PROXY_SETTINGS = {"egress_proxy_address": "proxy.internal:3128", "egress_secret": "e" * 40}
EGRESS_UPDATED = "sandbox.egress_updated"
OLD = ["api.example.com", ".example.org"]
NEW = ["b.example.net", "8.8.8.0/24"]
NULL_MESSAGE = (
    "egress_allowlist cannot be removed from a sandbox, create a new sandbox for open egress"
)
LEGACY_MESSAGE = "reset the sandbox to upgrade its egress credential"

AppFactory = Callable[..., FastAPI]
Seeded = tuple[FastAPI, str, str, str]  # app, org id, api key, sandbox id


@pytest.fixture
async def make_app(tmp_path: Path) -> AsyncIterator[AppFactory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    built: list[FastAPI] = []

    def build(**overrides: Any) -> FastAPI:
        url = f"sqlite+aiosqlite:///{tmp_path / 'egress-patch.db'}"  # one database per test
        config = Config(str(ROOT / "alembic.ini"))
        config.set_main_option("sqlalchemy.url", url)
        command.upgrade(config, "head")
        settings = Settings(
            driver="fake",
            database_url=url,
            api_key_pepper=PEPPER,
            autostop_enabled=False,
            **{**PROXY_SETTINGS, **overrides},
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
    generated = generate_api_key(PEPPER)
    stored_key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=READ_WRITE,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored_key)
        await uow.commit()
    return org.id, generated.key


async def send(
    app: FastAPI, key: str, method: str, path: str, *, tolerate: bool = False, **kwargs: Any
) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=not tolerate)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        headers = {"Authorization": f"Bearer {key}"}
        return await http.request(method, path, headers=headers, **kwargs)


async def create(app: FastAPI, key: str, **payload: Any) -> dict[str, Any]:
    response = await send(app, key, "POST", BASE, json={"name": "egress", **payload})
    assert response.status_code == 201, response.text
    data: dict[str, Any] = response.json()["data"]
    return data


async def seed(make_app: AppFactory, entries: list[str] | None = OLD, **overrides: Any) -> Seeded:
    """An app with a sandbox created with ``entries`` (``None``: no ``egress_allowlist`` field)."""
    app = make_app(**overrides)
    org_id, key = await connect(app)
    payload = {} if entries is None else {"egress_allowlist": entries}
    return app, org_id, key, (await create(app, key, **payload))["id"]


async def patch(app: FastAPI, key: str, sandbox_id: str, **payload: Any) -> httpx.Response:
    return await send(app, key, "PATCH", f"{BASE}/{sandbox_id}", json=payload, tolerate=False)


async def force_generation(app: FastAPI, sandbox_id: str, value: int) -> None:
    """Make the row a legacy one (generation 0) without going through the api."""
    async with app.state.session_factory() as session:
        await session.execute(
            text("UPDATE sandboxes SET egress_policy_generation = :value WHERE id = :id"),
            {"value": value, "id": sandbox_id},
        )
        await session.commit()


async def stored(app: FastAPI, org_id: str, sandbox_id: str) -> Sandbox:
    async with UnitOfWork(app.state.session_factory) as uow:
        row = await uow.sandboxes.get(org_id, sandbox_id)
    assert row is not None
    return row


async def audit_rows(app: FastAPI, org_id: str, action: str) -> list[Any]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, action=action))


def message_of(response: httpx.Response) -> str:
    return str(response.json()["error"]["message"])


# -- A1, A2: replace and no-op ----------------------------------------------------------------
async def test_a1_a_new_list_replaces_the_stored_one_and_raises_the_generation(
    make_app: AppFactory,
) -> None:
    app, org_id, key, sandbox_id = await seed(make_app)
    created = await send(app, key, "GET", f"{BASE}/{sandbox_id}")
    assert created.json()["data"]["egress_policy_generation"] == 1

    response = await patch(app, key, sandbox_id, egress_allowlist=NEW)

    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["egress_allowlist"] == NEW
    assert data["egress_policy_generation"] == 2
    row = await stored(app, org_id, sandbox_id)
    assert (row.egress_allowlist, row.egress_policy_generation) == (tuple(NEW), 2)
    (event,) = await audit_rows(app, org_id, EGRESS_UPDATED)
    assert event.target_id == sandbox_id
    assert event.details == {
        "old_allowlist": OLD,
        "new_allowlist": NEW,
        "old_generation": 1,
        "new_generation": 2,
    }


async def test_an_empty_list_is_accepted_for_a_sandbox_created_with_entries(
    make_app: AppFactory,
) -> None:
    app, org_id, key, sandbox_id = await seed(make_app)

    response = await patch(app, key, sandbox_id, egress_allowlist=[])

    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert (data["egress_allowlist"], data["egress_policy_generation"]) == ([], 2)
    row = await stored(app, org_id, sandbox_id)
    assert row.egress_allowlist == ()
    assert row.network.block_all is False  # the sandbox stays on the egress network
    (event,) = await audit_rows(app, org_id, EGRESS_UPDATED)
    assert event.details["new_allowlist"] == []


async def test_a2_the_same_list_in_the_same_order_changes_nothing(make_app: AppFactory) -> None:
    app, org_id, key, sandbox_id = await seed(make_app)

    response = await patch(app, key, sandbox_id, egress_allowlist=list(OLD))

    assert response.status_code == 200, response.text
    assert response.json()["data"]["egress_policy_generation"] == 1
    assert await audit_rows(app, org_id, EGRESS_UPDATED) == []
    row = await stored(app, org_id, sandbox_id)
    assert (row.egress_allowlist, row.egress_policy_generation) == (tuple(OLD), 1)


# -- A3 to A7: refusals -----------------------------------------------------------------------
async def test_a3_an_explicit_null_is_refused_with_the_exact_message(make_app: AppFactory) -> None:
    app, org_id, key, sandbox_id = await seed(make_app)

    response = await patch(app, key, sandbox_id, egress_allowlist=None, labels={"team": "a"})

    assert response.status_code == 422, response.text
    assert message_of(response) == NULL_MESSAGE
    row = await stored(app, org_id, sandbox_id)
    assert (row.egress_allowlist, row.egress_policy_generation) == (tuple(OLD), 1)
    assert "team" not in row.labels  # nothing of the refused PATCH was applied


@pytest.mark.parametrize(("entries", "stored_list"), [(None, None), ([], ())])  # A4, A5
async def test_a4_a5_a_sandbox_without_an_allowlist_or_with_an_empty_one_answers_409(
    make_app: AppFactory, entries: list[str] | None, stored_list: tuple[str, ...] | None
) -> None:
    app, org_id, key, sandbox_id = await seed(make_app, entries)

    response = await patch(app, key, sandbox_id, egress_allowlist=NEW)

    assert response.status_code == 409, response.text
    row = await stored(app, org_id, sandbox_id)
    assert row.egress_allowlist == stored_list
    assert row.network.block_all is (entries == [])


async def test_a6_a_legacy_sandbox_must_be_reset_before_it_can_be_patched(
    make_app: AppFactory,
) -> None:
    app, org_id, key, sandbox_id = await seed(make_app)
    await force_generation(app, sandbox_id, 0)

    refused = await patch(app, key, sandbox_id, egress_allowlist=NEW)

    assert refused.status_code == 409, refused.text
    assert message_of(refused) == LEGACY_MESSAGE
    assert (await stored(app, org_id, sandbox_id)).egress_policy_generation == 0

    reset = await send(app, key, "POST", f"{BASE}/{sandbox_id}/reset")
    assert reset.status_code == 200, reset.text
    assert reset.json()["data"]["egress_policy_generation"] >= 1
    after_reset = await stored(app, org_id, sandbox_id)
    assert after_reset.egress_policy_generation >= 1

    accepted = await patch(app, key, sandbox_id, egress_allowlist=NEW)

    assert accepted.status_code == 200, accepted.text
    data = accepted.json()["data"]
    assert data["egress_allowlist"] == NEW
    assert data["egress_policy_generation"] == after_reset.egress_policy_generation + 1


async def test_a_destroyed_sandbox_answers_409(make_app: AppFactory) -> None:
    app, _, key, sandbox_id = await seed(make_app)
    deleted = await send(app, key, "DELETE", f"{BASE}/{sandbox_id}")
    assert deleted.status_code == 200, deleted.text

    response = await patch(app, key, sandbox_id, egress_allowlist=NEW)

    assert response.status_code == 409, response.text


async def test_a7_enforce_block_network_refuses_the_patch_with_403(make_app: AppFactory) -> None:
    app, org_id, key, sandbox_id = await seed(make_app)
    enforcing = make_app(enforce_block_network=True)  # same database, stricter deployment

    response = await patch(enforcing, key, sandbox_id, egress_allowlist=NEW)

    assert response.status_code == 403, response.text
    row = await stored(app, org_id, sandbox_id)
    assert (row.egress_allowlist, row.egress_policy_generation) == (tuple(OLD), 1)


# -- A8, A9: one transaction ------------------------------------------------------------------
@pytest.mark.parametrize("failing_action", [None, "sandbox.update"])
async def test_a8_a_failing_audit_write_leaves_the_row_unchanged(
    make_app: AppFactory, monkeypatch: pytest.MonkeyPatch, failing_action: str | None
) -> None:
    app, org_id, key, sandbox_id = await seed(make_app)
    before = await stored(app, org_id, sandbox_id)

    async def audit_down(self: Lifecycle, uow: Any, org: str, target: str, note: Any) -> None:
        if failing_action in (None, note.action):  # None: every audit write fails
            raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(Lifecycle, "record", audit_down)
    payload: dict[str, Any] = {"egress_allowlist": NEW}
    if failing_action is not None:
        payload["labels"] = {"team": "a"}  # the egress note lands first, the update note fails
    response = await send(app, key, "PATCH", f"{BASE}/{sandbox_id}", json=payload, tolerate=True)

    assert response.status_code >= 500, response.text
    after = await stored(app, org_id, sandbox_id)
    assert (after.egress_allowlist, after.egress_policy_generation) == (tuple(OLD), 1)
    assert after.version == before.version
    assert "team" not in after.labels
    assert await audit_rows(app, org_id, EGRESS_UPDATED) == []


async def test_a9_egress_and_labels_commit_together_with_both_audit_rows(
    make_app: AppFactory,
) -> None:
    app, org_id, key, sandbox_id = await seed(make_app)

    response = await patch(app, key, sandbox_id, egress_allowlist=NEW, labels={"team": "payments"})

    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["egress_allowlist"] == NEW
    assert data["egress_policy_generation"] == 2
    assert data["labels"] == {"team": "payments"}
    row = await stored(app, org_id, sandbox_id)
    assert (row.egress_allowlist, row.labels["team"]) == (tuple(NEW), "payments")
    (egress_event,) = await audit_rows(app, org_id, EGRESS_UPDATED)
    (update_event,) = await audit_rows(app, org_id, "sandbox.update")
    assert egress_event.details["new_generation"] == 2
    assert update_event.details["labels"] == {"team": "payments"}
    assert update_event.target_id == egress_event.target_id == sandbox_id


# -- validation -------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        ("Example.com", "lowercase"),
        ("example.com:443", "port"),
        ("10.0.0.0/8", "entirely global"),  # the CIDR cases of the round 1 validation
        ("10.0.0.1/8", "host bits set"),
        ("https://example.com", "scheme"),
    ],
)
async def test_an_invalid_entry_answers_422_naming_it_and_stores_nothing(
    make_app: AppFactory, entry: str, reason: str
) -> None:
    app, org_id, key, sandbox_id = await seed(make_app)

    response = await patch(app, key, sandbox_id, egress_allowlist=["ok.example.com", entry])

    assert response.status_code == 422, response.text
    assert repr(entry) in message_of(response)
    assert reason in message_of(response)
    row = await stored(app, org_id, sandbox_id)
    assert (row.egress_allowlist, row.egress_policy_generation) == (tuple(OLD), 1)
    assert await audit_rows(app, org_id, EGRESS_UPDATED) == []


# -- A11, response half -----------------------------------------------------------------------
async def test_a11_the_response_carries_the_generation_by_allowlist_state(
    make_app: AppFactory,
) -> None:
    app = make_app()
    _, key = await connect(app)
    plain = await create(app, key, name="plain")
    closed = await create(app, key, name="closed", egress_allowlist=[])
    listed = await create(app, key, name="listed", egress_allowlist=OLD)
    legacy = await create(app, key, name="legacy", egress_allowlist=OLD)
    await force_generation(app, legacy["id"], 0)

    generations = {}
    for sandbox in (plain, closed, listed, legacy):
        response = await send(app, key, "GET", f"{BASE}/{sandbox['id']}")
        assert response.status_code == 200, response.text
        generations[sandbox["name"]] = response.json()["data"]["egress_policy_generation"]

    assert plain["egress_policy_generation"] is None
    assert generations["plain"] is None
    assert generations["closed"] >= 1  # a [] create still stores generation 1
    assert generations["listed"] >= 1
    assert generations["legacy"] == 0


async def test_a11_no_token_appears_in_any_response_body(make_app: AppFactory) -> None:
    app, org_id, key, sandbox_id = await seed(make_app)
    proxy_url = urlsplit((await stored(app, org_id, sandbox_id)).env[PROXY_VARIABLES[0]])
    assert proxy_url.password is not None
    token = unquote(proxy_url.password)
    url = f"{BASE}/{sandbox_id}"

    responses = [
        await send(app, key, "GET", url),
        await send(app, key, "GET", BASE),
        await patch(app, key, sandbox_id, egress_allowlist=NEW),
        await patch(app, key, sandbox_id, egress_allowlist=None),  # the error body too
        await send(app, key, "POST", f"{url}/reset"),
        await send(app, key, "GET", url),
    ]

    for response in responses:
        assert "sfe_" not in response.text
        assert "sfe2_" not in response.text
        assert token not in response.text
