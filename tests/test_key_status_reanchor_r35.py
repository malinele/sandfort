"""Round 35: API-key rows carry a server-computed ``status``; re-anchor records who and why.

Key status: ``revoked`` wins over ``expired``, ``expired`` once ``expires_at`` has passed,
else ``active``. Re-anchor: ``--operator`` and ``--reason-code`` are stored next to the note
and ``GET /v1/audit-events/verify`` exposes the effective event as ``reanchor``. Sync tests:
the admin CLI runs its own event loop.
"""

import asyncio
import json
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sandfort_sdk import ApiKeyInfo  # noqa: E402
from sqlalchemy import text  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

from sandfort import admin_cli  # noqa: E402
from sandfort.api.app import create_app  # noqa: E402
from sandfort.api.routes import audit as audit_routes  # noqa: E402
from sandfort.api.schemas import api_keys as key_schemas  # noqa: E402
from sandfort.auth.api_keys import generate_api_key  # noqa: E402
from sandfort.auth.authenticate import AUTH_STATE_ATTR  # noqa: E402
from sandfort.clock import FrozenClock  # noqa: E402
from sandfort.config import Settings  # noqa: E402
from sandfort.db.engine import create_engine, create_session_factory  # noqa: E402
from sandfort.db.unit_of_work import UnitOfWork  # noqa: E402
from sandfort.domain.events import ActorType  # noqa: E402
from sandfort.domain.org import ApiKey, Org, Scope  # noqa: E402
from sandfort.ids import new_api_key_id, new_org_id  # noqa: E402
from sandfort.services.audit import AuditRecorder  # noqa: E402
from sandfort.services.audit_chain import REANCHOR_ACTION, link_hash  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
KEYS_URL = "/v1/api-keys"
VERIFY_URL = "/v1/audit-events/verify"
FORGED_PREV = "f" * 64
NOTE = "2026-11 incident: forks written before the chain lock"
OPERATOR = "alice.ops"
RUNNER = CliRunner()
ADMIN_SCOPES = frozenset({Scope.API_KEYS_ADMIN, Scope.AUDIT_READ})


@pytest.fixture
def db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'r35.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    monkeypatch.setenv("SANDFORT_DATABASE_URL", url)
    monkeypatch.setenv("SANDFORT_API_KEY_PEPPER", PEPPER)
    return url


def _settings(url: str) -> Settings:
    return Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)


def _key(org_id: str, name: str, **extra: Any) -> tuple[ApiKey, str]:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name=name,
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=ADMIN_SCOPES,
        created_at=NOW,
        **extra,
    )
    return stored, generated.key


async def _setup_org(url: str, *extra_keys: tuple[str, dict[str, Any]]) -> tuple[str, str]:
    """An org with an admin key plus ``extra_keys`` (name, ApiKey fields); (org id, key)."""
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    admin, plaintext = _key(org.id, "admin")
    engine = create_engine(_settings(url))
    try:
        async with UnitOfWork(create_session_factory(engine)) as uow:
            await uow.orgs.add(org)
            await uow.api_keys.add(admin)
            for name, fields in extra_keys:
                await uow.api_keys.add(_key(org.id, name, **fields)[0])
            await uow.commit()
    finally:
        await engine.dispose()
    return org.id, plaintext


async def _get(url: str, key: str, path: str) -> Any:
    app = create_app(_settings(url))
    app.include_router(audit_routes.router)
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            response = await http.get(path, headers={"Authorization": f"Bearer {key}"})
        assert response.status_code == 200, response.text
        return response.json()["data"]
    finally:
        await app.state.engine.dispose()


# --- API key status ---------------------------------------------------------------------


def test_key_rows_carry_active_expired_and_revoked_status(db_url: str) -> None:
    now = datetime.now(UTC)
    past = now - timedelta(days=1)
    _, key = asyncio.run(
        _setup_org(
            db_url,
            ("expires-later", {"expires_at": now + timedelta(days=30)}),
            ("expired", {"expires_at": past}),
            ("revoked", {"revoked_at": past}),
            ("revoked-and-expired", {"revoked_at": past, "expires_at": past}),
        )
    )

    rows = asyncio.run(_get(db_url, key, KEYS_URL))

    by_name = {row["name"]: row["status"] for row in rows}
    assert by_name == {
        "admin": "active",
        "expires-later": "active",
        "expired": "expired",
        "revoked": "revoked",
        "revoked-and-expired": "revoked",
    }
    infos = [ApiKeyInfo.from_payload(row) for row in rows]  # the new field breaks no parse
    assert sorted(info.name for info in infos) == sorted(by_name)


def test_status_is_computed_at_the_given_time_and_expiry_is_inclusive() -> None:
    key, _ = _key("org_x", "k", expires_at=NOW)
    revoked = key.model_copy(update={"revoked_at": NOW - timedelta(days=1)})
    status = key_schemas.ApiKeyStatus

    def at(record: ApiKey, now: datetime) -> key_schemas.ApiKeyStatus:
        return key_schemas.api_key_response(record, now=now).status

    assert at(key, NOW - timedelta(seconds=1)) is status.ACTIVE
    assert at(key, NOW) is status.EXPIRED
    assert at(revoked, NOW) is status.REVOKED


async def _list_statuses_at(url: str, key: str, clock: FrozenClock, *times: datetime) -> list[Any]:
    """The key statuses by name from one app whose auth clock is ``clock``, set to each time."""
    app = create_app(_settings(url))
    # The context authentication reads is the one the routes take ``now`` from.
    setattr(app.state, AUTH_STATE_ATTR, replace(getattr(app.state, AUTH_STATE_ATTR), clock=clock))
    snapshots: list[Any] = []
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            for moment in times:
                clock.set(moment)
                response = await http.get(KEYS_URL, headers={"Authorization": f"Bearer {key}"})
                assert response.status_code == 200, response.text
                snapshots.append({row["name"]: row["status"] for row in response.json()["data"]})
        return snapshots
    finally:
        await app.state.engine.dispose()


def test_listed_status_follows_the_injected_clock_not_the_wall_clock(db_url: str) -> None:
    wall_now = datetime.now(UTC)
    expires_at = wall_now + timedelta(days=30)  # still in the future by the wall clock
    _, key = asyncio.run(_setup_org(db_url, ("short-lived", {"expires_at": expires_at})))
    clock = FrozenClock(wall_now)

    before, after = asyncio.run(
        _list_statuses_at(db_url, key, clock, wall_now, expires_at + timedelta(seconds=1))
    )

    assert datetime.now(UTC) < expires_at  # the wall clock would still say active
    assert before["short-lived"] == "active"
    assert after["short-lived"] == "expired"
    assert after["admin"] == "active"  # the non-expiring admin key still authenticates


def test_status_has_a_description_in_the_schema() -> None:
    field = key_schemas.ApiKeyResponse.model_fields["status"]

    assert field.description and "revoked" in field.description


# --- re-anchor operator and reason code -------------------------------------------------


async def _seed(url: str, org_id: str, count: int) -> list[str]:
    recorder = AuditRecorder(FrozenClock(NOW))
    engine = create_engine(_settings(url))
    ids: list[str] = []
    try:
        for index in range(count):
            async with UnitOfWork(create_session_factory(engine)) as uow:
                event = await recorder.record(
                    uow,
                    org_id=org_id,
                    actor_type=ActorType.SYSTEM,
                    actor_id=None,
                    action=f"test.step{index}",
                    target_type="thing",
                    target_id=f"thing-{index}",
                    details={"n": index},
                )
                await uow.commit()
            ids.append(event.id)
    finally:
        await engine.dispose()
    return ids


async def _fork_at(url: str, org_id: str, index: int) -> None:
    """Make row ``index`` link to a hash that is not its predecessor's (one broken link)."""
    engine = create_engine(_settings(url))
    try:
        async with UnitOfWork(create_session_factory(engine)) as uow:
            rows = list(await uow.audit.list_chained(org_id, limit=1000))
        prev = FORGED_PREV
        async with engine.begin() as connection:
            for row in rows[index:]:
                entry_hash = link_hash(prev, row.event)
                await connection.execute(
                    text("UPDATE audit_events SET prev_hash = :p, hash = :h WHERE id = :id"),
                    {"p": prev, "h": entry_hash, "id": row.event.id},
                )
                prev = entry_hash
    finally:
        await engine.dispose()


def broken_chain(url: str) -> tuple[str, str, list[str]]:
    """An org with 6 rows and two forged links (rows 1 and 3)."""
    org_id, key = asyncio.run(_setup_org(url))
    ids = asyncio.run(_seed(url, org_id, 6))
    asyncio.run(_fork_at(url, org_id, 1))
    asyncio.run(_fork_at(url, org_id, 3))
    return org_id, key, ids


def reanchor(org_id: str, *extra: str) -> Any:
    args = ["audit-reanchor", "--org", org_id, "--note", NOTE, *extra]
    return RUNNER.invoke(admin_cli.app, args)


def exported(org_id: str) -> list[dict[str, Any]]:
    result = RUNNER.invoke(admin_cli.app, ["audit-export", "--org-id", org_id])
    assert result.exit_code == 0, result.output
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]


def test_reanchor_stores_operator_and_reason_code_next_to_the_note(db_url: str) -> None:
    org_id, _, ids = broken_chain(db_url)

    result = reanchor(org_id, "--operator", OPERATOR, "--reason-code", "migration")

    assert result.exit_code == 0, result.output
    event = exported(org_id)[-1]
    assert event["action"] == REANCHOR_ACTION and event["id"] == result.stdout.strip()
    assert event["details"] == {
        "acknowledged_through": ids[3],
        "findings": 2,
        "note": NOTE,
        "operator": OPERATOR,
        "reason_code": "migration",
    }


def test_verify_exposes_the_reanchor_object(db_url: str) -> None:
    org_id, key, ids = broken_chain(db_url)
    result = reanchor(org_id, "--operator", OPERATOR, "--reason-code", "incident_acknowledged")
    assert result.exit_code == 0, result.output
    event_id = result.stdout.strip()

    data = asyncio.run(_get(db_url, key, VERIFY_URL))

    assert data["ok"] is True and data["reanchored_by"] == event_id
    body = dict(data["reanchor"])
    occurred_at = body.pop("occurred_at")
    assert body == {
        "event_id": event_id,
        "operator": OPERATOR,
        "reason_code": "incident_acknowledged",
        "acknowledged_through": ids[3],
        "findings": 2,
        "note": NOTE,
    }
    assert datetime.fromisoformat(occurred_at).tzinfo is not None


def test_verify_has_no_reanchor_without_a_reanchor(db_url: str) -> None:
    _, key, _ = broken_chain(db_url)

    data = asyncio.run(_get(db_url, key, VERIFY_URL))

    assert data["ok"] is False
    assert data.get("reanchor") is None and "reanchored_by" not in data


def test_an_older_reanchor_without_operator_shows_operator_null(db_url: str) -> None:
    org_id, key, _ = broken_chain(db_url)
    result = reanchor(org_id)
    assert result.exit_code == 0, result.output

    data = asyncio.run(_get(db_url, key, VERIFY_URL))

    assert data["reanchor"]["event_id"] == result.stdout.strip()
    assert data["reanchor"]["operator"] is None and data["reanchor"]["reason_code"] is None
    assert data["reanchor"]["note"] == NOTE


def test_operator_without_reason_code_exits_non_zero_and_writes_nothing(db_url: str) -> None:
    org_id, _, ids = broken_chain(db_url)

    result = reanchor(org_id, "--operator", OPERATOR)

    assert result.exit_code != 0
    assert len(exported(org_id)) == len(ids)


def test_reason_code_without_operator_exits_non_zero_and_writes_nothing(db_url: str) -> None:
    org_id, _, ids = broken_chain(db_url)

    result = reanchor(org_id, "--reason-code", "other")

    assert result.exit_code != 0
    assert len(exported(org_id)) == len(ids)


def test_an_unknown_reason_code_exits_non_zero(db_url: str) -> None:
    org_id, _, ids = broken_chain(db_url)

    result = reanchor(org_id, "--operator", OPERATOR, "--reason-code", "because")

    assert result.exit_code != 0
    assert len(exported(org_id)) == len(ids)


def test_a_blank_operator_exits_non_zero(db_url: str) -> None:
    org_id, _, ids = broken_chain(db_url)

    result = reanchor(org_id, "--operator", "  ", "--reason-code", "other")

    assert result.exit_code != 0
    assert len(exported(org_id)) == len(ids)
