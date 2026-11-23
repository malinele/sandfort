"""Round 60: the audit outcome of a refused request is never ``success``.

Every 4xx answer is audited ``denied`` and every 5xx ``error`` (the outcome the audit API
calls failed), with the error code in the details, including answers produced by an exception
handler after the route ran. A successful webhook redelivery writes ``webhook.redelivered``.
FakeDriver, temp SQLite database and the ASGI client; daemon-free.
"""

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from sqlalchemy import text

from sandfort.api.app import create_app
from sandfort.api.errors import RequestAuditMark
from sandfort.api.middleware.request_id import _AUDIT_MARK, CorrelatedAuditRecorder
from sandfort.api.schemas import toolbox_fs
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.repositories.ports import WebhookEndpointRecord
from sandfort.db.repositories.webhooks import delivery_queries
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType, AuditOutcome, EventType
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.docker.client import DISK_FULL_MESSAGE
from sandfort.drivers.errors import DriverConflict, DriverError
from sandfort.ids import WEBHOOK, new_api_key_id, new_id, new_org_id
from sandfort.services.events import OutboxEventPublisher
from sandfort.webhooks import signing
from sandfort.workers.webhook_dispatcher import BACKOFF_SCHEDULE_S, WebhookDispatcher

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
PUBLIC_IP = "93.184.216.34"
SANDBOXES = "/v1/sandboxes"
AUDIT = "/v1/audit-events"
HOOKS = "/v1/webhooks"
UPLOAD_ACTION = "toolbox.fs.upload"
SCOPES = frozenset(
    {
        Scope.SANDBOXES_READ,
        Scope.SANDBOXES_WRITE,
        Scope.TOOLBOX,
        Scope.AUDIT_READ,
        Scope.WEBHOOKS_WRITE,
    }
)


@pytest.fixture(autouse=True)
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(host: str) -> list[str]:
        return [PUBLIC_IP]

    monkeypatch.setattr("sandfort.webhooks.ssrf.resolve_host", resolve)


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'outcome.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(
        Settings(driver="fake", database_url=url, api_key_pepper=PEPPER, rate_limit_enabled=False)
    )
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


async def seed(app: FastAPI) -> tuple[str, str, str]:
    """An org and a key: ``(org_id, key_id, secret)``."""
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
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
        await uow.api_keys.add(stored)
        await uow.commit()
    return org.id, stored.id, generated.key


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def make_sandbox(client: httpx.AsyncClient, key: str) -> str:
    response = await client.post(SANDBOXES, headers=auth(key), json={})
    assert response.status_code == 201, response.text
    return str(response.json()["data"]["id"])


async def upload(client: httpx.AsyncClient, key: str, sandbox_id: str) -> httpx.Response:
    return await client.put(
        f"{SANDBOXES}/{sandbox_id}/toolbox/fs/upload",
        params={"path": "/tmp/big.bin"},
        content=b"payload",
        headers={**auth(key), "Content-Type": "application/octet-stream"},
    )


async def audit_rows(
    client: httpx.AsyncClient, key: str, request_id: str | None = None
) -> list[dict[str, Any]]:
    """Every audit row of the org, or only the rows the request ``request_id`` wrote."""
    extra = {} if request_id is None else {"request_id": request_id}
    response = await client.get(AUDIT, headers=auth(key), params={"limit": 100, **extra})
    assert response.status_code == 200, response.text
    rows: list[dict[str, Any]] = response.json()["data"]
    return rows


def fail_put_archive(app: FastAPI, error: DriverError) -> None:
    async def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise error

    app.state.driver.put_archive = refuse


async def stored_rows(app: FastAPI) -> list[tuple[str, str]]:
    """``(action, outcome)`` of every committed audit row, read straight from the database."""
    async with app.state.engine.connect() as connection:
        result = await connection.execute(text("SELECT action, outcome FROM audit_events"))
        return [(str(action), str(outcome)) for action, outcome in result.all()]


# --- the refused upload ---------------------------------------------------------------------


async def test_upload_refused_before_the_write_writes_exactly_one_denied_row(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    _, key_id, key = await seed(app)
    sandbox_id = await make_sandbox(client, key)

    response = await client.put(  # the fake driver's ``test -e`` says the file exists
        f"{SANDBOXES}/{sandbox_id}/toolbox/fs/upload",
        params={"path": "/tmp/big.bin", "overwrite": "false"},
        content=b"payload",
        headers={**auth(key), "X-Request-Id": "req-upload-refused"},
    )

    assert response.status_code == 409, response.text
    [row] = await audit_rows(client, key, "req-upload-refused")
    assert row["action"] == UPLOAD_ACTION
    assert row["outcome"] == "denied"
    assert row["actor_id"] == key_id
    assert row["details"]["status"] == 409
    assert row["details"]["error_code"] == "CONFLICT"
    assert row["details"]["reason"] == "already_exists"
    assert "supersedes" not in row["details"]  # no success row came first


async def test_upload_row_is_committed_before_the_archive_reaches_the_driver(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    _, _, key = await seed(app)
    sandbox_id = await make_sandbox(client, key)
    real_put_archive = app.state.driver.put_archive
    seen: list[list[tuple[str, str]]] = []

    async def assert_row_first(ref: str, dest: str, data: AsyncIterator[bytes]) -> None:
        seen.append(await stored_rows(app))
        assert (UPLOAD_ACTION, "success") in seen[-1]
        await real_put_archive(ref, dest, data)

    app.state.driver.put_archive = assert_row_first

    response = await upload(client, key, sandbox_id)

    assert response.status_code == 200, response.text
    assert len(seen) == 1
    uploads = [r for r in await audit_rows(client, key) if r["action"] == UPLOAD_ACTION]
    assert [row["outcome"] for row in uploads] == ["success"]
    assert uploads[0]["details"]["size_bytes"] == len(b"payload")


async def test_failing_upload_audit_write_answers_500_and_never_reaches_the_driver(
    app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, key = await seed(app)
    sandbox_id = await make_sandbox(client, key)
    recorder = app.state.audit_recorder
    real_record = recorder.record
    calls: list[str] = []

    async def record(*args: Any, **kwargs: Any) -> Any:
        if kwargs["action"] == UPLOAD_ACTION and kwargs.get("outcome") == AuditOutcome.SUCCESS:
            raise RuntimeError("audit store unavailable")
        return await real_record(*args, **kwargs)

    async def put_archive(*_args: Any, **_kwargs: Any) -> None:
        calls.append("put_archive")

    monkeypatch.setattr(recorder, "record", record)
    app.state.driver.put_archive = put_archive

    response = await upload(client, key, sandbox_id)

    assert response.status_code == 500, response.text
    assert calls == []


async def test_upload_refused_with_disk_full_is_audited_denied(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    _, key_id, key = await seed(app)
    sandbox_id = await make_sandbox(client, key)
    fail_put_archive(app, DriverConflict(DISK_FULL_MESSAGE))

    response = await upload(client, key, sandbox_id)

    assert response.status_code == 409, response.text
    request_rows = await audit_rows(client, key, response.headers["X-Request-Id"])
    assert all(row["action"] == UPLOAD_ACTION for row in request_rows)  # no request.denied
    # The intent row committed before the driver call, then the refusal of the write itself.
    assert sorted(row["outcome"] for row in request_rows) == ["denied", "success"]
    [row] = [r for r in request_rows if r["outcome"] == "denied"]
    assert row["actor_id"] == key_id
    assert row["target_id"] == sandbox_id
    assert row["details"]["status"] == 409
    assert row["details"]["error_code"] == "CONFLICT"
    assert row["details"]["reason"] == "disk_full"
    assert row["details"]["path"] == "/tmp/big.bin"
    [intent] = [r for r in request_rows if r["outcome"] == "success"]
    assert row["details"]["supersedes"] == intent["id"]  # a reader can pair the two rows
    assert "supersedes" not in intent["details"]


async def test_upload_driver_failure_is_audited_error(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    _, _, key = await seed(app)
    sandbox_id = await make_sandbox(client, key)
    fail_put_archive(app, DriverError("driver went away"))

    response = await upload(client, key, sandbox_id)

    assert response.status_code == 502, response.text
    request_rows = await audit_rows(client, key, response.headers["X-Request-Id"])
    assert all(row["action"] == UPLOAD_ACTION for row in request_rows)  # no request.failed
    assert sorted(row["outcome"] for row in request_rows) == ["error", "success"]
    [failed] = [r for r in request_rows if r["outcome"] == "error"]
    assert failed["details"]["error_code"] == "DRIVER_ERROR"
    assert failed["details"]["status"] == 502
    [intent] = [r for r in request_rows if r["outcome"] == "success"]
    assert failed["details"]["supersedes"] == intent["id"]


# --- the refusal mark follows the commit ----------------------------------------------------


def fail_next_commit_after_denied_upload(
    app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> list[str]:
    """Make the commit that would store the upload's refusal row fail once.

    Returns the list of commits that were failed (one entry per failure).
    """
    recorder = app.state.audit_recorder
    real_record = recorder.record
    armed: list[bool] = []
    failed: list[str] = []

    async def record(*args: Any, **kwargs: Any) -> Any:
        event = await real_record(*args, **kwargs)
        if kwargs["action"] == UPLOAD_ACTION and kwargs.get("outcome") == AuditOutcome.DENIED:
            armed.append(True)
        return event

    real_commit = UnitOfWork.commit

    async def commit(self: UnitOfWork) -> None:
        if armed and not failed:
            failed.append("commit")
            raise RuntimeError("commit failed")
        await real_commit(self)

    monkeypatch.setattr(recorder, "record", record)
    monkeypatch.setattr(UnitOfWork, "commit", commit)
    return failed


async def test_a_refusal_row_whose_commit_fails_leaves_the_handler_to_write_its_own(
    app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, key_id, key = await seed(app)
    sandbox_id = await make_sandbox(client, key)
    failed = fail_next_commit_after_denied_upload(app, monkeypatch)

    response = await client.put(  # the fake driver's ``test -e`` says the file exists
        f"{SANDBOXES}/{sandbox_id}/toolbox/fs/upload",
        params={"path": "/tmp/big.bin", "overwrite": "false"},
        content=b"payload",
        headers={**auth(key), "X-Request-Id": "req-commit-fails"},
    )

    assert response.status_code == 409, response.text
    assert failed == ["commit"]
    [row] = await audit_rows(client, key, "req-commit-fails")
    assert row["action"] == "request.denied"  # the handler's row, not the lost upload row
    assert row["outcome"] == "denied"
    assert row["actor_id"] == key_id
    assert row["details"]["status"] == 409


async def test_the_correlated_recorder_marks_a_refusal_only_after_the_commit(
    app: FastAPI,
) -> None:
    org_id, _, _ = await seed(app)
    mark = RequestAuditMark()
    token = _AUDIT_MARK.set(mark)
    recorder = CorrelatedAuditRecorder(FrozenClock(NOW))
    try:
        async with UnitOfWork(app.state.session_factory) as uow:
            await recorder.record(
                uow,
                org_id=org_id,
                actor_type=ActorType.SYSTEM,
                actor_id=None,
                action="test.refused",
                outcome=AuditOutcome.DENIED,
            )
            assert not mark.refusal_recorded  # recorded, not yet committed
            await uow.rollback()
        assert not mark.refusal_recorded  # a rolled-back row is no row
        async with UnitOfWork(app.state.session_factory) as uow:
            await recorder.record(
                uow,
                org_id=org_id,
                actor_type=ActorType.SYSTEM,
                actor_id=None,
                action="test.refused",
                outcome=AuditOutcome.DENIED,
            )
            await uow.commit()
        assert mark.refusal_recorded
    finally:
        _AUDIT_MARK.reset(token)


async def test_a_success_row_never_marks_the_request(app: FastAPI) -> None:
    org_id, _, _ = await seed(app)
    mark = RequestAuditMark()
    token = _AUDIT_MARK.set(mark)
    recorder = CorrelatedAuditRecorder(FrozenClock(NOW))
    try:
        async with UnitOfWork(app.state.session_factory) as uow:
            await recorder.record(
                uow,
                org_id=org_id,
                actor_type=ActorType.SYSTEM,
                actor_id=None,
                action="test.fine",
            )
            await uow.commit()
        assert not mark.refusal_recorded
    finally:
        _AUDIT_MARK.reset(token)


# --- the handler maps every 4xx to denied and every 5xx to error -----------------------------


async def test_a_4xx_outside_the_old_list_is_audited_denied(
    app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, key = await seed(app)
    sandbox_id = await make_sandbox(client, key)
    monkeypatch.setattr(toolbox_fs, "MAX_UPLOAD_BYTES", 3)

    response = await upload(client, key, sandbox_id)

    assert response.status_code == 413, response.text
    rows = await audit_rows(client, key)
    refusals = [r for r in rows if r["details"].get("status") == 413]
    assert [row["outcome"] for row in refusals] == ["denied"]
    assert refusals[0]["details"]["error_code"] == response.json()["error"]["code"]


async def test_a_5xx_is_audited_error_with_its_code(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    _, _, key = await seed(app)
    sandbox_id = await make_sandbox(client, key)

    async def explode(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("boom")

    app.state.driver.exec = explode
    response = await client.get(
        f"{SANDBOXES}/{sandbox_id}/toolbox/fs/stat",
        params={"path": "/tmp"},
        headers=auth(key),
    )

    assert response.status_code == 500, response.text
    rows = await audit_rows(client, key)
    failed = [r for r in rows if r["details"].get("status") == 500]
    assert failed
    assert {row["outcome"] for row in failed} == {"error"}
    assert failed[0]["details"]["error_code"] == response.json()["error"]["code"]


async def test_a_refusal_no_service_recorded_gets_exactly_one_handler_row(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    _, key_id, key = await seed(app)

    response = await client.post(
        f"{SANDBOXES}/sbx_missing/start", headers={**auth(key), "X-Request-Id": "req-missing"}
    )

    assert response.status_code == 404, response.text
    [row] = await audit_rows(client, key, "req-missing")
    assert row["action"] == "request.denied"
    assert row["outcome"] == "denied"
    assert row["actor_id"] == key_id
    assert row["details"]["status"] == 404


# --- webhook redelivery ---------------------------------------------------------------------


async def failed_delivery(app: FastAPI, org_id: str) -> tuple[WebhookEndpointRecord, str]:
    endpoint = WebhookEndpointRecord(
        id=new_id(WEBHOOK),
        org_id=org_id,
        url="https://hooks.example.com/in",
        secret=signing.generate_secret(),
        enabled=True,
        failure_count=0,
        event_types=[],
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.webhooks.add_endpoint(endpoint)
        payload = {"sandbox_id": "sbx_x", "state": "started"}
        publisher = OutboxEventPublisher(FrozenClock(NOW))
        await publisher.publish(uow, EventType.SANDBOX_STARTED, org_id, payload)
        await uow.commit()
    clock = FrozenClock(NOW)
    transport = httpx.MockTransport(lambda _request: httpx.Response(500))
    worker = WebhookDispatcher(
        lambda: UnitOfWork(app.state.session_factory), clock, interval_s=1, transport=transport
    )
    for delay in (*BACKOFF_SCHEDULE_S, 0):
        await worker.run_once()
        clock.advance(timedelta(seconds=delay + 1))
    async with UnitOfWork(app.state.session_factory) as uow:
        found: Sequence[Any] = await delivery_queries(uow).list_deliveries(
            org_id, endpoint.id, limit=10
        )
    (dead,) = found
    assert dead.state == "failed"
    return endpoint, str(dead.id)


async def test_redeliver_writes_a_webhook_redelivered_event(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    org_id, key_id, key = await seed(app)
    endpoint, delivery_id = await failed_delivery(app, org_id)

    response = await client.post(
        f"{HOOKS}/{endpoint.id}/deliveries/{delivery_id}/redeliver", headers=auth(key)
    )

    assert response.status_code == 200, response.text
    rows = [r for r in await audit_rows(client, key) if r["action"] == "webhook.redelivered"]
    [row] = rows
    assert row["outcome"] == "success"
    assert row["actor_id"] == key_id
    assert row["target_type"] == "webhook_endpoint"
    assert row["target_id"] == endpoint.id
    assert row["details"] == {"delivery_id": delivery_id}


async def test_refused_redeliver_writes_no_redelivered_event(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    org_id, _, key = await seed(app)
    endpoint, _ = await failed_delivery(app, org_id)

    response = await client.post(
        f"{HOOKS}/{endpoint.id}/deliveries/missing/redeliver", headers=auth(key)
    )

    assert response.status_code == 404, response.text
    rows = await audit_rows(client, key)
    assert [r for r in rows if r["action"] == "webhook.redelivered"] == []
