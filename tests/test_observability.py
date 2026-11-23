"""WP 4.5 observability: one trace across API, job and driver; stable metric names; request ids.

FakeDriver, temp SQLite database, httpx AsyncClient over the ASGI app. The lifespan does not
run under ASGITransport, so the job runner is stepped with ``run_once``.
"""

import io
import json
import logging
from collections.abc import AsyncIterator, Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.base import (
    ArchiveStreamDriver,
    ImageBuildDriver,
    ImageRegistryDriver,
    InventoryDriver,
    LogsDriver,
    NamedVolumeDriver,
    PtySessionDriver,
)
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.logging import configure_logging, current_client_ip, current_user_agent
from sandfort.observability import metrics
from sandfort.observability.tracing import (
    ORG_ID_ATTR,
    SANDBOX_ID_ATTR,
    UNMATCHED_ROUTE,
    build_tracer,
    install_span_exporter,
    instrument_driver,
    route_template,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 31, 1, 0, tzinfo=UTC)
PEPPER = "test-pepper"
READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
# Spelled out on purpose: renaming a metric must break this test, not silently follow along.
CATALOG = {
    "sandfort_http_requests_total",
    "sandfort_http_request_seconds",
    "sandfort_sandbox_creates_total",
    "sandfort_jobs_processed_total",
    "sandfort_jobs_queue_depth",
    "sandfort_driver_calls_total",
    "sandfort_driver_call_seconds",
    "sandfort_webhook_deliveries_total",
}


@pytest.fixture(scope="module")
def exporter() -> Iterator[InMemorySpanExporter]:
    installed = InMemorySpanExporter()
    install_span_exporter(installed)
    yield installed
    installed.shutdown()  # the processor stays; spans of later modules are not retained


@pytest.fixture
def spans(exporter: InMemorySpanExporter) -> Iterator[InMemorySpanExporter]:
    exporter.clear()
    yield exporter
    exporter.clear()


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'observability.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(
        driver="fake", database_url=url, api_key_pepper=PEPPER, sandbox_jobs_enabled=True
    )
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
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


@pytest.fixture
def json_log() -> Iterator[io.StringIO]:
    root = logging.getLogger()
    previous_level = root.level
    stream = io.StringIO()
    handler = configure_logging("INFO", stream=stream)
    try:
        yield stream
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)


def only(finished: Sequence[ReadableSpan], name: str) -> ReadableSpan:
    matching = [span for span in finished if span.name == name]
    assert len(matching) == 1, [span.name for span in finished]
    return matching[0]


def exposed_names(text: str) -> set[str]:
    return {line.split()[2] for line in text.splitlines() if line.startswith("# TYPE ")}


def log_lines(stream: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


# --- tracing ----------------------------------------------------------------------


async def test_sandbox_create_is_one_trace_across_api_job_and_driver(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    spans: InMemorySpanExporter,
) -> None:
    headers = {"Authorization": f"Bearer {key}"}
    response = await client.post("/v1/sandboxes", json={"name": "traced"}, headers=headers)
    assert response.status_code == 201, response.text
    sandbox = response.json()["data"]
    assert sandbox["state"] == "pending"  # the job path: the runner finishes the create

    assert await app.state.job_runner.run_once()

    finished = spans.get_finished_spans()
    api = only(finished, "POST /v1/sandboxes")
    job = only(finished, "job sandbox.create")
    create = only(finished, "driver.create")
    start = only(finished, "driver.start")
    assert api.parent is None
    assert api.context is not None and job.context is not None
    trace_id = api.context.trace_id
    assert {span.context.trace_id for span in (job, create, start) if span.context} == {trace_id}
    assert job.parent is not None and job.parent.span_id == api.context.span_id
    assert create.parent is not None and create.parent.span_id == job.context.span_id
    assert start.parent is not None and start.parent.span_id == job.context.span_id
    for span in (job, create, start):
        assert span.attributes is not None
        assert span.attributes[SANDBOX_ID_ATTR] == sandbox["id"]
        assert span.attributes[ORG_ID_ATTR] == org_id
    for span in finished:  # never key material
        assert not any(key in str(value) for value in (span.attributes or {}).values())


async def test_job_path_finishes_the_create_and_audit_rows_carry_the_request_id(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    headers = {"Authorization": f"Bearer {key}", "X-Request-Id": "create-audit-1"}
    created = await client.post("/v1/sandboxes", json={}, headers=headers)
    sandbox_id = created.json()["data"]["id"]

    assert await app.state.job_runner.run_once()

    fetched = await client.get(
        f"/v1/sandboxes/{sandbox_id}", headers={"Authorization": f"Bearer {key}"}
    )
    assert fetched.json()["data"]["state"] == "started"
    async with UnitOfWork(app.state.session_factory) as uow:
        events = await uow.audit.list(org_id)
    assert "create-audit-1" in {event.request_id for event in events}


async def audit_rows_for(app: FastAPI, org_id: str, request_id: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        events = await uow.audit.list(org_id)
    return [event for event in events if event.request_id == request_id]


async def test_audit_rows_carry_the_scope_client_ip_not_a_forged_forwarded_for(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    headers = {
        "Authorization": f"Bearer {key}",
        "X-Request-Id": "audit-origin-1",
        "X-Forwarded-For": "  203.0.113.9 , 10.0.0.2",
        "User-Agent": "agent-under-test/1.0",
    }

    created = await client.post("/v1/sandboxes", json={}, headers=headers)

    assert created.status_code in (200, 201, 202)
    rows = await audit_rows_for(app, org_id, "audit-origin-1")
    assert rows
    assert {(row.ip, row.user_agent) for row in rows} == {("127.0.0.1", "agent-under-test/1.0")}


async def test_audit_ip_is_the_scope_client_without_forwarded_for(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    headers = {"Authorization": f"Bearer {key}", "X-Request-Id": "audit-origin-2"}

    await client.post("/v1/sandboxes", json={}, headers=headers)

    rows = await audit_rows_for(app, org_id, "audit-origin-2")
    assert rows
    assert {row.ip for row in rows} == {"127.0.0.1"}  # httpx ASGITransport's default scope client


async def test_client_origin_is_reset_after_the_request_and_does_not_leak(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    first = {
        "Authorization": f"Bearer {key}",
        "X-Request-Id": "audit-origin-3",
        "X-Forwarded-For": "198.51.100.7",
        "User-Agent": "first-agent",
    }
    second = {
        "Authorization": f"Bearer {key}",
        "X-Request-Id": "audit-origin-4",
        "User-Agent": "second-agent",
    }

    await client.post("/v1/sandboxes", json={}, headers=first)
    assert (current_client_ip(), current_user_agent()) == (None, None)
    await client.post("/v1/sandboxes", json={}, headers=second)
    assert (current_client_ip(), current_user_agent()) == (None, None)

    [leak_check] = await audit_rows_for(app, org_id, "audit-origin-4")
    assert (leak_check.ip, leak_check.user_agent) == ("127.0.0.1", "second-agent")


def test_tracing_disabled_builds_a_non_recording_tracer() -> None:
    tracer = build_tracer(Settings(tracing_enabled=False))
    with tracer.start_as_current_span("ignored") as span:
        assert not span.is_recording()


def test_tracing_settings_are_parsed_and_validated() -> None:
    assert Settings.from_env({}).tracing_exporter == "none"
    assert Settings.from_env({"SANDFORT_TRACING_ENABLED": "off"}).tracing_enabled is False
    assert Settings.from_env({}).sandbox_jobs_enabled is False
    with pytest.raises(ValueError):
        Settings.from_env({"SANDFORT_TRACING_EXPORTER": "carrier-pigeon"})


def test_route_template_folds_path_parameters_back() -> None:
    scope: dict[str, Any] = {
        "endpoint": object(),
        "path": "/v1/sandboxes/sbx_123/start",
        "path_params": {"sandbox_id": "sbx_123"},
    }
    assert route_template(scope) == "/v1/sandboxes/{sandbox_id}/start"
    assert route_template({"path": "/nowhere"}) == UNMATCHED_ROUTE


async def test_instrumented_driver_keeps_capabilities_and_test_hooks(
    spans: InMemorySpanExporter,
) -> None:
    fake = FakeDriver()
    driver = instrument_driver(fake, build_tracer(Settings()))
    for capability in (
        ArchiveStreamDriver,
        ImageBuildDriver,
        ImageRegistryDriver,
        InventoryDriver,
        LogsDriver,
        NamedVolumeDriver,
        PtySessionDriver,
    ):
        assert isinstance(driver, capability), capability.__name__
    assert driver.name == "fake"
    fake.build_timeout = True
    assert cast(Any, driver).build_timeout is True  # instance data reads through

    assert await driver.list_managed() == []

    [span] = spans.get_finished_spans()
    assert span.name == "driver.list_managed"


# --- metrics ----------------------------------------------------------------------


async def test_metrics_expose_exactly_the_catalog_names(client: httpx.AsyncClient) -> None:
    response = await client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert exposed_names(response.text) == CATALOG
    assert metrics.METRIC_NAMES == CATALOG


async def test_metrics_need_no_auth_while_the_api_still_does(client: httpx.AsyncClient) -> None:
    scraped = await client.get("/metrics")
    listing = await client.get("/v1/sandboxes")

    assert scraped.status_code == 200
    assert listing.status_code == 401


async def test_counters_use_route_templates_and_record_jobs_and_driver_calls(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    await client.get("/v1/sandboxes/sbx_notarealid000000000000000")
    await client.post("/v1/sandboxes", json={}, headers={"Authorization": f"Bearer {key}"})
    assert await app.state.job_runner.run_once()

    text = (await client.get("/metrics")).text

    assert 'route="/v1/sandboxes/{sandbox_id}"' in text
    assert "sbx_notarealid" not in text
    assert 'sandfort_jobs_processed_total{kind="sandbox.create",outcome="ok"}' in text
    assert 'sandfort_driver_calls_total{operation="create",outcome="ok"}' in text
    assert 'sandfort_sandbox_creates_total{outcome="ok"}' in text
    assert "sandfort_jobs_queue_depth 0.0" in text


# --- request ids and logs ---------------------------------------------------------


async def test_supplied_request_id_round_trips_to_response_and_json_log(
    client: httpx.AsyncClient, json_log: io.StringIO
) -> None:
    response = await client.get("/healthz", headers={"X-Request-Id": "trace-me-123"})

    assert response.status_code == 200
    assert response.headers["X-Request-Id"] == "trace-me-123"
    lines = log_lines(json_log)
    correlated = [line for line in lines if line.get("request_id") == "trace-me-123"]
    assert correlated, lines
    access = correlated[-1]
    assert {"timestamp", "level", "logger", "message", "request_id"} <= set(access)
    assert access["logger"] == "sandfort.access"
    assert (access["route"], access["status"]) == ("/healthz", 200)
    assert datetime.fromisoformat(access["timestamp"]).tzinfo is not None


async def test_malformed_request_id_is_replaced_and_reaches_the_error_envelope(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/v1/sandboxes", headers={"X-Request-Id": "bad id; drop"})

    minted = response.headers["X-Request-Id"]
    assert minted.startswith("req_") and minted != "bad id; drop"
    assert response.status_code == 401
    assert response.json()["error"]["request_id"] == minted


def test_lines_logged_outside_a_request_carry_no_request_id(json_log: io.StringIO) -> None:
    logging.getLogger("sandfort.test").warning("background", extra={"job": "x"})

    [line] = [line for line in log_lines(json_log) if line["logger"] == "sandfort.test"]
    assert "request_id" not in line
    assert (line["level"], line["message"], line["job"]) == ("WARNING", "background", "x")
