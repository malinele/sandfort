"""WP 3.3 declarative image builder over the FakeDriver and the ASGI app (daemon-free).

A temp SQLite database migrated to head. The ``image.build`` job is driven by the app's own
runner (``run_once``), never by a background loop.
"""

import asyncio
import json
from collections.abc import AsyncIterator
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
from sandfort.domain.events import AuditEvent, AuditOutcome
from sandfort.domain.image_spec import ImageFile, ImageSpec
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.snapshot import SnapshotState
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.images.dockerfile import InvalidImageSpec, build_context, compile_dockerfile
from sandfort.images.sdk_dsl_schema import (
    IMAGE_SPEC_SCHEMA,
    SCHEMA_VERSION,
    validate_image_spec_payload,
)
from sandfort.services.image_builds import IMAGE_BUILD, LiveBuilds
from sandfort.workers.handlers import DEFAULT_REGISTRY

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BUILDS = "/v1/images/builds"
SNAPSHOTS = "/v1/snapshots"
FULL_ACCESS = frozenset({Scope.SNAPSHOTS_READ, Scope.SNAPSHOTS_WRITE})

GOLDEN_DOCKERFILE = (
    "FROM python:3.12-slim\n"
    'ENV A_VAR="one"\n'
    'ENV B_VAR="two"\n'
    "RUN apt-get update && apt-get install -y --no-install-recommends curl git"
    " && rm -rf /var/lib/apt/lists/*\n"
    "RUN pip install --no-cache-dir 'flask==3.0.0' 'requests>=2.31'\n"
    "COPY file-0000 /app/a.txt\n"
    "COPY file-0001 /app/b.txt\n"
    "WORKDIR /app\n"
)


def representative_spec() -> ImageSpec:
    return ImageSpec(
        base_image="python:3.12-slim",
        env={"A_VAR": "one", "B_VAR": "two"},
        apt_packages=["curl", "git"],
        pip_packages=["flask==3.0.0", "requests>=2.31"],
        workdir="/app",
        files=[
            ImageFile(destination="/app/a.txt", content="alpha\n"),
            ImageFile(destination="/app/b.txt", content="beta\n"),
        ],
    )


def reordered_spec() -> ImageSpec:
    return ImageSpec(
        base_image="python:3.12-slim",
        env={"B_VAR": "two", "A_VAR": "one"},
        apt_packages=["git", "curl"],
        pip_packages=["requests>=2.31", "flask==3.0.0"],
        workdir="/app",
        files=[
            ImageFile(destination="/app/b.txt", content="beta\n"),
            ImageFile(destination="/app/a.txt", content="alpha\n"),
        ],
    )


def wire_spec(**overrides: Any) -> dict[str, Any]:
    return {
        "base_image": "alpine:3.20",
        "files": [{"destination": "/opt/hello.txt", "content": "hello\n"}],
        **overrides,
    }


# --- dockerfile compiler -------------------------------------------------------------


def test_compiles_the_exact_golden_dockerfile() -> None:
    assert compile_dockerfile(representative_spec()) == GOLDEN_DOCKERFILE


def test_reordered_but_equal_specs_compile_byte_identically() -> None:
    first, second = representative_spec(), reordered_spec()

    assert first.spec_hash == second.spec_hash
    assert compile_dockerfile(first).encode() == compile_dockerfile(second).encode()
    assert build_context(first) == build_context(second)


def test_context_holds_the_dockerfile_and_one_deterministic_file_per_entry() -> None:
    context = build_context(representative_spec())

    assert sorted(context) == ["Dockerfile", "file-0000", "file-0001"]
    assert context["file-0000"] == b"alpha\n"
    assert context["file-0001"] == b"beta\n"
    assert context["Dockerfile"].decode() == GOLDEN_DOCKERFILE


def test_env_values_are_quoted_and_escaped() -> None:
    spec = ImageSpec(base_image="alpine:3.20", env={"MSG": 'say "hi" $HOME \\ok'})

    assert 'ENV MSG="say \\"hi\\" \\$HOME \\\\ok"\n' in compile_dockerfile(spec)


def test_an_empty_spec_is_just_the_base_image() -> None:
    assert compile_dockerfile(ImageSpec(base_image="alpine:3.20")) == "FROM alpine:3.20\n"


@pytest.mark.parametrize(
    "change",
    [
        {"apt_packages": ["curl; rm -rf /"]},
        {"apt_packages": ["-oAPT::Foo=bar"]},
        {"pip_packages": ["requests && id"]},
        {"pip_packages": ["pkg>=1.0; touch x"]},
        {"pip_packages": ["pkg==$(id)"]},
        {"pip_packages": ["pkg`id`"]},
        {"env": {"A": "one\nRUN id"}},
        {"env": {"A": "one\rtwo"}},
        {"env": {"BAD KEY": "x"}},
        {"env": {"A\nRUN id": "x"}},
        {"base_image": "alpine\nRUN id"},
        {"workdir": "relative/dir"},
        {"workdir": "/app\nRUN id"},
        {"files": [ImageFile(destination="etc/passwd", content="x")]},
        {"files": [ImageFile(destination="/etc/../passwd", content="x")]},
        {"files": [ImageFile(destination="/app/dir/", content="x")]},
        {"files": [ImageFile(destination="/app/x\nRUN id", content="x")]},
    ],
)
def test_unsafe_values_raise_a_typed_validation_error(change: dict[str, Any]) -> None:
    spec = ImageSpec(**{"base_image": "alpine:3.20", **change})

    with pytest.raises(InvalidImageSpec) as raised:
        compile_dockerfile(spec)

    assert raised.value.status == 422


@pytest.mark.parametrize("pin", ["requests", "requests==2.31.0", "a_b-c.d~=1.2", "x<3", "x!=1.0"])
def test_pip_pins_with_comparison_operators_are_accepted(pin: str) -> None:
    spec = ImageSpec(base_image="alpine:3.20", pip_packages=[pin])

    assert f"'{pin}'" in compile_dockerfile(spec)


# --- wire schema ---------------------------------------------------------------------


def test_schema_properties_match_the_domain_spec() -> None:
    assert set(IMAGE_SPEC_SCHEMA["properties"]) == set(ImageSpec.model_fields) | {"schema_version"}
    assert IMAGE_SPEC_SCHEMA["properties"]["schema_version"] == {"const": SCHEMA_VERSION}


def test_a_valid_payload_becomes_the_domain_spec() -> None:
    spec = validate_image_spec_payload({"schema_version": SCHEMA_VERSION, **wire_spec()})

    assert spec == ImageSpec(
        base_image="alpine:3.20", files=[ImageFile(destination="/opt/hello.txt", content="hello\n")]
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"base_image": ""},
        {"base_image": "alpine", "surprise": 1},
        {"base_image": "alpine", "apt_packages": "curl"},
        {"base_image": "alpine", "env": {"A": 1}},
        {"base_image": "alpine", "files": [{"destination": "/a"}]},
        {"base_image": "alpine", "schema_version": "999"},
    ],
)
def test_a_payload_off_the_schema_is_rejected(payload: dict[str, Any]) -> None:
    with pytest.raises(InvalidImageSpec):
        validate_image_spec_payload(payload)


# --- live build registry ---------------------------------------------------------------


async def test_late_subscribers_replay_from_the_start_and_end_when_finished() -> None:
    builds = LiveBuilds()
    live = builds.open("snap_1")
    await live.add("one")
    await live.add("two")
    await live.finish(SnapshotState.READY)

    assert [line async for line in live.follow()] == ["one", "two"]
    assert [line async for line in live.follow()] == ["one", "two"]


async def test_the_registry_keeps_a_bounded_number_of_finished_builds() -> None:
    builds = LiveBuilds(max_retained=2)
    for name in ("a", "b", "c"):
        await builds.open(name).finish(SnapshotState.READY)

    builds.open("d")

    assert builds.get("a") is None
    assert builds.get("b") is not None
    assert builds.get("d") is not None


def test_the_image_build_handler_is_registered() -> None:
    assert IMAGE_BUILD in DEFAULT_REGISTRY.kinds()


# --- api fixtures ----------------------------------------------------------------------


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'image-builds.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
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
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


async def add_org(app: FastAPI, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def seed_key(app: FastAPI, org_id: str) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=FULL_ACCESS,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "acme")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await seed_key(app, org_id)


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def post_build(
    client: httpx.AsyncClient, key: str, spec: dict[str, Any], *, status: int
) -> dict[str, Any]:
    response = await client.post(BUILDS, headers=auth(key), json={"spec": spec})
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


async def fetch_snapshot(client: httpx.AsyncClient, key: str, snapshot_id: str) -> dict[str, Any]:
    response = await client.get(f"{SNAPSHOTS}/{snapshot_id}", headers=auth(key))
    assert response.status_code == 200, response.text
    data: dict[str, Any] = response.json()["data"]
    return data


async def run_jobs(app: FastAPI) -> int:
    processed = 0
    while await app.state.job_runner.run_once():
        processed += 1
    return processed


async def audit_rows(app: FastAPI, org_id: str) -> list[AuditEvent]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, limit=200))


def parse_events(body: str) -> list[tuple[str, dict[str, Any]]]:
    events: list[tuple[str, dict[str, Any]]] = []
    for frame in body.strip().split("\n\n"):
        fields = dict(line.split(": ", 1) for line in frame.splitlines() if ": " in line)
        if "event" in fields:
            events.append((fields["event"], json.loads(fields["data"])))
    return events


# --- validation through the api ----------------------------------------------------------


@pytest.mark.parametrize(
    "spec",
    [
        wire_spec(apt_packages=["curl; rm -rf /"]),
        wire_spec(pip_packages=["requests && id"]),
        wire_spec(env={"A": "one\nRUN id"}),
        wire_spec(files=[{"destination": "relative/path", "content": "x"}]),
        wire_spec(unknown_field=True),
    ],
)
async def test_unsafe_or_malformed_specs_answer_422(
    client: httpx.AsyncClient, driver: FakeDriver, key: str, spec: dict[str, Any]
) -> None:
    body = await post_build(client, key, spec, status=422)

    assert body["success"] is False
    assert body["error"]["code"] in {"UNPROCESSABLE", "VALIDATION_ERROR"}
    assert driver.build_contexts == []


# --- build, cache, failure ---------------------------------------------------------------


async def test_building_compiles_runs_the_job_and_marks_the_row_ready(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, key: str
) -> None:
    body = await post_build(client, key, wire_spec(), status=202)
    pending = body["data"]

    assert pending["state"] == "pending"
    assert pending["reused"] is False
    assert len(pending["spec_hash"]) == 64
    assert driver.build_contexts == []

    assert await run_jobs(app) == 1

    ready = await fetch_snapshot(client, key, pending["id"])
    assert ready["state"] == "ready"
    assert ready["digest"].startswith("sha256:")
    assert ready["layer_count"] == 1
    assert len(driver.build_contexts) == 1
    context = driver.build_contexts[0]
    assert context["Dockerfile"].decode() == "FROM alpine:3.20\nCOPY file-0000 /opt/hello.txt\n"
    assert context["file-0000"] == b"hello\n"


async def test_two_identical_requests_build_once_and_reuse_the_ready_snapshot(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, key: str, org_id: str
) -> None:
    first = (await post_build(client, key, wire_spec(), status=202))["data"]
    await run_jobs(app)

    reordered = {"files": wire_spec()["files"], "base_image": "alpine:3.20"}
    second = (await post_build(client, key, reordered, status=200))["data"]

    assert second["id"] == first["id"]
    assert second["state"] == "ready"
    assert second["reused"] is True
    assert len(driver.build_contexts) == 1
    assert await run_jobs(app) == 0
    actions = [row.action for row in await audit_rows(app, org_id)]
    assert actions.count("image.build.request") == 2
    assert actions.count("image.build.complete") == 1


async def test_a_different_spec_is_a_different_build(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, key: str
) -> None:
    await post_build(client, key, wire_spec(), status=202)
    await run_jobs(app)

    other = await post_build(client, key, wire_spec(env={"A": "b"}), status=202)
    await run_jobs(app)

    assert other["data"]["reused"] is False
    assert len(driver.build_contexts) == 2


async def test_a_build_that_times_out_is_an_error_row_with_a_timeout_reason(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, key: str, org_id: str
) -> None:
    driver.build_timeout = True
    pending = (await post_build(client, key, wire_spec(), status=202))["data"]

    await run_jobs(app)

    failed = await fetch_snapshot(client, key, pending["id"])
    assert failed["state"] == "error"
    complete = [r for r in await audit_rows(app, org_id) if r.action == "image.build.complete"]
    assert len(complete) == 1
    assert complete[0].outcome is AuditOutcome.ERROR
    assert "timed out" in complete[0].details["reason"]


async def test_a_failed_build_is_not_reused_by_the_cache(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, key: str
) -> None:
    driver.build_timeout = True
    await post_build(client, key, wire_spec(), status=202)
    await run_jobs(app)

    driver.build_timeout = False
    retry = (await post_build(client, key, wire_spec(), status=202))["data"]
    await run_jobs(app)

    assert (await fetch_snapshot(client, key, retry["id"]))["state"] == "ready"


async def test_audit_never_carries_log_or_file_content(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str
) -> None:
    await post_build(client, key, wire_spec(), status=202)
    await run_jobs(app)

    rows = [r for r in await audit_rows(app, org_id) if r.action.startswith("image.build")]

    assert len(rows) == 2
    for row in rows:
        text = json.dumps(row.details)
        assert "COPY" not in text
        assert "hello" not in text


# --- log streaming -------------------------------------------------------------------------


async def test_build_logs_stream_the_lines_then_a_final_state_event(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    pending = (await post_build(client, key, wire_spec(), status=202))["data"]
    await run_jobs(app)

    response = await client.get(f"{BUILDS}/{pending['id']}/logs", headers=auth(key))

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    events = parse_events(response.text)
    lines = [data["line"] for name, data in events if name == "log"]
    assert lines[0].startswith("COPY Dockerfile")
    assert lines[-1] == f"Successfully tagged {pending['image_ref']}"
    name, final = events[-1]
    assert name == "state"
    assert final["state"] == "ready"
    assert final["snapshot_id"] == pending["id"]
    assert final["reason"] is None


async def test_a_subscriber_that_arrives_before_the_build_runs_follows_it_live(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    pending = (await post_build(client, key, wire_spec(), status=202))["data"]
    follower = asyncio.ensure_future(
        client.get(f"{BUILDS}/{pending['id']}/logs", headers=auth(key))
    )
    await asyncio.sleep(0.05)
    assert not follower.done()

    await run_jobs(app)
    response = await asyncio.wait_for(follower, timeout=10)

    events = parse_events(response.text)
    assert [name for name, _ in events].count("log") == 3
    assert events[-1][1]["state"] == "ready"


async def test_a_failed_build_ends_the_stream_with_the_error_state_and_reason(
    app: FastAPI, client: httpx.AsyncClient, driver: FakeDriver, key: str
) -> None:
    driver.build_timeout = True
    pending = (await post_build(client, key, wire_spec(), status=202))["data"]
    await run_jobs(app)

    response = await client.get(f"{BUILDS}/{pending['id']}/logs", headers=auth(key))

    name, final = parse_events(response.text)[-1]
    assert name == "state"
    assert final["state"] == "error"
    assert "timed out" in final["reason"]


# --- auth and tenancy ----------------------------------------------------------------------


async def test_unauthenticated_requests_answer_401(
    client: httpx.AsyncClient, driver: FakeDriver
) -> None:
    posted = await client.post(BUILDS, json={"spec": wire_spec()})
    streamed = await client.get(f"{BUILDS}/snap_x/logs")

    assert posted.status_code == 401
    assert streamed.status_code == 401
    assert driver.build_contexts == []


async def test_another_orgs_build_logs_answer_404(
    app: FastAPI, client: httpx.AsyncClient, key: str
) -> None:
    pending = (await post_build(client, key, wire_spec(), status=202))["data"]
    foreign_key = await seed_key(app, await add_org(app, "other"))

    foreign = await client.get(f"{BUILDS}/{pending['id']}/logs", headers=auth(foreign_key))
    missing = await client.get(f"{BUILDS}/snap_missing/logs", headers=auth(key))

    assert foreign.status_code == 404
    assert foreign.json()["error"]["code"] == "NOT_FOUND"
    assert missing.status_code == 404
