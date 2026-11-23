"""Load profile against a real local daemon (skipped when none is reachable).

Every sandbox runs create, one exec echo round-trip and delete through the ASGI client over
the docker driver on ``alpine:3.20``. Totals and concurrency are tunable from the environment
(``SLO_LOAD_SANDBOXES``, ``SLO_LOAD_CONCURRENCY``); the defaults are a laptop-friendly twenty
sandboxes, five at a time. The p95 objectives below are asserted and one summary line is
printed so the gate log records the numbers.
"""

import asyncio
import contextlib
import os
import time
import uuid
from collections.abc import AsyncIterator, Iterator, Sequence
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
from sandfort.drivers.base import InventoryDriver
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.docker.labels import LABEL_ORG_ID
from sandfort.ids import new_api_key_id, new_org_id

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "alpine:3.20"
PEPPER = "test-pepper"
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
SANDBOXES_ENV = "SLO_LOAD_SANDBOXES"
CONCURRENCY_ENV = "SLO_LOAD_CONCURRENCY"
DEFAULT_SANDBOXES = 20
DEFAULT_CONCURRENCY = 5
PERCENTILE = 95

# Local gates are lenient for daemon variance. The production objective for the exec
# round-trip is a p95 of 150 ms; the 400 ms below only guards against regressions here.
CREATE_P95_LIMIT_S = 2.0
EXEC_P95_LIMIT_S = 0.4
DELETE_P95_LIMIT_S = 2.0


def positive_int_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    value = int(raw)
    if value < 1:
        raise ValueError(f"{name} must be a positive integer, got {raw!r}")
    return value


def percentile(samples: Sequence[float], pct: int) -> float:
    """Nearest-rank percentile of a non-empty sample set."""
    ordered = sorted(samples)
    rank = max(1, -(-pct * len(ordered) // 100))
    return ordered[rank - 1]


@pytest.fixture(scope="module")
def client() -> Any:
    try:
        api_client = make_client()
        api_client.ping()
    except Exception as exc:
        pytest.skip(f"no reachable Docker daemon: {exc}")
    return api_client


@pytest.fixture
def image(client: Any) -> str:
    try:
        client.images.get(IMAGE)
    except docker.errors.ImageNotFound:
        try:
            client.images.pull(IMAGE)
        except Exception as exc:
            pytest.skip(f"cannot pull {IMAGE}: {exc}")
    return IMAGE


@pytest.fixture
async def app(tmp_path: Path, client: Any, image: str) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'load.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="docker", database_url=url, api_key_pepper=PEPPER))
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def http(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
        yield api


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Load", slug=f"load-{uuid.uuid4().hex[:6]}", created_at=NOW)
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
        name="load",
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
def sandbox_ids(client: Any) -> Iterator[list[str]]:
    """Force-removes whatever a failed run left behind on the daemon."""
    created: list[str] = []
    try:
        yield created
    finally:
        for sandbox_id in created:
            with contextlib.suppress(docker.errors.NotFound):
                client.api.remove_container(f"sf-{sandbox_id}", v=True, force=True)


class Samples:
    """Latency samples in seconds, one list per measured operation."""

    def __init__(self) -> None:
        self.create: list[float] = []
        self.exec: list[float] = []
        self.delete: list[float] = []


async def one_sandbox(
    http: httpx.AsyncClient,
    headers: dict[str, str],
    gate: asyncio.Semaphore,
    samples: Samples,
    sandbox_ids: list[str],
) -> None:
    async with gate:
        started = time.perf_counter()
        created = await http.post("/v1/sandboxes", headers=headers, json={"snapshot": IMAGE})
        samples.create.append(time.perf_counter() - started)
        assert created.status_code == 201, created.text
        sandbox_id: str = created.json()["data"]["id"]
        sandbox_ids.append(sandbox_id)
        assert created.json()["data"]["state"] == "started"

        started = time.perf_counter()
        ran = await http.post(
            f"/v1/sandboxes/{sandbox_id}/toolbox/process/execute",
            headers=headers,
            json={"argv": ["echo", "ok"]},
        )
        samples.exec.append(time.perf_counter() - started)
        assert ran.status_code == 200, ran.text
        assert ran.json()["data"]["exit_code"] == 0
        assert ran.json()["data"]["stdout"] == "ok\n"

        started = time.perf_counter()
        deleted = await http.delete(f"/v1/sandboxes/{sandbox_id}", headers=headers)
        samples.delete.append(time.perf_counter() - started)
        assert deleted.status_code == 200, deleted.text


def slo_line(total: int, concurrency: int, samples: Samples) -> str:
    def p95_ms(values: Sequence[float]) -> float:
        return percentile(values, PERCENTILE) * 1000

    return (
        f"SLO load sandboxes={total} concurrency={concurrency} "
        f"create_p95_ms={p95_ms(samples.create):.0f} "
        f"exec_p95_ms={p95_ms(samples.exec):.0f} "
        f"delete_p95_ms={p95_ms(samples.delete):.0f}"
    )


async def test_load_profile_meets_the_objectives_and_leaves_no_containers(
    app: FastAPI, http: httpx.AsyncClient, org_id: str, key: str, sandbox_ids: list[str]
) -> None:
    total = positive_int_from_env(SANDBOXES_ENV, DEFAULT_SANDBOXES)
    concurrency = positive_int_from_env(CONCURRENCY_ENV, DEFAULT_CONCURRENCY)
    headers = {"Authorization": f"Bearer {key}"}
    gate = asyncio.Semaphore(concurrency)
    samples = Samples()

    await asyncio.gather(
        *(one_sandbox(http, headers, gate, samples, sandbox_ids) for _ in range(total))
    )

    print(slo_line(total, concurrency, samples))
    driver = app.state.driver
    assert isinstance(driver, InventoryDriver)
    leftovers = [
        item.provider_id
        for item in await driver.list_instances()
        if item.labels.get(LABEL_ORG_ID) == org_id
    ]
    assert leftovers == []
    assert len(samples.create) == len(samples.exec) == len(samples.delete) == total
    assert percentile(samples.create, PERCENTILE) < CREATE_P95_LIMIT_S
    assert percentile(samples.exec, PERCENTILE) < EXEC_P95_LIMIT_S
    assert percentile(samples.delete, PERCENTILE) < DELETE_P95_LIMIT_S
