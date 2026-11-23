"""Round-30 message and hygiene fixes, tested without Docker.

Covers the stop message, the ``no_container`` message helper, the kernel's ``linecache`` entry
(run with a real ``python3`` subprocess), the bad-image-reference message, the export route
description and the ``X-Content-Type-Options`` header on JSON and streaming routes.
"""

import json
import subprocess
import sys
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.routes import snapshots as snapshot_routes
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.docker import client as docker_client
from sandfort.drivers.docker.exec import SANDBOX_DIED_MESSAGE
from sandfort.drivers.docker.images import pull_image
from sandfort.drivers.errors import DriverError
from sandfort.errors import (
    NO_CONTAINER,
    no_container_conflict,
    no_container_message,
)
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.toolbox import code_contexts

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
NOSNIFF = "nosniff"
HEADER = "x-content-type-options"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
KERNEL_TIMEOUT_S = 30


# --- 1) stop message -------------------------------------------------------------------


def test_the_stop_message_names_both_causes_without_blaming_one() -> None:
    text = SANDBOX_DIED_MESSAGE.decode()

    assert text == (
        "the sandbox stopped while running this command "
        "(a resource limit was hit or its main process ended); start it again"
    )
    assert "exceeded its memory" not in text


# --- 2) no_container message helper ------------------------------------------------------


@pytest.mark.parametrize("state", ["destroyed", "destroying"])
def test_a_deleted_sandbox_is_told_to_create_a_new_one(state: str) -> None:
    error = no_container_conflict(state)

    assert str(error) == "the sandbox was deleted; create a new one"
    assert error.message == "the sandbox was deleted; create a new one"
    assert (error.status, error.code, error.reason) == (409, "CONFLICT", NO_CONTAINER)
    assert error.details == {"reason": NO_CONTAINER, "state": state}


def test_a_stopped_sandbox_is_told_to_start_it_first() -> None:
    error = no_container_conflict("stopped")

    assert error.message == "sandbox has no container instance; start it first"
    assert (error.status, error.code, error.reason) == (409, "CONFLICT", NO_CONTAINER)
    assert error.details == {"reason": NO_CONTAINER, "state": "stopped"}


@pytest.mark.parametrize("state", ["creating", "started", "error"])
def test_any_other_state_keeps_the_plain_message(state: str) -> None:
    assert no_container_message(state) == "sandbox has no container instance"
    assert no_container_conflict(state).details == {"reason": NO_CONTAINER, "state": state}


def test_an_unknown_state_has_the_plain_message_and_no_state_detail() -> None:
    error = no_container_conflict()

    assert error.message == "sandbox has no container instance"
    assert error.details == {"reason": NO_CONTAINER}


# --- 3) kernel linecache -----------------------------------------------------------------

KERNEL_PROBE = r"""
import contextlib, io, json, sys
source = sys.stdin.read()
ns = {"__name__": "kernel_under_test", "__file__": "kernel.py"}
exec(compile(source, "kernel.py", "exec"), ns)
cells = ns["new_main"]()
stderrs = []
for code in json.loads(sys.argv[1]):
    buffer = io.StringIO()
    with contextlib.redirect_stderr(buffer):
        try:
            ns["execute"](cells, code)
        except BaseException as exc:
            ns["report"](exc)
    stderrs.append(buffer.getvalue())
print(json.dumps(stderrs))
"""


def run_cells_in_kernel(*cells: str) -> list[str]:
    """The stderr each cell produced when run through the kernel's own ``execute``/``report``."""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", KERNEL_PROBE, json.dumps(cells)],
        input=code_contexts.KERNEL_SOURCE.encode(),
        capture_output=True,
        timeout=KERNEL_TIMEOUT_S,
        check=True,
    )
    stderrs: list[str] = json.loads(completed.stdout)
    return stderrs


def test_a_failing_cell_traceback_shows_the_source_line() -> None:
    (stderr,) = run_cells_in_kernel("x = 1\nprint(x / 0)")

    assert 'File "<cell-1>", line 2' in stderr
    assert "print(x / 0)" in stderr
    assert "ZeroDivisionError" in stderr


def test_each_run_replaces_the_cell_source_entry() -> None:
    first, second = run_cells_in_kernel("x = 1\nprint(x / 0)", "y = 2\nraise ValueError(y)")

    assert "print(x / 0)" in first
    assert "raise ValueError(y)" in second
    assert "print(x / 0)" not in second


# --- 4) bad image reference message --------------------------------------------------------

errors = pytest.importorskip("docker.errors")
DNS_FAILURE_TEXT = (
    'failed to resolve reference "docker.io/library/python:3.12-slm": failed to do request: '
    'Head "https://registry-1.docker.io/v2/library/python/manifests/3.12-slm": dial tcp: '
    "lookup registry-1.docker.io on 127.0.0.53:53: server misbehaving"
)


async def test_a_registry_that_did_not_answer_names_both_possible_causes() -> None:
    docker_client.configure_thread_limit()  # an earlier test may have closed the shared lanes
    ref = "python:3.12-slm"
    response = SimpleNamespace(status_code=500, reason="x", url="http+docker://localhost/v1.43")

    def pull(*_: Any, **__: Any) -> None:
        raise errors.APIError("500 Server Error", response=response, explanation=DNS_FAILURE_TEXT)

    client = SimpleNamespace(images=SimpleNamespace(pull=pull))

    with pytest.raises(DriverError) as caught:
        await pull_image(client, ref)

    assert str(caught.value) == (
        f"could not pull {ref}: the registry did not answer (a transient network problem, or a "
        "registry host that does not exist); check the name, then try again"
    )
    assert "127.0.0.53" not in str(caught.value)


# --- 5) export description -----------------------------------------------------------------


def test_the_export_description_says_the_tar_names_no_repository() -> None:
    description = " ".join((snapshot_routes.export_snapshot.__doc__ or "").split())

    assert "names no repository" in description
    assert "``docker load`` prints the image id, so tag it yourself" in description
    assert "no sandbox env values, labels or secrets" in description
    assert "under the reference the snapshot carries" not in description


# --- 6) nosniff header -------------------------------------------------------------------


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'headers.db'}"
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


async def add_key(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=FULL_ACCESS,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def test_a_json_response_carries_nosniff(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers[HEADER] == NOSNIFF


async def test_an_error_response_carries_nosniff(client: httpx.AsyncClient) -> None:
    response = await client.get("/v1/sandboxes")

    assert response.status_code == 401
    assert response.headers[HEADER] == NOSNIFF


async def test_a_streaming_response_carries_nosniff(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    auth = {"Authorization": f"Bearer {await add_key(app)}"}
    created = await client.post("/v1/sandboxes", headers=auth, json={})
    assert created.status_code == 201, created.text
    sandbox_id = created.json()["data"]["id"]

    response = await client.get(f"/v1/sandboxes/{sandbox_id}/logs", headers=auth)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers[HEADER] == NOSNIFF
