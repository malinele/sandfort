"""Round 62: out-of-memory kills read ``oom_killed`` where the driver can see them.

Service level (FakeDriver, temp SQLite, httpx over ASGI):

* a container the runtime flags as OOM-killed: the exec answers ``stop_reason`` ``oom_killed``
  and the sandbox settles ``stopped`` with ``stop_cause`` ``oom_killed``;
* the driver reports an ``oom_kill`` counter increase for the exec: ``oom_killed`` on the exec
  result and the sandbox keeps running;
* no flag, no counter: the answers are the ones of earlier rounds (``killed``, ``sandbox_stopped``
  with ``container_exited``).

Docker driver level (fake docker client, a fake ``/proc`` and cgroup tree): the container tier
reads the counter and the daemon's verdict; gVisor and Kata (no host-visible signal) and an
unreadable counter keep the earlier answer.
"""

import socket
from collections.abc import AsyncIterator, Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api import dead_sandbox
from sandfort.api.app import create_app
from sandfort.api.routes.toolbox import process as process_routes
from sandfort.api.schemas.toolbox_process import (
    STOP_REASON_OOM_KILLED,
    derive_stop_reason,
    execute_response,
)
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import STOP_CAUSE_CONTAINER_EXITED, STOP_CAUSE_OOM_KILLED
from sandfort.drivers.base import ExecRequest, ExecResult, OomObservableDriver
from sandfort.drivers.docker import exec as exec_module
from sandfort.drivers.docker import oom
from sandfort.drivers.docker.exec import exec_run
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
STRESS = {"command": "stress"}
CODE = {"language": "python", "code": "x = bytearray(10**12)"}
ROUTES = [("execute", STRESS), ("code-run", CODE)]


# --- service-level fixtures ---------------------------------------------------------


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'oom.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)
    application = create_app(settings)
    application.include_router(process_routes.router)
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


@pytest.fixture(autouse=True)
def fast_settle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dead_sandbox, "SETTLE_TIMEOUT_S", 0.15)
    monkeypatch.setattr(dead_sandbox, "SETTLE_POLL_INTERVAL_S", 0.02)


@pytest.fixture
async def key(app: FastAPI) -> str:
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


async def send(
    client: httpx.AsyncClient, method: str, path: str, key: str, *, status: int, **kwargs: Any
) -> dict[str, Any]:
    response = await client.request(
        method, path, headers={"Authorization": f"Bearer {key}"}, **kwargs
    )
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


async def create_sandbox(client: httpx.AsyncClient, key: str) -> str:
    body = await send(client, "POST", BASE, key, status=201, json={})
    sandbox_id: str = body["data"]["id"]
    return sandbox_id


async def run(
    client: httpx.AsyncClient, key: str, sandbox_id: str, route: str, payload: dict[str, Any]
) -> dict[str, Any]:
    path = f"{BASE}/{sandbox_id}/toolbox/process/{route}"
    body = await send(client, "POST", path, key, status=200, json=payload)
    data: dict[str, Any] = body["data"]
    return data


async def sandbox(client: httpx.AsyncClient, key: str, sandbox_id: str) -> dict[str, Any]:
    body = await send(client, "GET", f"{BASE}/{sandbox_id}", key, status=200)
    data: dict[str, Any] = body["data"]
    return data


def stressed(result: ExecResult, before: Any = lambda: None) -> Any:
    """An exec handler: ``stress`` and python run ``before``, then end as ``result``."""

    def handler(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        if request.argv[-1] != "stress" and request.argv[0] != "python3":
            return ExecResult(exit_code=0)
        before()
        return result

    return handler


# --- an OOM-killed container ----------------------------------------------------------


@pytest.mark.parametrize(("route", "payload"), ROUTES)
@pytest.mark.parametrize("flagged", [False, True], ids=["bare-kill", "death-flag"])
async def test_an_oom_killed_container_stops_the_sandbox_with_cause_oom_killed(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    route: str,
    payload: dict[str, Any],
    flagged: bool,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    [instance] = await driver.list_managed()
    driver.exec_handler = stressed(
        ExecResult(exit_code=137, sandbox_stopped=flagged),
        lambda: driver.kill_instance(instance.ref, vanish=False, oom=True),
    )

    data = await run(client, key, sandbox_id, route, payload)

    assert (data["exit_code"], data["sandbox_stopped"]) == (137, True)
    assert data["stop_reason"] == STOP_REASON_OOM_KILLED
    assert "ran out of memory" in data["stderr"]
    row = await sandbox(client, key, sandbox_id)
    assert (row["state"], row["stop_cause"]) == ("stopped", STOP_CAUSE_OOM_KILLED)


async def test_an_exited_container_without_an_oom_verdict_keeps_container_exited(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    [instance] = await driver.list_managed()
    driver.exec_handler = stressed(
        ExecResult(exit_code=137, sandbox_stopped=True),
        lambda: driver.kill_instance(instance.ref, vanish=False),
    )

    data = await run(client, key, sandbox_id, "execute", STRESS)

    assert data["stop_reason"] == "sandbox_stopped"
    row = await sandbox(client, key, sandbox_id)
    assert (row["state"], row["stop_cause"]) == ("stopped", STOP_CAUSE_CONTAINER_EXITED)


async def test_the_oom_verdict_is_cleared_when_the_sandbox_starts_again(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    [instance] = await driver.list_managed()
    driver.exec_handler = stressed(
        ExecResult(exit_code=137),
        lambda: driver.kill_instance(instance.ref, vanish=False, oom=True),
    )
    await run(client, key, sandbox_id, "execute", STRESS)

    await send(client, "POST", f"{BASE}/{sandbox_id}/start", key, status=200)

    assert await driver.container_oom_killed(instance.ref) is False
    assert (await sandbox(client, key, sandbox_id))["stop_cause"] is None


# --- the kernel killed a process, the sandbox lives -----------------------------------


@pytest.mark.parametrize(("route", "payload"), ROUTES)
async def test_an_oom_kill_counter_increase_reports_oom_killed_and_the_sandbox_keeps_running(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    route: str,
    payload: dict[str, Any],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    driver.exec_handler = stressed(ExecResult(exit_code=137, oom_killed=True))

    data = await run(client, key, sandbox_id, route, payload)

    assert (data["exit_code"], data["sandbox_stopped"]) == (137, False)
    assert data["stop_reason"] == STOP_REASON_OOM_KILLED
    assert "ran out of memory" in data["stderr"]
    row = await sandbox(client, key, sandbox_id)
    assert (row["state"], row["stop_cause"]) == ("started", None)


# --- not observable: unchanged ------------------------------------------------------------


@pytest.mark.parametrize(("route", "payload"), ROUTES)
async def test_a_kill_without_a_counter_or_verdict_stays_killed(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    route: str,
    payload: dict[str, Any],
) -> None:
    sandbox_id = await create_sandbox(client, key)
    driver.exec_handler = stressed(ExecResult(exit_code=137))

    data = await run(client, key, sandbox_id, route, payload)

    assert data["stop_reason"] == "killed"
    assert "ran out of memory" not in data["stderr"]
    assert (await sandbox(client, key, sandbox_id))["state"] == "started"


def test_the_stop_reason_is_never_derived_from_the_flags_alone() -> None:
    assert (
        derive_stop_reason(exit_code=137, timed_out=False, truncated=False, sandbox_stopped=False)
        == "killed"
    )


def test_oom_killed_does_not_override_a_timeout_or_a_normal_exit() -> None:
    timed_out = execute_response(
        ExecResult(exit_code=124, timed_out=True), stop_reason=STOP_REASON_OOM_KILLED
    )
    normal = execute_response(ExecResult(exit_code=0), stop_reason=STOP_REASON_OOM_KILLED)

    assert (timed_out.stop_reason, normal.stop_reason) == ("timeout", None)


# --- Docker driver: counter and verdict ---------------------------------------------------

REF = "ab" * 32  # a container id, as the daemon reports it
EXIT_KILLED = 137


class Api:
    """A docker-py ``api`` stub: one container, a socket that ends at once, a scripted exit."""

    def __init__(
        self,
        sock: socket.socket,
        *,
        runtime: str = "runc",
        state: dict[str, Any] | None = None,
        on_exit: Any = lambda: None,
    ) -> None:
        self.sock = sock
        self.attrs = {
            "HostConfig": {"Runtime": runtime},
            "State": state or {"Running": True},
        }
        self.on_exit = on_exit
        self.created: list[dict[str, Any]] = []

    def inspect_container(self, ref: str) -> dict[str, Any]:
        return self.attrs

    def exec_create(self, container: str, **kwargs: Any) -> dict[str, str]:
        self.created.append(kwargs)
        return {"Id": f"exec{len(self.created)}"}

    def exec_start(self, exec_id: str, **kwargs: Any) -> Any:
        return self.sock if kwargs.get("socket") else b""

    def exec_inspect(self, exec_id: str) -> dict[str, Any]:
        self.on_exit()
        return {"Running": False, "ExitCode": EXIT_KILLED}


class Client:
    def __init__(self, api: Api) -> None:
        self.api = api


@pytest.fixture
def pair() -> Iterator[socket.socket]:
    ours, theirs = socket.socketpair()
    theirs.close()
    try:
        yield ours
    finally:
        ours.close()


@pytest.fixture
def cgroups(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake cgroup v2 tree (systemd layout); returns the container's ``memory.events``."""
    root = tmp_path / "cgroup"
    events = root / "system.slice" / f"docker-{REF}.scope" / "memory.events"
    events.parent.mkdir(parents=True)
    set_oom_kill(events, 0)
    monkeypatch.setattr(oom, "CGROUP_ROOT", root)
    return events


def set_oom_kill(events: Path, count: int) -> None:
    events.write_text(f"low 0\nhigh 0\nmax 3\noom {count}\noom_kill {count}\n")


async def exec_killed(api: Api) -> ExecResult:
    return await exec_run(Client(api), REF, ExecRequest(argv=["x"], timeout_s=5))


async def test_the_container_tier_reports_oom_when_the_counter_rises_during_the_exec(
    pair: socket.socket, cgroups: Path
) -> None:
    api = Api(pair, on_exit=lambda: set_oom_kill(cgroups, 1))

    result = await exec_killed(api)

    assert (result.exit_code, result.oom_killed, result.sandbox_stopped) == (137, True, False)


async def test_a_counter_that_did_not_move_leaves_the_kill_unexplained(
    pair: socket.socket, cgroups: Path
) -> None:
    result = await exec_killed(Api(pair))

    assert (result.exit_code, result.oom_killed) == (137, False)


async def test_the_counter_is_only_consulted_for_a_sigkill_exit(
    pair: socket.socket, cgroups: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = Api(pair, on_exit=lambda: set_oom_kill(cgroups, 1))
    monkeypatch.setattr(exec_module, "KILLED_EXIT_CODE", 1)  # the exec ends 137, not "killed"

    assert (await exec_killed(api)).oom_killed is False


@pytest.mark.parametrize("runtime", ["runsc", "kata-qemu"])
async def test_gvisor_and_kata_tiers_keep_the_plain_kill(
    pair: socket.socket, cgroups: Path, runtime: str
) -> None:
    api = Api(pair, runtime=runtime, on_exit=lambda: set_oom_kill(cgroups, 1))

    result = await exec_killed(api)

    assert (result.exit_code, result.oom_killed) == (137, False)


async def test_an_unreadable_counter_keeps_the_plain_kill(
    pair: socket.socket, cgroups: Path
) -> None:
    api = Api(pair, on_exit=lambda: set_oom_kill(cgroups, 1))
    cgroups.unlink()  # the host cgroup tree is not visible to the server

    assert (await exec_killed(api)).oom_killed is False


def test_the_counter_parser_and_cgroup_lookup(
    cgroups: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert oom.parse_oom_kill("oom 2\noom_kill 5\n") == 5
    assert oom.parse_oom_kill("oom 2\n") is None
    assert oom.parse_oom_kill("oom_kill x\n") is None
    assert oom.memory_events_file(REF) == cgroups
    assert oom.memory_events_file("ref") is None  # not a container id
    cgroupfs = tmp_path / "cgroupfs"
    (cgroupfs / "docker" / REF).mkdir(parents=True)
    (cgroupfs / "docker" / REF / "memory.events").write_text("oom_kill 1\n")
    monkeypatch.setattr(oom, "CGROUP_ROOT", cgroupfs)
    assert oom.memory_events_file(REF) == cgroupfs / "docker" / REF / "memory.events"


@pytest.mark.parametrize(
    ("runtime", "state", "expected"),
    [
        ("runc", {"Running": False, "OOMKilled": True}, True),
        ("runc", {"Running": False, "OOMKilled": False}, False),
        ("runc", {"Running": True, "OOMKilled": True}, False),  # a process was killed, not it
        ("runsc", {"Running": False, "OOMKilled": True}, False),
        ("kata-qemu", {"Running": False, "OOMKilled": True}, False),
    ],
)
async def test_the_container_verdict_is_read_for_the_container_tier_only(
    pair: socket.socket, runtime: str, state: dict[str, Any], expected: bool
) -> None:
    client = Client(Api(pair, runtime=runtime, state=state))

    assert await oom.container_oom_killed(client, REF) is expected


def test_the_docker_and_fake_drivers_offer_the_oom_verdict(driver: FakeDriver) -> None:
    from sandfort.drivers.docker.driver import DockerDriver

    assert isinstance(driver, OomObservableDriver)
    assert hasattr(DockerDriver, "container_oom_killed")
