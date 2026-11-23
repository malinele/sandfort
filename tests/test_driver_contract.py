"""Driver plug-in certification (WP 5.6): registry, packaged conformance suite, firecracker.

The fake driver passes the whole suite; the docker driver too against a real daemon on
``alpine:3.20`` (skipped when none is reachable); the firecracker skeleton passes the compute
and exec subset against an in-process mock agent, everything else skipped by capability.
``pytest --driver=NAME`` picks the target of ``test_selected_driver_certifies``.
"""

import base64
import dataclasses
import sys
import types
import uuid
from collections.abc import AsyncIterator, Mapping, Sequence
from datetime import UTC, datetime
from importlib import metadata
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from sandfort.api.wiring import build_driver
from sandfort.clock import FrozenClock, SystemClock
from sandfort.config import Settings
from sandfort.drivers.base import ExecRequest, ExecResult, InstanceState, PtyRequest
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.docker.containers import KEEPALIVE_ENTRYPOINT
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.errors import DriverConflict, DriverError, DriverNotFound, DriverUnsupported
from sandfort.drivers.fake import FakeDriver
from sandfort.drivers.firecracker import CAPABILITIES, FirecrackerDriver, driver_entry
from sandfort.drivers.registry import (
    ALL_CAPABILITIES,
    BUILTIN_DRIVERS,
    ENTRY_POINT_GROUP,
    Capability,
    DriverRegistryError,
    UnknownDriver,
    known_drivers,
    resolve_driver,
)
from sandfort.errors import ValidationFailed
from sandfort.testing.driver_contract import (
    SUITE,
    ConformanceFailure,
    DriverContext,
    DriverContract,
    detect_capabilities,
    run_suite,
)

IMAGE = "alpine:3.20"
AGENT_URL = "http://agent.test"
PLUGIN_MODULE = "sandfort_conformance_sample_plugin"
ALL_CHECKS = tuple(check.name for check in SUITE)
VM_FIELDS = (
    "name",
    "sandbox_id",
    "org_id",
    "image",
    "cpu_millicores",
    "memory_mib",
    "disk_gib",
    "labels",
)
# action -> (state it requires, or None for any; state it leaves)
TRANSITIONS: Mapping[str, tuple[str | None, str]] = {
    "start": (None, "running"),
    "stop": (None, "exited"),
    "pause": ("running", "paused"),
    "resume": ("paused", "running"),
}

type VmTable = dict[str, dict[str, Any]]


async def append_fake_logs(driver: object, ref: str, lines: Sequence[str]) -> None:
    assert isinstance(driver, FakeDriver)
    for line in lines:
        driver.append_log(ref, line)


FAKE_CONTEXT = DriverContext(image=IMAGE, emit_logs=append_fake_logs)
DOCKER_CONTEXT = DriverContext(image=IMAGE, keepalive_argv=KEEPALIVE_ENTRYPOINT)
FIRECRACKER_CONTEXT = DriverContext(image=IMAGE)


# -- mock microVM agent -----------------------------------------------------------


def run_argv(argv: list[str], env: Mapping[str, str]) -> tuple[int, bytes]:
    """The agent's tiny guest: echo, env and ``sh -c 'exit N'``."""
    if argv[:1] == ["echo"]:
        return 0, (" ".join(argv[1:]) + "\n").encode()
    if argv == ["env"]:
        return 0, "".join(f"{key}={value}\n" for key, value in env.items()).encode()
    if len(argv) == 3 and argv[:2] == ["sh", "-c"] and argv[2].startswith("exit "):
        return int(argv[2].split()[1]), b""
    return 127, b""


def agent_error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def build_agent(vms: VmTable) -> FastAPI:
    """An agent implementing the ``agent_client`` protocol over the in-memory ``vms``."""
    app = FastAPI()

    @app.post("/vms")
    async def create_vm(request: Request) -> Response:
        body = await request.json()
        for vm in vms.values():
            if vm["name"] == body["name"]:
                return JSONResponse(vm)  # adopted; the driver checks the owner
        vm_id = f"vm-{uuid.uuid4().hex[:8]}"
        created = datetime.now(UTC).isoformat()
        fields = {key: body[key] for key in VM_FIELDS}
        vms[vm_id] = {"id": vm_id, "state": "created", "created_at": created, **fields}
        vms[vm_id]["env"] = dict(body.get("env") or {})
        return JSONResponse(vms[vm_id], status_code=201)

    @app.get("/vms")
    async def list_vms(org_id: str | None = None) -> Response:
        listed = [vm for vm in vms.values() if org_id is None or vm["org_id"] == org_id]
        return JSONResponse({"vms": listed})

    @app.get("/vms/{vm_id}")
    async def get_vm(vm_id: str) -> Response:
        vm = vms.get(vm_id)
        return JSONResponse(vm) if vm is not None else agent_error(404, f"no vm {vm_id}")

    @app.post("/vms/{vm_id}/exec")
    async def exec_vm(vm_id: str, request: Request) -> Response:
        vm = vms.get(vm_id)
        if vm is None:
            return agent_error(404, f"no vm {vm_id}")
        if vm["state"] != "running":
            return agent_error(409, f"vm {vm_id} is not running")
        body = await request.json()
        exit_code, stdout = run_argv(list(body["argv"]), {**vm["env"], **body["env"]})
        cap = int(body["max_output_bytes"])
        return JSONResponse(
            {
                "exit_code": exit_code,
                "stdout_b64": base64.b64encode(stdout[:cap]).decode(),
                "stderr_b64": "",
                "timed_out": False,
                "truncated": len(stdout) > cap,
                "duration_ms": 1,
            }
        )

    @app.post("/vms/{vm_id}/{action}")
    async def act(vm_id: str, action: str) -> Response:
        vm, transition = vms.get(vm_id), TRANSITIONS.get(action)
        if vm is None or transition is None:
            return agent_error(404, f"no vm {vm_id} or action {action}")
        required, target = transition
        if required is not None and vm["state"] != required:
            return agent_error(409, f"vm {vm_id} is {vm['state']}, {action} needs {required}")
        vm["state"] = target
        return Response(status_code=204)

    @app.delete("/vms/{vm_id}")
    async def delete_vm(vm_id: str) -> Response:
        if vms.pop(vm_id, None) is None:
            return agent_error(404, f"no vm {vm_id}")
        return Response(status_code=204)

    return app


def firecracker_driver(vms: VmTable) -> FirecrackerDriver:
    return FirecrackerDriver(AGENT_URL, transport=httpx.ASGITransport(app=build_agent(vms)))


@pytest.fixture
def agent_vms() -> VmTable:
    return {}


@pytest.fixture
async def firecracker(agent_vms: VmTable) -> AsyncIterator[FirecrackerDriver]:
    driver = firecracker_driver(agent_vms)
    try:
        yield driver
    finally:
        await driver.aclose()


# -- targets ----------------------------------------------------------------------


def make_docker_driver() -> DockerDriver:
    """A docker driver on a reachable daemon with ``alpine:3.20`` present, else a skip."""
    docker = pytest.importorskip("docker")
    try:
        client = make_client()
        client.ping()
    except Exception as exc:
        pytest.skip(f"no reachable Docker daemon: {exc}")
    try:
        client.images.get(IMAGE)
    except docker.errors.ImageNotFound:
        try:
            client.images.pull(IMAGE)
        except Exception as exc:
            pytest.skip(f"cannot pull {IMAGE}: {exc}")
    return DockerDriver(Settings(), client=client)


def make_target(name: str, vms: VmTable) -> tuple[object, DriverContext, frozenset[Capability]]:
    """``(driver, context, declared capabilities)`` for a ``--driver`` value."""
    if name == "fake":
        return FakeDriver(), FAKE_CONTEXT, resolve_driver("fake").capabilities
    if name == "docker":
        return make_docker_driver(), DOCKER_CONTEXT, resolve_driver("docker").capabilities
    if name == "firecracker":
        return firecracker_driver(vms), FIRECRACKER_CONTEXT, CAPABILITIES
    entry = resolve_driver(name)
    return entry.build(Settings(), SystemClock()), DriverContext(), entry.capabilities


async def close_driver(driver: object) -> None:
    aclose = getattr(driver, "aclose", None)
    if aclose is not None:
        await aclose()


def expected_split(capabilities: frozenset[Capability]) -> tuple[tuple[str, ...], ...]:
    """``(passed, skipped)`` check names a fully conforming driver reports."""
    passed = tuple(check.name for check in SUITE if check.requires <= capabilities)
    skipped = tuple(check.name for check in SUITE if not check.requires <= capabilities)
    return passed, skipped


async def test_selected_driver_certifies(selected_driver: str, agent_vms: VmTable) -> None:
    driver, context, capabilities = make_target(selected_driver, agent_vms)
    try:
        report = await run_suite(driver, context, capabilities=capabilities)
    finally:
        await close_driver(driver)
    assert report.ok, report.summary()
    assert (report.passed, report.skipped) == expected_split(capabilities)


# -- fake and docker: the whole suite -----------------------------------------------


async def test_fake_driver_passes_full_suite() -> None:
    driver = FakeDriver()
    declared = resolve_driver("fake").capabilities
    report = await run_suite(driver, FAKE_CONTEXT, capabilities=declared)
    assert report.ok, report.summary()
    assert report.passed == ALL_CHECKS
    assert report.skipped == ()
    assert detect_capabilities(driver) == ALL_CAPABILITIES


async def test_suite_leaves_nothing_behind() -> None:
    driver = FakeDriver()
    report = await run_suite(driver, FAKE_CONTEXT)
    assert report.ok, report.summary()
    assert await driver.list_managed() == []
    assert await driver.list_volumes() == []
    assert not await driver.image_exists(IMAGE)  # pulled by the images check, then removed


async def test_failing_check_is_named_and_still_cleans_up() -> None:
    def silent(env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        return ExecResult(exit_code=0)

    driver = FakeDriver(exec_handler=silent)
    with pytest.raises(ConformanceFailure) as raised:
        await DriverContract(driver, FAKE_CONTEXT).check_exec()
    assert raised.value.check == "exec"
    assert str(raised.value).startswith("[exec] ")
    report = await run_suite(driver, FAKE_CONTEXT)
    assert set(report.failed) == {"exec"}
    assert "compute" in report.passed
    assert await driver.list_managed() == []


async def test_contract_run_uses_declared_capabilities() -> None:
    contract = DriverContract(FakeDriver(), FAKE_CONTEXT, capabilities=[Capability.COMPUTE])
    report = await contract.run()
    assert report.passed == ("compute",)
    assert report.skipped == ALL_CHECKS[1:]


@pytest.mark.docker
async def test_docker_driver_passes_full_suite() -> None:
    driver = make_docker_driver()
    declared = resolve_driver("docker").capabilities
    report = await run_suite(driver, DOCKER_CONTEXT, capabilities=declared)
    assert report.ok, report.summary()
    assert report.passed == ALL_CHECKS
    assert report.skipped == ()


# -- firecracker skeleton against the mock agent ------------------------------------


async def test_firecracker_passes_compute_and_exec_subset(
    firecracker: FirecrackerDriver, agent_vms: VmTable
) -> None:
    report = await run_suite(firecracker, FIRECRACKER_CONTEXT, capabilities=CAPABILITIES)
    assert report.ok, report.summary()
    assert report.passed == ("compute", "exec")
    assert report.skipped == ("archive", "logs", "volumes", "images")
    assert agent_vms == {}


async def test_firecracker_capabilities_are_exactly_compute_and_exec(
    firecracker: FirecrackerDriver,
) -> None:
    assert CAPABILITIES == frozenset({Capability.COMPUTE, Capability.EXEC})
    assert detect_capabilities(firecracker) == CAPABILITIES
    undeclared = await run_suite(firecracker, FIRECRACKER_CONTEXT)
    assert undeclared.capabilities == CAPABILITIES
    assert undeclared.passed == ("compute", "exec")


async def test_overclaimed_capabilities_fail_the_report(
    firecracker: FirecrackerDriver, agent_vms: VmTable
) -> None:
    report = await run_suite(firecracker, FIRECRACKER_CONTEXT, capabilities=ALL_CAPABILITIES)
    assert not report.ok
    assert "archive" in report.failed["protocols"]
    assert {"archive", "logs", "volumes", "images"} <= set(report.failed)
    assert report.passed == ("compute", "exec")
    assert agent_vms == {}


async def test_firecracker_maps_agent_errors(firecracker: FirecrackerDriver) -> None:
    with pytest.raises(DriverNotFound):
        await firecracker.inspect("vm-missing")
    spec = FIRECRACKER_CONTEXT.new_spec()
    info = await firecracker.create(spec)
    with pytest.raises(DriverConflict):
        await firecracker.exec(info.ref, ExecRequest(argv=("echo", "early")))
    with pytest.raises(DriverConflict):
        await firecracker.create(dataclasses.replace(spec, sandbox_id="sbx_someoneelse"))
    await firecracker.start(info.ref)
    await firecracker.pause(info.ref)
    assert (await firecracker.inspect(info.ref)).state == InstanceState.PAUSED
    await firecracker.unpause(info.ref)
    assert (await firecracker.inspect(info.ref)).state == InstanceState.RUNNING
    with pytest.raises(DriverConflict):
        await firecracker.unpause(info.ref)
    await firecracker.destroy(info.ref)
    await firecracker.destroy(info.ref)  # a missing vm is already destroyed


async def test_firecracker_rejects_malformed_agent_answers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/vms":
            return httpx.Response(200, json={"vms": "nope"})
        if request.url.path.endswith("/exec"):
            return httpx.Response(200, json={"exit_code": "zero"})
        if request.url.path.endswith("/boom"):
            return httpx.Response(500, text="kaput")
        return httpx.Response(200, json={"id": "vm-1", "state": "melting"})

    driver = FirecrackerDriver(AGENT_URL, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(DriverError, match="listing"):
            await driver.list_managed()
        with pytest.raises(DriverError, match="malformed"):
            await driver.inspect("vm-1")
        with pytest.raises(DriverError, match="exit_code"):
            await driver.exec("vm-1", ExecRequest(argv=("echo",)))
        with pytest.raises(DriverError, match="500"):
            await driver.inspect("boom")
    finally:
        await driver.aclose()


async def test_firecracker_has_no_archive_or_pty(firecracker: FirecrackerDriver) -> None:
    with pytest.raises(DriverUnsupported):
        firecracker.get_archive("vm-1", "/tmp")
    with pytest.raises(DriverUnsupported):
        await firecracker.open_pty("vm-1", PtyRequest())


# -- registry -----------------------------------------------------------------------


def inject_entry_points(
    monkeypatch: pytest.MonkeyPatch, plugins: Sequence[tuple[str, Any]]
) -> None:
    """Expose ``plugins`` as ``sandfort.drivers`` entry points of a synthetic module."""
    module = types.ModuleType(PLUGIN_MODULE)
    points = []
    for index, (name, value) in enumerate(plugins):
        attribute = f"entry_{index}"
        setattr(module, attribute, value)
        value_path = f"{PLUGIN_MODULE}:{attribute}"
        points.append(metadata.EntryPoint(name=name, value=value_path, group=ENTRY_POINT_GROUP))
    monkeypatch.setitem(sys.modules, PLUGIN_MODULE, module)
    original = metadata.entry_points

    def entry_points(**params: Any) -> Any:
        if params.get("group") == ENTRY_POINT_GROUP:
            return metadata.EntryPoints(points)
        return original(**params)

    monkeypatch.setattr(metadata, "entry_points", entry_points)


def test_registry_resolves_builtins() -> None:
    fake = resolve_driver("fake")
    assert fake.capabilities == ALL_CAPABILITIES
    assert isinstance(fake.build(Settings(driver="fake"), FrozenClock()), FakeDriver)
    docker = resolve_driver("docker")
    assert (docker.name, docker.capabilities) == ("docker", ALL_CAPABILITIES)


def test_unknown_driver_names_the_known_ones(monkeypatch: pytest.MonkeyPatch) -> None:
    inject_entry_points(monkeypatch, [("sample", driver_entry(AGENT_URL))])
    with pytest.raises(UnknownDriver) as raised:
        resolve_driver("nope")
    assert raised.value.known == ("docker", "fake", "sample")
    assert "known drivers: docker, fake, sample" in str(raised.value)


async def test_registry_discovers_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = httpx.ASGITransport(app=build_agent({}))
    plugin = driver_entry(AGENT_URL, transport=transport)
    inject_entry_points(monkeypatch, [("microvm", plugin)])
    assert known_drivers() == ("docker", "fake", "microvm")
    entry = resolve_driver("microvm")
    assert (entry.name, entry.capabilities) == ("microvm", CAPABILITIES)
    driver = entry.build(Settings(), SystemClock())
    assert isinstance(driver, FirecrackerDriver)
    try:
        report = await run_suite(driver, FIRECRACKER_CONTEXT, capabilities=entry.capabilities)
    finally:
        await driver.aclose()
    assert report.ok, report.summary()
    assert report.passed == ("compute", "exec")


def test_entry_points_cannot_shadow_builtins(monkeypatch: pytest.MonkeyPatch) -> None:
    inject_entry_points(monkeypatch, [("fake", driver_entry(AGENT_URL))])
    assert resolve_driver("fake") is BUILTIN_DRIVERS["fake"]
    assert known_drivers() == ("docker", "fake")


def test_malformed_entry_point_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    inject_entry_points(monkeypatch, [("broken", object())])
    with pytest.raises(DriverRegistryError, match="must load a DriverEntry"):
        resolve_driver("broken")


def test_wiring_builds_builtin_drivers_through_the_registry() -> None:
    assert isinstance(build_driver(Settings(driver="fake"), FrozenClock()), FakeDriver)


def test_wiring_refuses_a_partial_driver(monkeypatch: pytest.MonkeyPatch) -> None:
    inject_entry_points(monkeypatch, [("microvm", driver_entry(AGENT_URL))])
    with pytest.raises(ValidationFailed, match="lacks"):
        build_driver(Settings(driver="microvm"), FrozenClock())
