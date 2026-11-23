"""Round 58: the egress probe replaces the honour-system flag in the prod startup gate (H5).

A fake canary runner stands in for docker: it answers which targets "connected".
"""

import asyncio
import logging
import time
from collections.abc import Sequence
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

import sandfort.admin_doctor as doctor_module
import sandfort.api.app as app_module
from sandfort.admin_doctor import CheckResult, Status, evaluate
from sandfort.api.app import IsolationUnavailableError, check_isolation
from sandfort.config import Settings
from sandfort.drivers.docker.capabilities import DockerCapabilities
from sandfort.drivers.docker.egress_probe import (
    CANARY_LABEL,
    CANARY_SCRIPT,
    CANARY_STARTED_LABEL,
    LOOPBACK_MARK,
    READY_MARK,
    DockerCanaryRunner,
    EgressProbeError,
    canary_runner_for,
    gateway_of,
    parse_canary,
    parse_reachable,
    probe_findings,
    probe_networks,
)
from sandfort.drivers.docker.lanes import reopen_lanes
from sandfort.drivers.docker.networks import EGRESS_NETWORK_NAME, NETWORK_NAME

GATEWAY = "172.20.0.1"
METADATA = "169.254.169.254:80"
GATEWAY_SSH = f"{GATEWAY}:22"
HEALTHY = f"{READY_MARK}\n{LOOPBACK_MARK}\n"
PUBLIC = "1.1.1.1:443"
OVERRIDE_VARIABLE = "SANDFORT_EGRESS_ACKNOWLEDGED"


class FakeRunner:
    """Answers each probe with the targets configured as reachable on that network."""

    def __init__(
        self, hits: dict[str, set[str]] | None = None, error: str = "", gateway: str = GATEWAY
    ) -> None:
        self.hits = hits or {}
        self.error = error
        self.gateway_address = gateway
        self.calls: list[tuple[str, str, tuple[str, ...]]] = []
        self.pruned_after: int | None = None  # how many canaries had run when it pruned

    async def prune(self) -> None:
        self.pruned_after = len(self.calls)

    async def gateway(self, network: str) -> str:
        return self.gateway_address

    async def reachable(self, network: str, image: str, targets: Sequence[str]) -> frozenset[str]:
        self.calls.append((network, image, tuple(targets)))
        if self.error:
            raise EgressProbeError(self.error)
        return frozenset(target for target in targets if target in self.hits.get(network, set()))


class GapsDriver:
    """A driver stand-in with no capability gaps."""

    async def isolation_gaps(self) -> list[str]:
        return []


def prod(**changes: Any) -> Settings:
    return replace(Settings(environment="prod"), **changes)


def targets_for(runner: FakeRunner, network: str) -> tuple[str, ...]:
    [targets] = [call[2] for call in runner.calls if call[0] == network]
    return targets


# --- settings ---------------------------------------------------------------------------


def test_the_probe_is_on_by_default_in_prod_only() -> None:
    assert Settings(environment="prod").egress_probe_enabled() is True
    assert Settings(environment="dev").egress_probe_enabled() is False


def test_the_setting_overrides_the_environment_default() -> None:
    assert Settings(environment="dev", egress_probe=True).egress_probe_enabled() is True
    assert Settings(environment="prod", egress_probe=False).egress_probe_enabled() is False


def test_the_env_reads_the_probe_flag_and_image() -> None:
    defaults = Settings.from_env({})
    custom = Settings.from_env(
        {"SANDFORT_EGRESS_PROBE": "false", "SANDFORT_EGRESS_PROBE_IMAGE": " busybox:1.36 "}
    )

    assert defaults.egress_probe is None
    assert defaults.egress_probe_image == "alpine:3.20"
    assert defaults.egress_acknowledged is False
    assert custom.egress_probe is False
    assert custom.egress_probe_image == "busybox:1.36"


# --- the probe itself -------------------------------------------------------------------


async def test_every_target_refused_gives_a_clean_report() -> None:
    runner = FakeRunner()

    report = await probe_networks(runner, "alpine:3.20")

    assert report.findings() == []
    assert [network.network for network in report.networks] == [NETWORK_NAME, EGRESS_NETWORK_NAME]
    assert all(call[1] == "alpine:3.20" for call in runner.calls)


async def test_the_public_address_is_probed_on_the_allowlist_network_only() -> None:
    runner = FakeRunner()

    await probe_networks(runner, "alpine:3.20")

    assert {METADATA, GATEWAY_SSH} <= set(targets_for(runner, NETWORK_NAME))
    assert PUBLIC not in targets_for(runner, NETWORK_NAME)
    assert PUBLIC in targets_for(runner, EGRESS_NETWORK_NAME)
    assert len(targets_for(runner, NETWORK_NAME)) == 3  # metadata, gateway:22, one RFC 1918
    assert len(targets_for(runner, EGRESS_NETWORK_NAME)) == 4


async def test_a_reachable_target_is_reported_per_network() -> None:
    runner = FakeRunner({EGRESS_NETWORK_NAME: {METADATA, PUBLIC}})

    report = await probe_networks(runner, "alpine:3.20")

    [finding] = report.findings()
    assert EGRESS_NETWORK_NAME in finding
    assert METADATA in finding
    assert PUBLIC in finding
    assert f"{NETWORK_NAME} " not in finding


async def test_a_runner_failure_is_an_error_not_a_pass() -> None:
    with pytest.raises(EgressProbeError, match="no docker"):
        await probe_networks(FakeRunner(error="no docker"), "alpine:3.20")


def test_the_canary_output_lists_the_reachable_targets() -> None:
    output = "REACHABLE 169.254.169.254:80\nnoise\nREACHABLE 10.255.255.254:80\n"
    known = [METADATA, "10.255.255.254:80", PUBLIC]

    assert parse_reachable(output, known) == {METADATA, "10.255.255.254:80"}
    assert parse_reachable("REACHABLE 8.8.8.8:53\n", [METADATA]) == frozenset()  # unknown target


def test_a_runner_is_built_from_a_docker_driver_only() -> None:
    class WithClient:
        _client = object()

    assert canary_runner_for(object()) is None
    assert isinstance(canary_runner_for(WithClient()), DockerCanaryRunner)


# --- the prod startup gate --------------------------------------------------------------


async def test_prod_passes_when_every_target_is_refused_without_the_flag() -> None:
    runner = FakeRunner()

    await check_isolation(GapsDriver(), prod(), canary=runner)

    assert len(runner.calls) == 2


async def test_prod_refuses_when_the_metadata_address_is_reachable() -> None:
    runner = FakeRunner({NETWORK_NAME: {METADATA}})

    with pytest.raises(IsolationUnavailableError, match="169.254.169.254:80") as raised:
        await check_isolation(GapsDriver(), prod(), canary=runner)

    assert NETWORK_NAME in str(raised.value)


async def test_the_acknowledgement_downgrades_the_refusal_to_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    runner = FakeRunner({NETWORK_NAME: {METADATA}})

    with caplog.at_level(logging.WARNING):
        await check_isolation(GapsDriver(), prod(egress_acknowledged=True), canary=runner)

    text = "\n".join(record.getMessage() for record in caplog.records)
    assert "169.254.169.254:80" in text
    assert OVERRIDE_VARIABLE in text
    assert "override" in text


async def test_a_probe_that_cannot_run_refuses_and_the_override_downgrades_it() -> None:
    runner = FakeRunner(error="image alpine:3.20 not found")

    with pytest.raises(IsolationUnavailableError, match="could not run.*not found"):
        await check_isolation(GapsDriver(), prod(), canary=runner)

    await check_isolation(GapsDriver(), prod(egress_acknowledged=True), canary=runner)


async def test_capability_gaps_still_refuse_after_a_clean_probe() -> None:
    class Broken:
        async def isolation_gaps(self) -> list[str]:
            return ["container runtime 'runsc': missing"]

    with pytest.raises(IsolationUnavailableError, match="container runtime"):
        await check_isolation(Broken(), prod(), canary=FakeRunner())


async def test_the_probe_is_skipped_outside_prod_by_default() -> None:
    runner = FakeRunner({NETWORK_NAME: {METADATA}})

    await check_isolation(GapsDriver(), Settings(environment="dev"), canary=runner)

    assert runner.calls == []


async def test_dev_with_the_setting_on_runs_the_probe_and_only_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    runner = FakeRunner({NETWORK_NAME: {METADATA}})
    settings = Settings(environment="dev", egress_probe=True)

    with caplog.at_level(logging.WARNING):
        await check_isolation(GapsDriver(), settings, canary=runner)

    assert len(runner.calls) == 2
    assert any(METADATA in record.getMessage() for record in caplog.records)


async def test_prod_with_the_probe_off_keeps_the_acknowledgement_requirement() -> None:
    runner = FakeRunner()

    with pytest.raises(IsolationUnavailableError, match=OVERRIDE_VARIABLE):
        await check_isolation(GapsDriver(), prod(egress_probe=False), canary=runner)

    await check_isolation(GapsDriver(), prod(egress_probe=False, egress_acknowledged=True))
    assert runner.calls == []


async def test_prod_without_a_runner_falls_back_to_the_acknowledgement() -> None:
    with pytest.raises(IsolationUnavailableError, match=OVERRIDE_VARIABLE):
        await check_isolation(GapsDriver(), prod())


# --- robustness: any failure, a deadline, a positive control, odd subnets ---------------


class CrashingRunner(FakeRunner):
    async def reachable(self, network: str, image: str, targets: Sequence[str]) -> frozenset[str]:
        raise AttributeError("'Fake' object has no attribute 'containers'")


class SlowRunner(FakeRunner):
    async def reachable(self, network: str, image: str, targets: Sequence[str]) -> frozenset[str]:
        await asyncio.sleep(10)
        return frozenset()


async def test_any_runner_exception_is_a_could_not_run_finding() -> None:
    [finding] = await probe_findings(CrashingRunner(), "alpine:3.20")

    assert finding.startswith("egress probe could not run")
    assert "AttributeError" in finding
    assert NETWORK_NAME in finding


async def test_stale_canaries_are_pruned_before_any_canary_runs() -> None:
    runner = FakeRunner()

    await probe_networks(runner, "alpine:3.20")

    assert runner.pruned_after == 0


async def test_a_probe_past_its_deadline_refuses_prod_and_the_override_downgrades_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(app_module, "EGRESS_PROBE_DEADLINE_S", 0.05)

    with pytest.raises(IsolationUnavailableError, match="could not run.*did not finish"):
        await check_isolation(GapsDriver(), prod(), canary=SlowRunner())

    await check_isolation(GapsDriver(), prod(egress_acknowledged=True), canary=SlowRunner())


def test_the_canary_checks_its_tools_and_prints_ready_before_probing() -> None:
    ready = CANARY_SCRIPT.index(f"echo {READY_MARK}")

    assert CANARY_SCRIPT.index("command -v nc") < ready
    assert CANARY_SCRIPT.index("command -v timeout") < ready
    assert ready < CANARY_SCRIPT.index("for t in")


def test_the_canary_runs_a_loopback_control_before_the_targets() -> None:
    assert "nc -l" in CANARY_SCRIPT
    assert "127.0.0.1" in CANARY_SCRIPT
    assert CANARY_SCRIPT.index(f"echo {READY_MARK}") < CANARY_SCRIPT.index("nc -l")
    assert CANARY_SCRIPT.index(f"echo '{LOOPBACK_MARK}'") < CANARY_SCRIPT.index("for t in")


def test_a_canary_without_ready_or_with_a_failing_exit_could_not_run() -> None:
    assert parse_canary(f"{HEALTHY}REACHABLE {METADATA}\n", 0, [METADATA]) == {METADATA}
    with pytest.raises(EgressProbeError, match=READY_MARK):
        parse_canary(f"REACHABLE {METADATA}\n", 0, [METADATA])
    with pytest.raises(EgressProbeError, match="status 3"):
        parse_canary(f"{READY_MARK}\n", 3, [METADATA])


def test_a_canary_without_the_loopback_marker_could_not_run() -> None:
    # a broken nc would otherwise make every target look refused
    with pytest.raises(EgressProbeError, match=LOOPBACK_MARK):
        parse_canary(f"{READY_MARK}\n", 0, [METADATA])
    assert parse_canary(HEALTHY, 0, [METADATA]) == frozenset()


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ({"Subnet": "172.20.0.0/16", "Gateway": "172.20.0.1"}, "172.20.0.1"),
        ({"Subnet": "172.21.0.0/16"}, "172.21.0.1"),
        ({"Subnet": "172.22.0.7/32"}, None),
        ({"Subnet": "172.22.0.6/31"}, None),
        ({"Subnet": "not-a-subnet", "Gateway": "nope"}, None),
        ("not-a-mapping", None),
    ],
)
def test_the_gateway_is_guarded_against_odd_subnets(config: Any, expected: str | None) -> None:
    assert gateway_of({"IPAM": {"Config": [config]}}) == expected


class FakeDocker:
    """docker-py stand-in: networks, images and containers; creates and removals are kept."""

    def __init__(
        self,
        *,
        subnet: str = "172.20.0.0/16",
        output: bytes = HEALTHY.encode(),
        status: int = 0,
        stale: tuple[str, ...] = (),
    ) -> None:
        self.created: list[dict[str, Any]] = []
        self.removed: list[str] = []
        self.filters: list[Any] = []
        self._output, self._status, self._stale = output, status, stale
        attrs = {"IPAM": {"Config": [{"Subnet": subnet}]}}
        network = SimpleNamespace(attrs=attrs, name="")
        self.networks = SimpleNamespace(
            list=lambda names: [replace_name(network, name) for name in names],
            get=lambda name: replace_name(network, name),
        )
        self.images = SimpleNamespace(get=lambda image: image)
        self.containers = SimpleNamespace(create=self._create, list=self._list)

    def _container(self, ident: str, labels: dict[str, str]) -> Any:
        return SimpleNamespace(
            labels=labels,
            start=lambda: None,
            wait=lambda timeout: {"StatusCode": self._status},
            logs=lambda stdout, stderr: self._output,
            remove=lambda force: self.removed.append(ident),
        )

    def _create(self, image: str, command: list[str], **kwargs: Any) -> Any:
        self.created.append(kwargs)
        return self._container(f"canary-{len(self.created)}", kwargs["labels"])

    def _list(self, all: bool, filters: Any) -> list[Any]:
        self.filters.append(filters)
        return [
            self._container(f"stale-{index}", {CANARY_LABEL: "canary", CANARY_STARTED_LABEL: at})
            for index, at in enumerate(self._stale)
        ]


def replace_name(network: Any, name: str) -> Any:
    return SimpleNamespace(attrs=network.attrs, name=name)


def docker_runner(**options: Any) -> tuple[DockerCanaryRunner, FakeDocker]:
    pytest.importorskip("docker")
    reopen_lanes()  # an earlier test's driver close shuts the module-wide lanes
    client = FakeDocker(**options)
    return DockerCanaryRunner(client), client


async def test_the_docker_runner_labels_each_canary_and_removes_it() -> None:
    runner, client = docker_runner(output=f"{HEALTHY}REACHABLE {METADATA}\n".encode())

    findings = await probe_findings(runner, "alpine:3.20")

    assert len(findings) == 2
    assert all(METADATA in finding for finding in findings)
    assert all({CANARY_LABEL, CANARY_STARTED_LABEL} <= set(kw["labels"]) for kw in client.created)
    assert client.removed == ["canary-1", "canary-2"]


async def test_stale_canaries_are_removed_and_fresh_ones_are_left() -> None:
    runner, client = docker_runner(stale=("0", "garbage", str(int(time.time()))))

    assert await probe_findings(runner, "alpine:3.20") == []

    assert client.filters == [{"label": [f"{CANARY_LABEL}=canary"]}]
    assert client.removed == ["stale-0", "stale-1", "canary-1", "canary-2"]


async def test_a_host_route_subnet_could_not_run_for_that_network() -> None:
    runner, client = docker_runner(subnet="172.20.0.7/32")

    [finding] = await probe_findings(runner, "alpine:3.20")

    assert "could not run" in finding
    assert NETWORK_NAME in finding
    assert client.created == []


@pytest.mark.parametrize(
    ("output", "status", "expected"),
    [
        (b"", 0, READY_MARK),
        (b"READY\n", 0, LOOPBACK_MARK),
        (b"READY\n", 3, "status 3"),
    ],
)
async def test_a_canary_that_did_not_get_ready_could_not_run(
    output: bytes, status: int, expected: str
) -> None:
    runner, client = docker_runner(output=output, status=status)

    [finding] = await probe_findings(runner, "alpine:3.20")

    assert "could not run" in finding
    assert expected in finding
    assert client.removed == ["canary-1"]  # removed even though it failed


async def test_a_client_without_the_docker_api_could_not_run() -> None:
    [finding] = await probe_findings(DockerCanaryRunner(object()), "alpine:3.20")

    assert finding.startswith("egress probe could not run")


# --- the doctor -------------------------------------------------------------------------


def capabilities() -> DockerCapabilities:
    return DockerCapabilities(
        "27.0.1",
        "1.46",
        True,
        storage_driver="overlay2",
        backing_filesystem="xfs",
        disk_quota_supported=True,
        runtimes=("runc", "runsc"),
        userns_remap=True,
        default_runtime="runc",
        cgroup_driver="systemd",
    )


def named(settings: Settings, name: str, findings: list[str] | None) -> CheckResult | None:
    results = evaluate(settings, capabilities(), egress_probe=findings)
    return next((result for result in results if result.name == name), None)


def test_the_doctor_has_no_probe_check_when_the_probe_did_not_run() -> None:
    assert named(prod(egress_acknowledged=True), "egress probe", None) is None


def test_the_doctor_passes_a_clean_probe_without_the_flag() -> None:
    check = named(prod(), "egress probe", [])
    acknowledged = named(prod(), "egress acknowledged", [])

    assert check is not None and check.status is Status.PASS
    assert acknowledged is not None and acknowledged.status is Status.PASS  # probe verified it


def test_the_doctor_fails_a_reachable_target_in_prod() -> None:
    check = named(prod(), "egress probe", [f"egress probe: {NETWORK_NAME} reached {METADATA}"])

    assert check is not None and check.status is Status.FAIL
    assert METADATA in check.detail


def test_the_doctor_warns_when_the_override_is_set() -> None:
    finding = f"egress probe: {NETWORK_NAME} reached {METADATA}"

    check = named(prod(egress_acknowledged=True), "egress probe", [finding])

    assert check is not None and check.status is Status.WARN
    assert OVERRIDE_VARIABLE in check.detail


def test_the_doctor_still_requires_the_flag_when_no_probe_ran() -> None:
    check = named(prod(egress_acknowledged=False), "egress acknowledged", None)

    assert check is not None and check.status is Status.FAIL


# --- the doctor's probe deadline --------------------------------------------------------


class _Client:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


async def _hang(runner: object, image: str) -> list[str]:
    await asyncio.sleep(10)
    return []


async def test_a_hung_doctor_probe_is_a_finding_and_closes_the_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _Client()
    monkeypatch.setattr(app_module, "EGRESS_PROBE_DEADLINE_S", 0.05)
    monkeypatch.setattr(doctor_module, "make_client", lambda **_: client)
    monkeypatch.setattr(doctor_module, "probe_findings", _hang)

    [finding] = await doctor_module.fetch_probe(Settings(environment="prod"))

    assert finding.startswith("egress probe could not run")
    assert "did not finish" in finding
    assert client.closed is True
    check = named(prod(), "egress probe", [finding])
    assert check is not None and check.status is Status.FAIL


async def test_a_doctor_probe_inside_the_deadline_returns_its_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def quick(runner: object, image: str) -> list[str]:
        return ["egress probe: x reached y"]

    client = _Client()
    monkeypatch.setattr(doctor_module, "make_client", lambda **_: client)
    monkeypatch.setattr(doctor_module, "probe_findings", quick)

    findings = await doctor_module.fetch_probe(Settings(environment="prod"))

    assert findings == ["egress probe: x reached y"]
    assert client.closed is True
