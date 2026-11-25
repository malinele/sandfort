"""Egress v2 round 4, driver side (design 4.5, 6.2; cases D2 and D5), no daemon needed.

D2: every container on the egress net gets ``dns=[sink]`` except runtimes with their own network
stack (runsc, kata: the families ``check_tier_families`` pins); an unrecognised runtime string
fails closed and gets the sink. gVisor, Kata and the open net are unchanged. 4.5:
``ensure_network`` refuses an egress net with IPv6, adopted or just created. D5: the prod probe
reports a runc canary that resolves a public name (a fake runner stands in for docker).
"""

import logging
from collections.abc import Sequence
from types import SimpleNamespace
from typing import Any

import pytest
from tests.test_docker_driver_unit import make_spec

from sandfort.config import Settings
from sandfort.domain.sandbox import EGRESS_RESTRICTED_LABEL, NetworkPolicy
from sandfort.drivers.base import SandboxSpec
from sandfort.drivers.docker import hardening, networks
from sandfort.drivers.docker.egress_probe import (
    PROBE_FINDING_PREFIX,
    EgressProbeError,
    probe_findings,
    probe_networks,
)
from sandfort.drivers.docker.egress_probe_dns import (
    DNS_FINDING,
    DNS_PROBE_NAME,
    LOCAL_MARK,
    READY_MARK,
    RESOLVED_MARK,
    DnsCanaryError,
    DnsCanaryRunner,
    parse_dns_canary,
)
from sandfort.drivers.docker.hardening import build_host_config, options_from_settings
from sandfort.drivers.docker.networks import EGRESS_NETWORK_NAME, NETWORK_NAME, ensure_network
from sandfort.drivers.errors import DriverUnsupported

SINK = "172.30.0.1"
TIER_MAP = (("container", ""), ("gvisor", "runsc"), ("microvm", "kata"))
GATEWAY = "172.20.0.1"


@pytest.fixture(autouse=True)
def _reset_module_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hardening, "_sink_warned", False)
    monkeypatch.setattr(networks, "_warned", set())


def egress_spec(*, isolation: str | None = None, block_all: bool = False) -> SandboxSpec:
    base = make_spec()
    return SandboxSpec(
        sandbox_id=base.sandbox_id,
        org_id=base.org_id,
        name=base.name,
        image=base.image,
        resources=base.resources,
        labels={EGRESS_RESTRICTED_LABEL: "true"},
        network=NetworkPolicy(block_all=block_all),
        isolation=isolation,
    )


def open_spec(*, isolation: str | None = None) -> SandboxSpec:
    base = make_spec()
    return SandboxSpec(
        sandbox_id=base.sandbox_id,
        org_id=base.org_id,
        name=base.name,
        image=base.image,
        resources=base.resources,
        isolation=isolation,
    )


def config_for(spec: SandboxSpec, **changes: Any) -> dict[str, Any]:
    settings = Settings(isolation_runtimes=TIER_MAP, **changes)
    return build_host_config(spec, settings, options_from_settings(settings))


# --- D2: the dns kwarg -----------------------------------------------------------------


def test_runc_on_the_egress_net_gets_the_sink_as_its_only_resolver() -> None:
    config = config_for(egress_spec(isolation="container"), egress_dns_sink_address=SINK)

    assert config["network_mode"] == EGRESS_NETWORK_NAME
    assert config["dns"] == [SINK]


@pytest.mark.parametrize(
    "runtime",
    ["runc", "crun", "io.containerd.runc.v2", "nvidia", "sysbox-runc", "my-custom-alias", "youki"],
)
def test_any_container_tier_runtime_without_its_own_stack_gets_the_sink(runtime: str) -> None:
    settings = Settings(
        isolation_runtimes=(("container", runtime), ("gvisor", "runsc"), ("microvm", "kata")),
        egress_dns_sink_address=SINK,
    )

    config = build_host_config(
        egress_spec(isolation="container"), settings, options_from_settings(settings)
    )

    assert config["runtime"] == runtime
    assert config["dns"] == [SINK]


def test_an_unrecognised_runtime_on_the_default_tier_fails_closed() -> None:
    settings = Settings(container_runtime="mystery-runtime", egress_dns_sink_address=SINK)

    config = build_host_config(egress_spec(), settings, options_from_settings(settings))

    assert config["dns"] == [SINK]


def test_the_default_tier_with_no_runtime_is_runc_and_gets_the_sink() -> None:
    settings = Settings(egress_dns_sink_address=SINK)

    config = build_host_config(egress_spec(), settings, options_from_settings(settings))

    assert config["dns"] == [SINK]


@pytest.mark.parametrize("tier", ["gvisor", "microvm"])
def test_gvisor_and_kata_are_unchanged(tier: str) -> None:
    config = config_for(egress_spec(isolation=tier), egress_dns_sink_address=SINK)

    assert config["network_mode"] == EGRESS_NETWORK_NAME
    assert "dns" not in config


@pytest.mark.parametrize(
    ("tier", "runtime"),
    [
        ("gvisor", "runsc"),
        ("gvisor", "runsc-kvm"),
        ("gvisor", "RunSC"),
        ("microvm", "kata"),
        ("microvm", "kata-qemu"),
        ("microvm", "io.containerd.kata.v2"),
    ],
)
def test_runtimes_of_the_runsc_and_kata_families_do_not_get_the_sink(
    tier: str, runtime: str
) -> None:
    settings = Settings(
        isolation_runtimes=((tier, runtime),), default_isolation=tier, egress_dns_sink_address=SINK
    )

    config = build_host_config(
        egress_spec(isolation=tier), settings, options_from_settings(settings)
    )

    assert config["network_mode"] == EGRESS_NETWORK_NAME
    assert "dns" not in config


def test_a_deployment_default_runtime_of_runsc_is_not_treated_as_runc() -> None:
    settings = Settings(container_runtime="runsc", egress_dns_sink_address=SINK)

    config = build_host_config(egress_spec(), settings, options_from_settings(settings))

    assert "dns" not in config


def test_the_open_net_and_a_blocked_net_are_unchanged() -> None:
    assert "dns" not in config_for(open_spec(isolation="container"), egress_dns_sink_address=SINK)
    blocked = egress_spec(isolation="container", block_all=True)
    assert "dns" not in config_for(blocked, egress_dns_sink_address=SINK)
    assert config_for(open_spec(), egress_dns_sink_address=SINK)["network_mode"] == NETWORK_NAME


def test_without_a_sink_v1_behaviour_stays() -> None:
    assert "dns" not in config_for(egress_spec(isolation="container"))


# --- the Settings field ------------------------------------------------------------------


def test_the_sink_address_defaults_to_unset_and_parses_from_the_env() -> None:
    assert Settings.from_env({}).egress_dns_sink_address == ""
    parsed = Settings.from_env({"SANDFORT_EGRESS_DNS_SINK_ADDRESS": f" {SINK} "})
    assert parsed.egress_dns_sink_address == SINK


@pytest.mark.parametrize("bad", ["not-an-ip", "172.30.0.1,172.30.0.2", "::1"])
def test_a_bad_sink_address_fails_at_load_time(bad: str) -> None:
    with pytest.raises(ValueError, match="EGRESS_DNS_SINK_ADDRESS"):
        Settings.from_env({"SANDFORT_EGRESS_DNS_SINK_ADDRESS": bad})


# --- the startup warning ---------------------------------------------------------------


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


def test_one_startup_warning_when_egress_is_on_and_the_sink_is_unset(
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = Settings(egress_proxy_address="10.0.0.1:3128")

    with caplog.at_level(logging.WARNING, logger=hardening.__name__):
        options_from_settings(settings)
        options_from_settings(settings)

    [message] = _warnings(caplog)
    assert "SANDFORT_EGRESS_DNS_SINK_ADDRESS" in message


def test_no_warning_with_the_sink_set_or_egress_off(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger=hardening.__name__):
        options_from_settings(
            Settings(egress_proxy_address="10.0.0.1:3128", egress_dns_sink_address=SINK)
        )
        options_from_settings(Settings())

    assert _warnings(caplog) == []


# --- section 4.5: the egress net stays IPv4-only ---------------------------------------


class FakeNetworks:
    def __init__(self, existing: list[Any], *, created_attrs: dict[str, Any] | None = None) -> None:
        self.existing = existing
        self.created_attrs = created_attrs
        self.created: list[tuple[str, dict[str, Any]]] = []
        self.removed: list[str] = []

    def list(self, **_: Any) -> list[Any]:
        return self.existing

    def create(self, name: str, **kwargs: Any) -> Any:
        self.created.append((name, kwargs))
        if self.created_attrs is None:
            return None
        return SimpleNamespace(
            name=name, attrs=self.created_attrs, remove=lambda: self.removed.append(name)
        )


def _network(name: str, **attrs: Any) -> Any:
    return SimpleNamespace(name=name, attrs={"Options": {}, **attrs})


@pytest.mark.parametrize("name", [EGRESS_NETWORK_NAME])
async def test_ensure_network_refuses_an_egress_net_with_ipv6(name: str) -> None:
    client = SimpleNamespace(networks=FakeNetworks([_network(name, EnableIPv6=True)]))

    with pytest.raises(DriverUnsupported, match="IPv6"):
        await ensure_network(client, name)

    assert client.networks.created == []


@pytest.mark.parametrize("attrs", [{}, {"EnableIPv6": False}, {"EnableIPv6": None}])
async def test_ensure_network_adopts_an_ipv4_only_egress_net(attrs: dict[str, Any]) -> None:
    client = SimpleNamespace(networks=FakeNetworks([_network(EGRESS_NETWORK_NAME, **attrs)]))

    assert await ensure_network(client, EGRESS_NETWORK_NAME) == EGRESS_NETWORK_NAME


async def test_the_main_network_is_not_subject_to_the_ipv4_rule() -> None:
    client = SimpleNamespace(networks=FakeNetworks([_network(NETWORK_NAME, EnableIPv6=True)]))

    assert await ensure_network(client, NETWORK_NAME) == NETWORK_NAME


async def test_a_new_egress_net_is_created_without_ipv6() -> None:
    client = SimpleNamespace(networks=FakeNetworks([]))

    await ensure_network(client, EGRESS_NETWORK_NAME)

    [(_, kwargs)] = client.networks.created
    assert kwargs.get("enable_ipv6", False) is False


async def test_a_created_egress_net_that_came_up_with_ipv6_is_removed_and_refused() -> None:
    # docker-py sends no EnableIPv6=false, so a daemon defaulting bridges to IPv6 creates one.
    networks_api = FakeNetworks([], created_attrs={"EnableIPv6": True, "Options": {}})
    client = SimpleNamespace(networks=networks_api)

    with pytest.raises(DriverUnsupported, match="IPv6"):
        await ensure_network(client, EGRESS_NETWORK_NAME)

    assert networks_api.removed == [EGRESS_NETWORK_NAME]


async def test_a_created_ipv4_only_egress_net_is_kept() -> None:
    networks_api = FakeNetworks([], created_attrs={"EnableIPv6": False, "Options": {}})
    client = SimpleNamespace(networks=networks_api)

    assert await ensure_network(client, EGRESS_NETWORK_NAME) == EGRESS_NETWORK_NAME
    assert networks_api.removed == []


async def test_a_created_main_network_with_ipv6_is_left_alone() -> None:
    networks_api = FakeNetworks([], created_attrs={"EnableIPv6": True, "Options": {}})
    client = SimpleNamespace(networks=networks_api)

    assert await ensure_network(client, NETWORK_NAME) == NETWORK_NAME
    assert networks_api.removed == []


# --- D5: the prod probe's DNS check ------------------------------------------------------


class DnsRunner:
    """A fake canary runner that also answers the DNS canary."""

    def __init__(self, *, resolves: bool = False, sink: str = SINK, error: str = "") -> None:
        self.resolved = resolves
        self.dns_sink = sink
        self.error = error
        self.dns_calls: list[tuple[str, str]] = []

    async def prune(self) -> None:
        return None

    async def gateway(self, network: str) -> str:
        return GATEWAY

    async def reachable(self, network: str, image: str, targets: Sequence[str]) -> frozenset[str]:
        return frozenset()

    async def resolves(self, network: str, image: str) -> bool:
        self.dns_calls.append((network, image))
        if self.error:
            raise EgressProbeError(self.error)
        return self.resolved


async def test_a_canary_that_resolves_a_public_name_is_a_finding() -> None:
    runner = DnsRunner(resolves=True)

    findings = await probe_findings(runner, "alpine:3.20")

    assert findings == [
        DNS_FINDING.format(prefix=PROBE_FINDING_PREFIX, network=EGRESS_NETWORK_NAME)
    ]
    assert runner.dns_calls == [(EGRESS_NETWORK_NAME, "alpine:3.20")]


async def test_a_canary_that_cannot_resolve_is_clean() -> None:
    runner = DnsRunner(resolves=False)

    report = await probe_networks(runner, "alpine:3.20")

    assert report.findings() == []
    assert len(runner.dns_calls) == 1


async def test_the_dns_check_is_skipped_when_no_sink_is_configured() -> None:
    runner = DnsRunner(resolves=True, sink="")

    assert await probe_findings(runner, "alpine:3.20") == []
    assert runner.dns_calls == []


class PlainRunner:
    """A runner from before round 4: no DNS canary."""

    async def prune(self) -> None:
        return None

    async def gateway(self, network: str) -> str:
        return GATEWAY

    async def reachable(self, network: str, image: str, targets: Sequence[str]) -> frozenset[str]:
        return frozenset()


async def test_a_runner_without_the_dns_canary_is_still_probed_as_before() -> None:
    assert not isinstance(PlainRunner(), DnsCanaryRunner)
    assert await probe_findings(PlainRunner(), "alpine:3.20") == []


async def test_a_dns_canary_that_cannot_run_is_a_could_not_run_finding() -> None:
    runner = DnsRunner(error="canary on sf-egress-net: no getent")

    [finding] = await probe_findings(runner, "alpine:3.20")

    assert finding.startswith(f"{PROBE_FINDING_PREFIX} could not run")
    assert "no getent" in finding


# --- the canary's output contract (fail closed) ------------------------------------------


def _output(*marks: str) -> str:
    return "\n".join(marks) + "\n"


def test_the_canary_output_says_resolved_only_with_the_positive_controls() -> None:
    assert parse_dns_canary(_output(READY_MARK, LOCAL_MARK), 0) is False
    assert parse_dns_canary(_output(READY_MARK, LOCAL_MARK, RESOLVED_MARK), 0) is True


@pytest.mark.parametrize(
    ("output", "status"),
    [
        ("", 0),
        (_output(READY_MARK), 0),  # no local control: getent cannot resolve anything
        (_output(LOCAL_MARK), 0),
        (_output(READY_MARK, LOCAL_MARK), 3),
        (_output(READY_MARK, LOCAL_MARK, RESOLVED_MARK), 1),
    ],
)
def test_a_canary_that_did_not_run_cleanly_is_an_error_never_a_pass(
    output: str, status: int
) -> None:
    with pytest.raises(DnsCanaryError):
        parse_dns_canary(output, status)


def test_the_probe_name_is_a_fixed_public_name() -> None:
    assert "." in DNS_PROBE_NAME
