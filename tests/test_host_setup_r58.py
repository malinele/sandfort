"""deploy/host-setup.sh in dry-run mode against stub system executables."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "deploy" / "host-setup.sh"

_IPTABLES_STUB = (
    'if [ "$1 $2 $3" = "-n -L DOCKER-USER" ]; then exit 0; fi\n'
    'if [ "$1" = "-n" ]; then exit 1; fi\n'
    "exit 0\n"
)
STUBS = {
    "uname": "echo Linux\n",
    "id": "echo 0\n",
    # No network exists yet (inspect fails), so the script falls back to the fixed names.
    "docker": '[ "$1 $2" = "network inspect" ] && exit 1\nexit 0\n',
    "ip": '[ "$4" = "${STUB_MISSING_IFACE:-}" ] && exit 1\nexit 0\n',
    "iptables": _IPTABLES_STUB,
    "ip6tables": _IPTABLES_STUB,
}

PROXY_INPUT = "SANDFORT-HOST-GUARD-PROXY"
PROXY_FORWARD = "SANDFORT-EGRESS-PROXY"

pytestmark = pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX sh")


@pytest.fixture
def stub_bin(tmp_path: Path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in STUBS.items():
        path = bin_dir / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return bin_dir


# Variables every run gets unless the test passes its own value; filled by the autouse fixture.
_DEFAULT_ENV: dict[str, str] = {}
DEFAULT_PROXY = "10.0.0.5:3128"


@pytest.fixture(autouse=True)
def proxy_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    """The script refuses to derive a loopback endpoint, so name a reachable one."""
    monkeypatch.setitem(_DEFAULT_ENV, "SF_EGRESS_PROXY", DEFAULT_PROXY)


def run_script(
    stub_bin: Path, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    base = {k: v for k, v in os.environ.items() if not k.startswith(("SF_", "DRY_RUN"))}
    base["PATH"] = f"{stub_bin}:/usr/bin:/bin"
    base.update(_DEFAULT_ENV)
    base.update(env or {})
    return subprocess.run(
        ["sh", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=base,
        timeout=30,
        check=False,
    )


def rules(result: subprocess.CompletedProcess[str]) -> list[str]:
    return [line[2:] for line in result.stdout.splitlines() if line.startswith("+ ")]


def chain_rules(result: subprocess.CompletedProcess[str], chain: str) -> list[str]:
    return [r for r in rules(result) if r.startswith(f"iptables -A {chain} ")]


def test_dry_run_installs_input_jump_for_allowlist_bridge(stub_bin: Path) -> None:
    result = run_script(stub_bin, "--dry-run")

    assert result.returncode == 0, result.stderr
    assert f"iptables -I INPUT 1 -i sf-br1 -j {PROXY_INPUT}" in rules(result)
    assert f"iptables -I DOCKER-USER 1 -i sf-br1 -j {PROXY_FORWARD}" in rules(result)


def test_proxy_exception_sits_between_established_and_reject(stub_bin: Path) -> None:
    result = run_script(stub_bin, "--dry-run", env={"SF_EGRESS_PROXY": "10.9.8.7:3129"})

    chain = chain_rules(result, PROXY_INPUT)
    assert result.returncode == 0, result.stderr
    assert len(chain) == 3
    assert "--ctstate ESTABLISHED,RELATED -j RETURN" in chain[0]
    assert chain[1].endswith("-p tcp -d 10.9.8.7 --dport 3129 -j RETURN")
    assert "-j REJECT" in chain[2]


def test_forward_return_is_limited_to_the_proxy_port(stub_bin: Path) -> None:
    result = run_script(stub_bin, "--dry-run", env={"SF_EGRESS_PROXY": "10.9.8.7:3129"})

    chain = chain_rules(result, PROXY_FORWARD)
    assert result.returncode == 0, result.stderr
    assert len(chain) == 3
    assert chain[1].endswith("-p tcp -d 10.9.8.7 --dport 3129 -j RETURN")
    assert not any(r.endswith("-d 10.9.8.7 -j RETURN") for r in chain)
    assert "tcp 10.9.8.7:3129 on INPUT and FORWARD" in result.stdout


def test_bare_run_no_longer_defaults_to_loopback(
    stub_bin: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delitem(_DEFAULT_ENV, "SF_EGRESS_PROXY")
    env_file = tmp_path / "sandfort.env"
    env_file.write_text("OTHER=1\n")

    result = run_script(stub_bin, "--dry-run", env={"SF_ENV_FILE": str(env_file)})

    # A bare dry run on a fresh host no longer silently builds loopback rules: it names the
    # placeholder gateway endpoint it used and says the real run reads the created network.
    assert result.returncode == 0
    assert "placeholder endpoint 172.18.0.1:3128" in result.stdout
    assert "127.0.0.1" not in "\n".join(chain_rules(result, PROXY_FORWARD))


def test_loopback_override_restores_the_loopback_rules(stub_bin: Path) -> None:
    result = run_script(
        stub_bin,
        "--dry-run",
        env={"SF_EGRESS_PROXY": "127.0.0.1:3128", "SF_ALLOW_LOOPBACK_PROXY": "1"},
    )

    forward = chain_rules(result, PROXY_FORWARD)
    assert result.returncode == 0, result.stderr
    assert any("-d 127.0.0.1 --dport 3128 -j RETURN" in r for r in forward)


def test_port_variable_applies_to_a_bare_proxy_address(stub_bin: Path) -> None:
    result = run_script(
        stub_bin,
        "--dry-run",
        env={"SF_EGRESS_PROXY": "10.9.8.7", "SF_EGRESS_PROXY_PORT": "8080"},
    )

    assert result.returncode == 0, result.stderr
    guard = chain_rules(result, PROXY_INPUT)
    assert any("-d 10.9.8.7 --dport 8080 -j RETURN" in r for r in guard)


def test_proxy_address_without_any_port_dies(stub_bin: Path) -> None:
    result = run_script(stub_bin, "--dry-run", env={"SF_EGRESS_PROXY": "10.9.8.7"})

    assert result.returncode != 0
    assert "SF_EGRESS_PROXY_PORT" in result.stderr
    assert rules(result) == []


def test_conflicting_ports_die(stub_bin: Path) -> None:
    result = run_script(
        stub_bin,
        "--dry-run",
        env={"SF_EGRESS_PROXY": "10.9.8.7:3129", "SF_EGRESS_PROXY_PORT": "3130"},
    )

    assert result.returncode != 0
    assert "differs" in result.stderr


def test_empty_default_bridge_skips_docker0_rules(stub_bin: Path) -> None:
    result = run_script(stub_bin, "--dry-run", env={"SF_DEFAULT_BRIDGE_IFACE": ""})

    assert result.returncode == 0, result.stderr
    assert "skipping the docker0" in result.stdout
    assert "docker0" not in "\n".join(rules(result))
    assert "iptables -I INPUT 1 -i sf-br0 -j SANDFORT-HOST-GUARD" in rules(result)


def test_default_bridge_is_hooked_when_unset(stub_bin: Path) -> None:
    result = run_script(stub_bin, "--dry-run")

    assert "iptables -I INPUT 1 -i docker0 -j SANDFORT-HOST-GUARD" in rules(result)


def test_missing_interface_dies_outside_dry_run(stub_bin: Path) -> None:
    result = run_script(stub_bin, env={"STUB_MISSING_IFACE": "sf-br1"})

    assert result.returncode != 0
    assert "interface sf-br1 does not exist" in result.stderr
    assert not any(r.startswith("iptables -A") for r in rules(result))


def test_missing_interface_only_warns_in_dry_run(stub_bin: Path) -> None:
    result = run_script(stub_bin, "--dry-run", env={"STUB_MISSING_IFACE": "sf-br1"})

    assert result.returncode == 0, result.stderr
    assert "warning: interface sf-br1 does not exist" in result.stdout


BUILD_CHAIN = "SANDFORT-EGRESS-BUILD"
RESOLVECTL_STUB = (
    "printf 'Link 2 (eth0)\\n"
    "    Current DNS Server: 10.43.0.10\\n"
    "           DNS Servers: 10.43.0.10\\n'\n"
)


def add_stub(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def test_build_dns_return_rules_only_on_default_bridge_before_reject(stub_bin: Path) -> None:
    add_stub(stub_bin, "resolvectl", RESOLVECTL_STUB)

    result = run_script(stub_bin, "--dry-run")

    build = chain_rules(result, BUILD_CHAIN)
    plain = chain_rules(result, "SANDFORT-EGRESS")
    assert result.returncode == 0, result.stderr
    udp = "iptables -A SANDFORT-EGRESS-BUILD -p udp -d 10.43.0.10 --dport 53 -j RETURN"
    tcp = "iptables -A SANDFORT-EGRESS-BUILD -p tcp -d 10.43.0.10 --dport 53 -j RETURN"
    assert udp in rules(result) and tcp in rules(result)
    first_reject = next(i for i, r in enumerate(build) if "-j REJECT" in r)
    assert max(i for i, r in enumerate(build) if "--dport 53" in r) < first_reject
    assert not any("--dport 53" in r for r in plain)
    assert "iptables -I DOCKER-USER 1 -i docker0 -j SANDFORT-EGRESS-BUILD" in rules(result)
    assert "iptables -I DOCKER-USER 1 -i sf-br0 -j SANDFORT-EGRESS" in rules(result)
    assert "build DNS resolvers (default bridge only): 10.43.0.10" in result.stdout


def test_build_dns_override_replaces_discovery(stub_bin: Path) -> None:
    add_stub(stub_bin, "resolvectl", RESOLVECTL_STUB)

    result = run_script(stub_bin, "--dry-run", env={"SF_BUILD_DNS": "10.1.2.3 10.1.2.4"})

    joined = "\n".join(rules(result))
    assert result.returncode == 0, result.stderr
    assert "-d 10.1.2.3 --dport 53 -j RETURN" in joined
    assert "-d 10.1.2.4 --dport 53 -j RETURN" in joined
    assert "10.43.0.10" not in joined


def test_build_dns_override_rejects_non_addresses(stub_bin: Path) -> None:
    result = run_script(stub_bin, "--dry-run", env={"SF_BUILD_DNS": "dns.internal"})

    assert result.returncode != 0
    assert "SF_BUILD_DNS" in result.stderr


def test_no_build_dns_rules_when_default_bridge_is_skipped(stub_bin: Path) -> None:
    add_stub(stub_bin, "resolvectl", RESOLVECTL_STUB)

    result = run_script(stub_bin, "--dry-run", env={"SF_DEFAULT_BRIDGE_IFACE": ""})

    assert result.returncode == 0, result.stderr
    assert "--dport 53" not in "\n".join(rules(result))
    assert BUILD_CHAIN not in "\n".join(rules(result))
