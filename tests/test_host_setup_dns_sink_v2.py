"""deploy/host-setup.sh and deploy/egress-dns-sink.sh: the DNS sink exception (D6).

Egress v2 round 4 (docs/egress-v2-design.md section 6.2). The only new host rule is udp and
tcp port 53 to the sink address, in SANDFORT-HOST-GUARD-PROXY, before the final REJECT.
Dry-run only, against stub system executables, as in tests/test_host_setup_r58.py.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"
SCRIPT = DEPLOY / "host-setup.sh"
HELPER = DEPLOY / "egress-dns-sink.sh"

_IPTABLES_STUB = (
    'if [ "$1 $2 $3" = "-n -L DOCKER-USER" ]; then exit 0; fi\n'
    'if [ "$1" = "-n" ]; then exit 1; fi\n'
    "exit 0\n"
)
STUBS = {
    "uname": "echo Linux\n",
    "id": "echo 0\n",
    "docker": '[ "$1 $2" = "network inspect" ] && exit 1\nexit 0\n',
    "ip": "exit 0\n",
    "iptables": _IPTABLES_STUB,
    "ip6tables": _IPTABLES_STUB,
}

PROXY_INPUT = "SANDFORT-HOST-GUARD-PROXY"
SINK = "172.30.0.1"
SINK_VAR = "SANDFORT_EGRESS_DNS_SINK_ADDRESS"

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


def run_script(
    stub_bin: Path, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    base = {
        k: v for k, v in os.environ.items() if not k.startswith(("SF_", "DRY_RUN", "SANDFORT_"))
    }
    base["PATH"] = f"{stub_bin}:/usr/bin:/bin"
    base["SF_EGRESS_PROXY"] = "10.0.0.5:3128"
    base["SF_DEFAULT_BRIDGE_IFACE"] = ""  # no docker0 rules, so no build-DNS port 53 lines
    base["SF_ENV_FILE"] = str(stub_bin.parent / "absent.env")  # never the developer's file
    base.update(env or {})
    return subprocess.run(
        ["sh", str(SCRIPT), "--dry-run", *args],
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


def port53_rules(result: subprocess.CompletedProcess[str]) -> list[str]:
    return [r for r in rules(result) if "--dport 53" in r]


def test_helper_exists_and_is_valid_sh() -> None:
    assert HELPER.is_file()
    syntax = subprocess.run(["sh", "-n", str(HELPER)], capture_output=True, text=True, check=False)
    assert syntax.returncode == 0, syntax.stderr


def test_d6_dry_run_prints_only_udp_and_tcp_53_to_the_sink(stub_bin: Path) -> None:
    result = run_script(stub_bin, env={SINK_VAR: SINK})

    assert result.returncode == 0, result.stderr
    assert port53_rules(result) == [
        f"iptables -A {PROXY_INPUT} -p udp -d {SINK} --dport 53 -j RETURN",
        f"iptables -A {PROXY_INPUT} -p tcp -d {SINK} --dport 53 -j RETURN",
    ]


def test_sink_exception_sits_between_the_proxy_rule_and_reject(stub_bin: Path) -> None:
    result = run_script(stub_bin, env={SINK_VAR: SINK})

    chain = chain_rules(result, PROXY_INPUT)
    assert result.returncode == 0, result.stderr
    assert len(chain) == 5
    assert "--ctstate ESTABLISHED,RELATED -j RETURN" in chain[0]
    assert chain[1].endswith("-p tcp -d 10.0.0.5 --dport 3128 -j RETURN")
    assert "-p udp" in chain[2] and "-p tcp" in chain[3]
    assert "-j REJECT" in chain[4]


def test_sink_exception_is_not_added_to_any_other_chain(stub_bin: Path) -> None:
    result = run_script(stub_bin, env={SINK_VAR: SINK})

    outside = [r for r in port53_rules(result) if f"-A {PROXY_INPUT} " not in r]
    assert outside == []
    assert not any(r.startswith("ip6tables") and "--dport 53" in r for r in rules(result))


def test_unset_sink_adds_nothing_and_says_so(stub_bin: Path) -> None:
    result = run_script(stub_bin)

    assert result.returncode == 0, result.stderr
    assert port53_rules(result) == []
    assert len(chain_rules(result, PROXY_INPUT)) == 3
    assert f"no DNS sink address ({SINK_VAR} is unset)" in result.stdout


def test_sink_address_is_read_from_the_env_file(stub_bin: Path, tmp_path: Path) -> None:
    env_file = tmp_path / "sandfort.env"
    env_file.write_text(f"OTHER=1\n{SINK_VAR}={SINK}\n")

    result = run_script(stub_bin, env={"SF_ENV_FILE": str(env_file)})

    assert result.returncode == 0, result.stderr
    assert f"iptables -A {PROXY_INPUT} -p udp -d {SINK} --dport 53 -j RETURN" in rules(result)
    assert f"in {env_file}" in result.stdout


def test_environment_variable_wins_over_the_env_file(stub_bin: Path, tmp_path: Path) -> None:
    env_file = tmp_path / "sandfort.env"
    env_file.write_text(f"{SINK_VAR}=172.31.0.1\n")

    result = run_script(stub_bin, env={"SF_ENV_FILE": str(env_file), SINK_VAR: SINK})

    assert result.returncode == 0, result.stderr
    assert all(f"-d {SINK} " in r for r in port53_rules(result))
    assert len(port53_rules(result)) == 2


def test_sink_with_port_53_is_accepted(stub_bin: Path) -> None:
    result = run_script(stub_bin, env={SINK_VAR: f"{SINK}:53"})

    assert result.returncode == 0, result.stderr
    assert len(port53_rules(result)) == 2


@pytest.mark.parametrize(
    "value", [f"{SINK}:5353", "dns.example.com", "fd00::1", "300.1.1.1", f"{SINK}:"]
)
def test_invalid_sink_address_dies_before_any_rule_is_printed(stub_bin: Path, value: str) -> None:
    result = run_script(stub_bin, env={SINK_VAR: value})

    assert result.returncode == 1
    assert SINK_VAR in result.stderr
    assert port53_rules(result) == []


def test_summary_names_the_sink_exception(stub_bin: Path) -> None:
    result = run_script(stub_bin, env={SINK_VAR: SINK})

    assert f"udp and tcp 53 to {SINK}" in result.stdout


def test_missing_helper_skips_the_exception_and_warns(stub_bin: Path, tmp_path: Path) -> None:
    lone = tmp_path / "lone"
    lone.mkdir()
    shutil.copy(SCRIPT, lone / "host-setup.sh")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SF_", "SANDFORT_"))}
    env.update(PATH=f"{stub_bin}:/usr/bin:/bin", SF_EGRESS_PROXY="10.0.0.5:3128")
    env.update({SINK_VAR: SINK, "SF_DEFAULT_BRIDGE_IFACE": ""})

    result = subprocess.run(
        ["sh", str(lone / "host-setup.sh"), "--dry-run"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert port53_rules(result) == []
    assert "egress-dns-sink.sh not found" in result.stdout


def create_commands(result: subprocess.CompletedProcess[str]) -> list[str]:
    return [r for r in rules(result) if r.startswith("docker network create")]


def test_the_egress_network_is_created_with_ipv6_explicitly_off(stub_bin: Path) -> None:
    result = run_script(stub_bin)

    assert result.returncode == 0, result.stderr
    [egress] = [c for c in create_commands(result) if c.endswith(" sf-egress-net")]
    assert "--ipv6=false" in egress.split()


def test_the_main_network_create_is_unchanged(stub_bin: Path) -> None:
    result = run_script(stub_bin)

    [main] = [c for c in create_commands(result) if c.endswith(" sf-net")]
    assert "--ipv6=false" not in main
