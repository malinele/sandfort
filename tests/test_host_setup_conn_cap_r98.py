"""deploy/host-setup.sh and deploy/egress-conn-cap.sh: the host connection cap (B16, round 98).

One rule sits in SANDFORT-EGRESS, before its final RETURN: a new flow from a sandbox address on
the sandbox bridge is sent to SANDFORT-CONNCAP once that address already holds the limit of
tracked flows. Dry-run only (apart from the probe test), against stub system executables, as in
tests/test_host_setup_dns_sink_v2.py.
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
HELPER = DEPLOY / "egress-conn-cap.sh"

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

LIMIT_VAR = "SF_SANDBOX_CONN_LIMIT"
CAP_CHAIN = "SANDFORT-CONNCAP"
EGRESS = "SANDFORT-EGRESS"
_CAP_TAIL = (
    "-i sf-br0 -m conntrack --ctstate NEW -m connlimit --connlimit-above 512 "
    "--connlimit-mask {mask} --connlimit-saddr -j SANDFORT-CONNCAP"
)
CAP_RULE_V4 = f"iptables -A {EGRESS} " + _CAP_TAIL.format(mask=32)
CAP_RULE_V6 = f"ip6tables -A {EGRESS} " + _CAP_TAIL.format(mask=128)

pytestmark = pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX sh")


def write_stub(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def stub_bin(tmp_path: Path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in STUBS.items():
        write_stub(bin_dir, name, body)
    return bin_dir


def run_script(
    stub_bin: Path,
    *args: str,
    env: dict[str, str] | None = None,
    dry: bool = True,
) -> subprocess.CompletedProcess[str]:
    base = {
        k: v for k, v in os.environ.items() if not k.startswith(("SF_", "DRY_RUN", "SANDFORT_"))
    }
    base.pop(LIMIT_VAR, None)
    base["PATH"] = f"{stub_bin}:/usr/bin:/bin"
    base["SF_EGRESS_PROXY"] = "10.0.0.5:3128"
    base["SF_DEFAULT_BRIDGE_IFACE"] = ""  # no docker0 rules unless a test asks for them
    base["SF_ENV_FILE"] = str(stub_bin.parent / "absent.env")  # never the developer's file
    base.update(env or {})
    argv = ["sh", str(SCRIPT), *(["--dry-run"] if dry else []), *args]
    return subprocess.run(argv, capture_output=True, text=True, env=base, timeout=30, check=False)


def rules(result: subprocess.CompletedProcess[str]) -> list[str]:
    return [line[2:] for line in result.stdout.splitlines() if line.startswith("+ ")]


def chain_rules(result: subprocess.CompletedProcess[str], chain: str) -> list[str]:
    return [r for r in rules(result) if r.startswith(f"iptables -A {chain} ")]


def v6_rules(result: subprocess.CompletedProcess[str], chain: str) -> list[str]:
    return [r for r in rules(result) if r.startswith(f"ip6tables -A {chain} ")]


def family_rules(result: subprocess.CompletedProcess[str], tool: str) -> list[str]:
    return [r for r in rules(result) if r.startswith(f"{tool} ")]


def connlimit_rules(result: subprocess.CompletedProcess[str], tool: str) -> list[str]:
    return [r for r in family_rules(result, tool) if "connlimit" in r]


def test_helper_exists_and_is_valid_sh() -> None:
    assert HELPER.is_file()
    syntax = subprocess.run(["sh", "-n", str(HELPER)], capture_output=True, text=True, check=False)
    assert syntax.returncode == 0, syntax.stderr


@pytest.mark.parametrize("tool", ["iptables", "ip6tables"])
def test_default_run_creates_the_cap_chain_before_any_jump_to_it(stub_bin: Path, tool: str) -> None:
    result = run_script(stub_bin)

    lines = family_rules(result, tool)
    assert result.returncode == 0, result.stderr
    created = lines.index(f"{tool} -N {CAP_CHAIN}")
    jumps = [i for i, r in enumerate(lines) if f"-j {CAP_CHAIN}" in r]
    assert jumps, "no rule jumps to the cap chain"
    assert created < jumps[0]


def test_cap_chain_logs_then_resets_tcp_then_rejects_the_rest(stub_bin: Path) -> None:
    result = run_script(stub_bin)

    v4 = chain_rules(result, CAP_CHAIN)
    v6 = v6_rules(result, CAP_CHAIN)
    assert result.returncode == 0, result.stderr
    log_rule = "-m limit --limit 1/min --limit-burst 5 -j LOG --log-prefix sandfort-conncap:"
    for chain in (v4, v6):
        assert len(chain) == 3
        assert log_rule in chain[0]
        assert chain[0].endswith("--log-level warning")
        assert chain[1].endswith("-p tcp -j REJECT --reject-with tcp-reset")
    assert v4[2].endswith("-j REJECT --reject-with icmp-admin-prohibited")
    assert v6[2].endswith("-j REJECT --reject-with icmp6-adm-prohibited")


def test_cap_rule_is_second_to_last_in_the_v4_egress_chain(stub_bin: Path) -> None:
    result = run_script(stub_bin)

    chain = chain_rules(result, EGRESS)
    assert result.returncode == 0, result.stderr
    assert chain[-2] == CAP_RULE_V4
    assert chain[-1].endswith("-j RETURN")
    assert "-j REJECT" in chain[-3]


def test_cap_rule_is_second_to_last_in_the_v6_egress_chain(stub_bin: Path) -> None:
    result = run_script(stub_bin)

    chain = v6_rules(result, EGRESS)
    assert result.returncode == 0, result.stderr
    assert chain[-2] == CAP_RULE_V6
    assert chain[-1].endswith("-j RETURN")
    assert "-j REJECT" in chain[-3]


def test_other_chains_get_no_connlimit(stub_bin: Path) -> None:
    result = run_script(stub_bin, env={"SF_DEFAULT_BRIDGE_IFACE": "docker0"})

    assert result.returncode == 0, result.stderr
    for chain in (
        "SANDFORT-EGRESS-BUILD",
        "SANDFORT-EGRESS-PROXY",
        "SANDFORT-HOST-GUARD",
        "SANDFORT-HOST-GUARD-PROXY",
    ):
        both = chain_rules(result, chain) + v6_rules(result, chain)
        assert not [r for r in both if "connlimit" in r], chain
    limited = connlimit_rules(result, "iptables") + connlimit_rules(result, "ip6tables")
    assert not [r for r in limited if "-i docker0" in r]
    assert len(connlimit_rules(result, "iptables")) == 1
    assert len(connlimit_rules(result, "ip6tables")) == 1


def test_limit_from_the_environment_is_used(stub_bin: Path) -> None:
    result = run_script(stub_bin, env={LIMIT_VAR: "2048"})

    assert result.returncode == 0, result.stderr
    for tool in ("iptables", "ip6tables"):
        [rule] = connlimit_rules(result, tool)
        assert "--connlimit-above 2048 " in rule


def test_empty_limit_means_the_default(stub_bin: Path) -> None:
    result = run_script(stub_bin, env={LIMIT_VAR: ""})

    assert result.returncode == 0, result.stderr
    assert chain_rules(result, EGRESS)[-2] == CAP_RULE_V4


def test_zero_turns_the_cap_off(stub_bin: Path) -> None:
    result = run_script(stub_bin, env={LIMIT_VAR: "0"})

    assert result.returncode == 0, result.stderr
    assert not [r for r in rules(result) if "connlimit" in r or CAP_CHAIN in r]
    assert "connection cap: off" in result.stdout


@pytest.mark.parametrize("value", ["abc", "-1", "100001", "1.5", "0512"])
def test_invalid_limit_exits_before_any_rule(stub_bin: Path, value: str) -> None:
    result = run_script(stub_bin, env={LIMIT_VAR: value})

    assert result.returncode != 0
    assert rules(result) == []
    assert LIMIT_VAR in result.stderr


def test_rerun_flushes_the_existing_cap_chain(stub_bin: Path) -> None:
    for name in ("iptables", "ip6tables"):
        write_stub(
            stub_bin,
            name,
            f'if [ "$*" = "-n -L {CAP_CHAIN}" ]; then exit 0; fi\n' + _IPTABLES_STUB,
        )

    result = run_script(stub_bin)

    assert result.returncode == 0, result.stderr
    lines = rules(result)
    for tool in ("iptables", "ip6tables"):
        assert f"{tool} -F {CAP_CHAIN}" in lines
        assert f"{tool} -N {CAP_CHAIN}" not in lines
        assert len(connlimit_rules(result, tool)) == 1
    assert not [r for r in lines if f"-X {CAP_CHAIN}" in r]


def test_missing_helper_skips_the_cap(stub_bin: Path, tmp_path: Path) -> None:
    lone = tmp_path / "lone"
    lone.mkdir()
    shutil.copy(SCRIPT, lone / "host-setup.sh")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SF_", "SANDFORT_"))}
    env.update(PATH=f"{stub_bin}:/usr/bin:/bin", SF_EGRESS_PROXY="10.0.0.5:3128")
    env.update({"SF_DEFAULT_BRIDGE_IFACE": ""})

    result = subprocess.run(
        ["sh", str(lone / "host-setup.sh"), "--dry-run"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "egress-conn-cap.sh not found" in result.stdout
    assert "connection cap: off (egress-conn-cap.sh not found)" in result.stdout
    assert "tracked flows" not in result.stdout
    assert not [r for r in rules(result) if "connlimit" in r]


def test_dry_run_skips_the_probe(stub_bin: Path) -> None:
    result = run_script(stub_bin)

    assert result.returncode == 0, result.stderr
    assert "connlimit probe skipped" in result.stdout
    assert not [line for line in result.stdout.splitlines() if f"{CAP_CHAIN}-PROBE" in line]


def test_missing_connlimit_module_fails_before_any_flush(stub_bin: Path, tmp_path: Path) -> None:
    log = tmp_path / "log"
    body = (
        f'echo "$*" >> {log}\n'
        'for arg in "$@"; do if [ "$arg" = "connlimit" ]; then exit 1; fi; done\n'
        'if [ "$1 $2 $3" = "-n -L DOCKER-USER" ]; then exit 0; fi\n'
        'if [ "$1" = "-n" ]; then exit 1; fi\n'
        "exit 0\n"
    )
    for name in ("iptables", "ip6tables"):
        write_stub(stub_bin, name, body)

    result = run_script(stub_bin, dry=False)

    assert result.returncode != 0
    assert "modprobe xt_connlimit" in result.stderr
    assert f"{LIMIT_VAR}=0" in result.stderr
    logged = log.read_text().splitlines()
    assert not [line for line in logged if line.startswith(f"-F {EGRESS}")]
    assert not [line for line in logged if line.startswith(f"-A {EGRESS} ")]


_CONNLIMIT_FAILS = (
    'for arg in "$@"; do if [ "$arg" = "connlimit" ]; then exit 1; fi; done\n'
    'if [ "$1 $2 $3" = "-n -L DOCKER-USER" ]; then exit 0; fi\n'
    'if [ "$1" = "-n" ]; then exit 1; fi\n'
    "exit 0\n"
)


def test_zero_skips_the_probe_and_still_writes_rules(stub_bin: Path, tmp_path: Path) -> None:
    """With the cap off, a kernel without connlimit must not fail the run (non-dry)."""
    log = tmp_path / "log"
    for name in ("iptables", "ip6tables"):
        write_stub(stub_bin, name, f'echo "$*" >> {log}\n' + _CONNLIMIT_FAILS)

    result = run_script(stub_bin, env={LIMIT_VAR: "0"}, dry=False)

    assert result.returncode == 0, result.stderr
    assert "connection cap: off" in result.stdout
    logged = log.read_text().splitlines()
    assert not [line for line in logged if f"{CAP_CHAIN}-PROBE" in line]
    assert [line for line in logged if line.startswith(f"-A {EGRESS} ")]


@pytest.mark.parametrize("failing", ["iptables", "ip6tables"])
def test_probe_failure_names_the_failing_tool(stub_bin: Path, tmp_path: Path, failing: str) -> None:
    log = tmp_path / "log"
    plain = (
        f'echo "$*" >> {log}\n'
        'if [ "$1 $2 $3" = "-n -L DOCKER-USER" ]; then exit 0; fi\n'
        'if [ "$1" = "-n" ]; then exit 1; fi\n'
        "exit 0\n"
    )
    for name in ("iptables", "ip6tables"):
        body = f'echo "$*" >> {log}\n' + _CONNLIMIT_FAILS if name == failing else plain
        write_stub(stub_bin, name, body)

    result = run_script(stub_bin, dry=False)

    assert result.returncode != 0
    assert f"error: {failing} connlimit" in result.stderr
    logged = log.read_text().splitlines()
    assert not [line for line in logged if line.startswith(f"-F {EGRESS}")]
    assert not [line for line in logged if line.startswith(f"-A {EGRESS} ")]


def test_header_names_the_cap() -> None:
    text = SCRIPT.read_text()

    assert CAP_CHAIN in text
    assert LIMIT_VAR in text
    assert "egress-conn-cap.sh" in text
