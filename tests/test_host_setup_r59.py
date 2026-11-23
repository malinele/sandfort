"""deploy/host-setup.sh: the egress proxy endpoint never defaults to loopback silently.

Round 59 (MAJOR-1): the script ran without SF_EGRESS_PROXY and built the INPUT and FORWARD
exceptions for 127.0.0.1:3128, an address no sandbox packet carries. The script now derives the
endpoint from the compose environment file, else from the egress network gateway, and refuses
loopback. Same approach as tests/test_host_setup_r58.py: --dry-run under stub executables.
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
REDEPLOY = DEPLOY / "redeploy-beta.sh"

needs_private_ops = pytest.mark.skipif(
    not REDEPLOY.is_file(),
    reason="private ops script not present in public tree",
)

_IPTABLES_STUB = (
    'if [ "$1 $2 $3" = "-n -L DOCKER-USER" ]; then exit 0; fi\n'
    'if [ "$1" = "-n" ]; then exit 1; fi\n'
    "exit 0\n"
)
# The network does not exist yet (plain inspect fails) unless STUB_NETWORK_EXISTS is set (then
# every inspect answers "true", which also satisfies the managed-label check). The gateway
# template query answers with STUB_GATEWAY when the test sets it.
_DOCKER_STUB = (
    'case "$*" in\n'
    '  *IPAM*) [ -n "${STUB_GATEWAY:-}" ] && { echo "$STUB_GATEWAY"; exit 0; }; exit 1 ;;\n'
    '  "network inspect"*) [ -n "${STUB_NETWORK_EXISTS:-}" ] && { echo true; exit 0; }\n'
    "    exit 1 ;;\n"
    "esac\n"
    "exit 0\n"
)
STUBS = {
    "uname": "echo Linux\n",
    "id": "echo 0\n",
    "docker": _DOCKER_STUB,
    "ip": "exit 0\n",
    "iptables": _IPTABLES_STUB,
    "ip6tables": _IPTABLES_STUB,
}

PROXY_INPUT = "SANDFORT-HOST-GUARD-PROXY"
PROXY_FORWARD = "SANDFORT-EGRESS-PROXY"
ENV_KEY = "SANDFORT_EGRESS_PROXY_ADDRESS"

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


def write_env(tmp_path: Path, *lines: str) -> Path:
    env_file = tmp_path / "sandfort.env"
    env_file.write_text("\n".join(lines) + "\n")
    return env_file


def run_script(
    stub_bin: Path, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    base = {k: v for k, v in os.environ.items() if not k.startswith(("SF_", "DRY_RUN", "STUB_"))}
    base["PATH"] = f"{stub_bin}:/usr/bin:/bin"
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


def proxy_returns(result: subprocess.CompletedProcess[str]) -> list[str]:
    """The tcp RETURN exceptions on both proxy chains (INPUT guard and FORWARD)."""
    return [
        r
        for r in rules(result)
        if r.startswith((f"iptables -A {PROXY_INPUT} ", f"iptables -A {PROXY_FORWARD} "))
        and "-p tcp" in r
    ]


# 1. Env file source


def test_env_file_variable_supplies_address_and_port(stub_bin: Path, tmp_path: Path) -> None:
    env_file = write_env(tmp_path, f"{ENV_KEY}=10.20.30.40:3129")

    result = run_script(stub_bin, env={"SF_ENV_FILE": str(env_file)})

    assert result.returncode == 0, result.stderr
    assert len(proxy_returns(result)) == 2
    assert all("-d 10.20.30.40 --dport 3129 -j RETURN" in r for r in proxy_returns(result))
    assert f"(source: {ENV_KEY} in {env_file})" in result.stdout


def test_env_file_wins_over_the_gateway(stub_bin: Path, tmp_path: Path) -> None:
    env_file = write_env(tmp_path, f"{ENV_KEY}=10.20.30.40:3129")

    result = run_script(
        stub_bin, env={"SF_ENV_FILE": str(env_file), "STUB_GATEWAY": "172.30.0.1"}
    )

    assert result.returncode == 0, result.stderr
    assert "172.30.0.1" not in "\n".join(proxy_returns(result))
    assert "-d 10.20.30.40 --dport 3129" in proxy_returns(result)[0]


def test_explicit_variable_wins_over_the_env_file(stub_bin: Path, tmp_path: Path) -> None:
    env_file = write_env(tmp_path, f"{ENV_KEY}=10.20.30.40:3129")

    result = run_script(
        stub_bin, env={"SF_ENV_FILE": str(env_file), "SF_EGRESS_PROXY": "10.9.8.7:3130"}
    )

    assert result.returncode == 0, result.stderr
    assert "-d 10.9.8.7 --dport 3130" in proxy_returns(result)[0]
    assert "(source: SF_EGRESS_PROXY)" in result.stdout


def test_env_file_is_grepped_not_sourced(stub_bin: Path, tmp_path: Path) -> None:
    marker = tmp_path / "sourced"
    env_file = write_env(
        tmp_path,
        f"#{ENV_KEY}=1.1.1.1:1",
        f"  {ENV_KEY}=2.2.2.2:2",
        f"OTHER=$(touch {marker})",
        f'{ENV_KEY}="10.20.30.40:3129"',
    )

    result = run_script(stub_bin, env={"SF_ENV_FILE": str(env_file)})

    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    assert "-d 10.20.30.40 --dport 3129" in proxy_returns(result)[0]


def test_named_env_file_that_is_missing_dies(stub_bin: Path, tmp_path: Path) -> None:
    result = run_script(stub_bin, env={"SF_ENV_FILE": str(tmp_path / "absent.env")})

    assert result.returncode != 0
    assert "SF_ENV_FILE" in result.stderr
    assert rules(result) == []


def test_env_file_value_must_be_an_ipv4_address(stub_bin: Path, tmp_path: Path) -> None:
    env_file = write_env(tmp_path, f"{ENV_KEY}=proxy.internal:3128")

    result = run_script(stub_bin, env={"SF_ENV_FILE": str(env_file)})

    assert result.returncode != 0
    assert "IPv4" in result.stderr
    assert rules(result) == []


# 2. Gateway source


def test_gateway_is_used_when_the_env_file_has_no_variable(
    stub_bin: Path, tmp_path: Path
) -> None:
    env_file = write_env(tmp_path, "SANDFORT_API_KEY_PEPPER=x")

    result = run_script(
        stub_bin, env={"SF_ENV_FILE": str(env_file), "STUB_GATEWAY": "172.30.0.1"}
    )

    assert result.returncode == 0, result.stderr
    assert all("-d 172.30.0.1 --dport 3128 -j RETURN" in r for r in proxy_returns(result))
    assert "(source: gateway of docker network sf-egress-net)" in result.stdout


def test_existing_network_without_a_gateway_dies_naming_the_variable(
    stub_bin: Path, tmp_path: Path
) -> None:
    env_file = write_env(tmp_path, "OTHER=1")

    result = run_script(
        stub_bin, env={"SF_ENV_FILE": str(env_file), "STUB_NETWORK_EXISTS": "1"}
    )

    assert result.returncode != 0
    assert "SF_EGRESS_PROXY" in result.stderr
    assert "has no gateway" in result.stderr
    assert "placeholder" not in result.stdout
    assert rules(result) == []


def test_dry_run_on_a_fresh_host_without_a_proxy_source_uses_a_placeholder(
    stub_bin: Path, tmp_path: Path
) -> None:
    """L11: the network is only printed under --dry-run, so it has no gateway to read yet."""
    env_file = write_env(tmp_path, "OTHER=1")

    result = run_script(stub_bin, env={"SF_ENV_FILE": str(env_file)})

    assert result.returncode == 0, result.stderr
    assert "has no gateway" not in result.stderr
    assert "would be read after the network is created" in result.stdout
    assert "placeholder endpoint 172.18.0.1:3128" in result.stdout
    assert "the real run resolves" in result.stdout
    assert len(proxy_returns(result)) == 2
    assert all("-d 172.18.0.1 --dport 3128 -j RETURN" in r for r in proxy_returns(result))
    created = "creating network sf-egress-net"
    assert result.stdout.index(created) < result.stdout.index("placeholder endpoint")


def test_dry_run_placeholder_keeps_the_port_variable(stub_bin: Path, tmp_path: Path) -> None:
    env_file = write_env(tmp_path, "OTHER=1")

    result = run_script(
        stub_bin, env={"SF_ENV_FILE": str(env_file), "SF_EGRESS_PROXY_PORT": "8080"}
    )

    assert result.returncode == 0, result.stderr
    assert all("-d 172.18.0.1 --dport 8080 -j RETURN" in r for r in proxy_returns(result))


def test_gateway_fallback_resolves_after_the_egress_network_is_ensured(
    stub_bin: Path, tmp_path: Path
) -> None:
    """L2: on a fresh host the network does not exist when the endpoint is resolved."""
    env_file = write_env(tmp_path, "OTHER=1")

    result = run_script(
        stub_bin, env={"SF_ENV_FILE": str(env_file), "STUB_GATEWAY": "172.30.0.1"}
    )

    created = "creating network sf-egress-net"
    resolved = "egress proxy endpoint 172.30.0.1:3128"
    assert result.returncode == 0, result.stderr
    assert result.stdout.count(created) == 1
    assert result.stdout.index(created) < result.stdout.index(resolved)


def test_invalid_endpoint_is_refused_before_the_network_is_created(
    stub_bin: Path, tmp_path: Path
) -> None:
    env_file = write_env(tmp_path, f"{ENV_KEY}=127.0.0.1:3128")

    result = run_script(stub_bin, env={"SF_ENV_FILE": str(env_file)})

    assert result.returncode != 0
    assert "creating network" not in result.stdout


def test_egress_network_is_ensured_once_with_an_explicit_endpoint(
    stub_bin: Path, tmp_path: Path
) -> None:
    env_file = write_env(tmp_path, "OTHER=1")

    result = run_script(
        stub_bin, env={"SF_ENV_FILE": str(env_file), "SF_EGRESS_PROXY": "10.9.8.7:3130"}
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.count("creating network sf-egress-net") == 1


# 3. Loopback refusal and override


def test_loopback_from_the_env_file_is_refused(stub_bin: Path, tmp_path: Path) -> None:
    env_file = write_env(tmp_path, f"{ENV_KEY}=127.0.0.1:3128")

    result = run_script(stub_bin, env={"SF_ENV_FILE": str(env_file)})

    assert result.returncode != 0
    assert "SF_EGRESS_PROXY" in result.stderr
    assert "loopback" in result.stderr
    assert rules(result) == []


def test_explicit_loopback_is_refused(stub_bin: Path, tmp_path: Path) -> None:
    env_file = write_env(tmp_path, "OTHER=1")

    result = run_script(
        stub_bin, env={"SF_ENV_FILE": str(env_file), "SF_EGRESS_PROXY": "127.0.0.1:3128"}
    )

    assert result.returncode != 0
    assert "SF_EGRESS_PROXY" in result.stderr
    assert "loopback" in result.stderr


def test_loopback_gateway_is_refused(stub_bin: Path, tmp_path: Path) -> None:
    env_file = write_env(tmp_path, "OTHER=1")

    result = run_script(
        stub_bin, env={"SF_ENV_FILE": str(env_file), "STUB_GATEWAY": "127.0.0.1"}
    )

    assert result.returncode != 0
    assert "loopback" in result.stderr


def test_loopback_override_allows_the_endpoint(stub_bin: Path, tmp_path: Path) -> None:
    env_file = write_env(tmp_path, f"{ENV_KEY}=127.0.0.1:3128")

    result = run_script(
        stub_bin, env={"SF_ENV_FILE": str(env_file), "SF_ALLOW_LOOPBACK_PROXY": "1"}
    )

    assert result.returncode == 0, result.stderr
    assert all("-d 127.0.0.1 --dport 3128 -j RETURN" in r for r in proxy_returns(result))
    assert "warning: loopback proxy allowed" in result.stdout


# 4. Port precedence


@pytest.mark.parametrize(
    ("env_value", "var_port", "expected"),
    [
        ("10.20.30.40", None, "3128"),  # derived address, no port anywhere: default
        ("10.20.30.40:3129", None, "3129"),  # port carried by the value
        ("10.20.30.40", "8080", "8080"),  # SF_EGRESS_PROXY_PORT for a bare address
        ("10.20.30.40:3129", "3129", "3129"),  # agreeing duplicates are fine
    ],
)
def test_env_file_port_precedence(
    stub_bin: Path, tmp_path: Path, env_value: str, var_port: str | None, expected: str
) -> None:
    env_file = write_env(tmp_path, f"{ENV_KEY}={env_value}")
    env = {"SF_ENV_FILE": str(env_file)}
    if var_port:
        env["SF_EGRESS_PROXY_PORT"] = var_port

    result = run_script(stub_bin, env=env)

    assert result.returncode == 0, result.stderr
    assert all(f"--dport {expected} -j RETURN" in r for r in proxy_returns(result))


def test_conflicting_env_file_and_variable_ports_die(stub_bin: Path, tmp_path: Path) -> None:
    env_file = write_env(tmp_path, f"{ENV_KEY}=10.20.30.40:3129")

    result = run_script(
        stub_bin, env={"SF_ENV_FILE": str(env_file), "SF_EGRESS_PROXY_PORT": "3130"}
    )

    assert result.returncode != 0
    assert "differs" in result.stderr


def test_gateway_port_comes_from_the_port_variable(stub_bin: Path, tmp_path: Path) -> None:
    env_file = write_env(tmp_path, "OTHER=1")

    result = run_script(
        stub_bin,
        env={
            "SF_ENV_FILE": str(env_file),
            "STUB_GATEWAY": "172.30.0.1",
            "SF_EGRESS_PROXY_PORT": "8080",
        },
    )

    assert result.returncode == 0, result.stderr
    assert all("-d 172.30.0.1 --dport 8080 -j RETURN" in r for r in proxy_returns(result))


def test_explicit_address_without_any_port_still_dies(stub_bin: Path, tmp_path: Path) -> None:
    env_file = write_env(tmp_path, "OTHER=1")

    result = run_script(
        stub_bin, env={"SF_ENV_FILE": str(env_file), "SF_EGRESS_PROXY": "10.9.8.7"}
    )

    assert result.returncode != 0
    assert "SF_EGRESS_PROXY_PORT" in result.stderr


# 5. Summary line


def test_summary_names_endpoint_and_gateway_without_warning_when_equal(
    stub_bin: Path, tmp_path: Path
) -> None:
    env_file = write_env(tmp_path, f"{ENV_KEY}=172.30.0.1:3128")

    result = run_script(
        stub_bin, env={"SF_ENV_FILE": str(env_file), "STUB_GATEWAY": "172.30.0.1"}
    )

    assert result.returncode == 0, result.stderr
    assert "proxy endpoint 172.30.0.1:3128; sf-egress-net gateway 172.30.0.1" in result.stdout
    assert "WARNING" not in result.stdout


def test_summary_warns_loudly_when_endpoint_and_gateway_differ(
    stub_bin: Path, tmp_path: Path
) -> None:
    env_file = write_env(tmp_path, f"{ENV_KEY}=10.20.30.40:3129")

    result = run_script(
        stub_bin, env={"SF_ENV_FILE": str(env_file), "STUB_GATEWAY": "172.30.0.1"}
    )

    warning = next(ln for ln in result.stdout.splitlines() if "WARNING" in ln)
    assert result.returncode == 0, result.stderr
    assert "10.20.30.40" in warning
    assert "172.30.0.1" in warning
    assert "proxy endpoint 10.20.30.40:3129; sf-egress-net gateway 172.30.0.1" in result.stdout


def test_summary_says_gateway_unknown_before_the_network_exists(
    stub_bin: Path, tmp_path: Path
) -> None:
    env_file = write_env(tmp_path, f"{ENV_KEY}=10.20.30.40:3129")

    result = run_script(stub_bin, env={"SF_ENV_FILE": str(env_file)})

    assert result.returncode == 0, result.stderr
    assert "sf-egress-net gateway unknown" in result.stdout
    assert "WARNING" not in result.stdout


# 6. Redeploy reminder


@needs_private_ops
@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_redeploy_reminder_command_carries_the_proxy_from_the_env_file() -> None:
    result = subprocess.run(
        ["bash", str(REDEPLOY), "--print-host-setup-command"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    command = result.stdout.strip()
    assert result.returncode == 0, result.stderr
    assert "SF_EGRESS_PROXY=" in command
    assert f"grep '^{ENV_KEY}=' sandfort.env" in command
    assert command.startswith("cd /home/sandfort/sandfort/deploy && sudo ")
    assert command.endswith("sh host-setup.sh")
    assert command.index("SF_EGRESS_PROXY=") < command.index("host-setup.sh")


def _reminder_proxy_value(tmp_path: Path, env_lines: list[str]) -> str:
    """Run the printed reminder for real: a stub sudo and host-setup.sh echo SF_EGRESS_PROXY."""
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "sandfort.env").write_bytes(("\n".join(env_lines) + "\n").encode())
    (deploy / "host-setup.sh").write_text('printf "%s" "${SF_EGRESS_PROXY-unset}"\n')
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    sudo = bin_dir / "sudo"
    sudo.write_text('#!/bin/sh\nexec env "$@"\n')
    sudo.chmod(sudo.stat().st_mode | stat.S_IXUSR)
    printed = subprocess.run(
        ["bash", str(REDEPLOY), "--print-host-setup-command"],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    ).stdout.strip()
    command = printed.replace("cd /home/sandfort/sandfort/deploy &&", f"cd {deploy} &&", 1)
    result = subprocess.run(
        ["sh", "-c", command],
        capture_output=True,
        text=True,
        env={"PATH": f"{bin_dir}:/usr/bin:/bin"},
        timeout=30,
        check=True,
    )
    return result.stdout


@needs_private_ops
@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize(
    ("env_line", "expected"),
    [
        (f"{ENV_KEY}=10.20.30.40", "10.20.30.40:3128"),  # no port: the default is appended
        (f"{ENV_KEY}=10.20.30.40:3129", "10.20.30.40:3129"),  # a port stays
        (f'{ENV_KEY}="10.20.30.40"', "10.20.30.40:3128"),  # double quotes stripped
        (f"{ENV_KEY}='10.20.30.40:3129'", "10.20.30.40:3129"),  # single quotes stripped
        (f"{ENV_KEY}=10.20.30.40\r", "10.20.30.40:3128"),  # CRLF env file
        (f"{ENV_KEY}=http://10.20.30.40", "10.20.30.40:3128"),  # scheme stripped, port added
        (f"{ENV_KEY}=10.20.30.40:3129 # proxy", "10.20.30.40:3129"),  # comment stripped
        (f"{ENV_KEY}=", ""),  # empty value: host-setup derives the endpoint itself
        ("OTHER=1", ""),  # variable absent
    ],
)
def test_redeploy_reminder_passes_a_parsable_proxy_value(
    tmp_path: Path, env_line: str, expected: str
) -> None:
    value = _reminder_proxy_value(tmp_path, [env_line])

    assert value == expected


@needs_private_ops
@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_redeploy_reminder_uses_the_last_assignment(tmp_path: Path) -> None:
    value = _reminder_proxy_value(
        tmp_path, [f"{ENV_KEY}=1.1.1.1:1", f'{ENV_KEY}="10.20.30.40"']
    )

    assert value == "10.20.30.40:3128"


@needs_private_ops
def test_redeploy_prints_the_reminder_after_the_api_deploy_and_in_dry_run() -> None:
    text = REDEPLOY.read_text()
    api_start = text.index("deploy_api() {")
    api_body = text[api_start : text.index("\n}\n", api_start)]

    assert "reminder: if the egress proxy address or port changed" in text
    assert "$(host_setup_command)" in text
    assert api_body.count("remind_host_setup") == 2
    assert api_body.rindex("remind_host_setup") > api_body.index("verify_live_spec")
