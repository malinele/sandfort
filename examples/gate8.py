"""Gate 8: per-sandbox egress allowlist, end to end from a real container.

Proves the proxy path live: the egress proxy runs as a subprocess, one server process (role
``all``) injects the proxy environment into a sandbox created with the allowlist
``["example.com"]``, and the sandbox reaches only that host through the proxy:

* the allowlisted https host can be fetched using only the injected proxy variables;
* a different https host is refused by the proxy (the fetch fails);
* the allowlisted host with a wrong proxy password is refused (the credential is checked).

The host firewall chain (``deploy/host-setup.sh``) is a linux-host concern and is not
exercised here; this gate covers the proxy path only.

Run: .venv/bin/python examples/gate8.py
Requires a local Docker daemon with ``python:3.12-slim`` available and outbound internet access.
A fresh temporary sqlite database is migrated and bootstrapped in-process. Prints one progress
line per step and exits non-zero on any failure; both processes and the database are removed.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

API_PORT = 4201
PROXY_PORT = 4202
API = f"http://127.0.0.1:{API_PORT}"
PROXY_ADDRESS = f"host.docker.internal:{PROXY_PORT}"
EGRESS_SECRET = "gate8-egress-signing-secret-0123456789abcdef"
IMAGE = "python:3.12-slim"
SNAPSHOT_NAME = "gate8-python"
ALLOWED_HOST = "example.com"
DENIED_HOST = "example.org"
PROXY_VARIABLES = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY")
FETCH_TIMEOUT_S = 15
EXEC_TIMEOUT_S = 40
HEALTH_TIMEOUT_S = 40.0
START_WAIT_S = 120.0
DESTROY_TIMEOUT_S = 90.0
GONE_STATES = frozenset({"destroyed", "deleted"})


def check(condition: bool, message: str) -> None:
    """Fail the gate (non-zero exit) unless ``condition`` holds."""
    if not condition:
        raise SystemExit(f"GATE8 FAIL: {message}")


def step(message: str) -> None:
    print(f"CHECK {message}", flush=True)


def wait_health(base: str) -> None:
    deadline = time.time() + HEALTH_TIMEOUT_S
    while time.time() < deadline:
        try:
            if httpx.get(f"{base}/healthz", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    raise SystemExit(f"GATE8 FAIL: {base} did not become healthy")


def provision(env: dict[str, str]) -> str:
    """Migrate and bootstrap in-process; return the platform key."""
    os.environ.update(env)
    from sandfort import admin_cli

    admin_cli.migrate()
    key = admin_cli.bootstrap("Gate8", "gate8")
    check(key.startswith("sf_"), "bootstrap did not return an sf_ key")
    return key


def spawn_proxy(env: dict[str, str]) -> subprocess.Popen[bytes]:
    proxy_env = {
        **env,
        "SANDFORT_EGRESS_SECRET": EGRESS_SECRET,
        "SANDFORT_EGRESS_LISTEN_HOST": "0.0.0.0",  # noqa: S104 - containers must reach it
        "SANDFORT_EGRESS_LISTEN_PORT": str(PROXY_PORT),
    }
    return subprocess.Popen(
        [str(REPO / ".venv" / "bin" / "python"), "-m", "sandfort.egress.proxy"],
        cwd=REPO,
        env=proxy_env,
    )


def spawn_server(env: dict[str, str]) -> subprocess.Popen[bytes]:
    server_env = {
        **env,
        "SANDFORT_ROLE": "all",
        "SANDFORT_PORT": str(API_PORT),
        "SANDFORT_EGRESS_PROXY_ADDRESS": PROXY_ADDRESS,
        "SANDFORT_EGRESS_SECRET": EGRESS_SECRET,
    }
    return subprocess.Popen(
        [str(REPO / ".venv" / "bin" / "python"), "-m", "sandfort.main"],
        cwd=REPO,
        env=server_env,
    )


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def register_snapshot(client: httpx.Client) -> str:
    """Register the public python image as a snapshot; return its id."""
    body = {"image": IMAGE, "name": SNAPSHOT_NAME}
    registered = client.post("/v1/snapshots", json=body, timeout=300)
    check(registered.status_code == 201, f"register -> {registered.status_code} {registered.text}")
    data = registered.json()["data"]
    check(data["state"] == "ready", f"snapshot is {data['state']!r}, not ready")
    return str(data["id"])


def create_started(client: httpx.Client, snapshot_id: str) -> str:
    body = {"snapshot": snapshot_id, "name": "gate8", "egress_allowlist": [ALLOWED_HOST]}
    created = client.post("/v1/sandboxes", json=body)
    check(created.status_code in (200, 201, 202), f"create -> {created.status_code} {created.text}")
    sandbox_id = str(created.json()["data"]["id"])
    deadline = time.time() + START_WAIT_S
    state = "unknown"
    while time.time() < deadline:
        polled = client.get(f"/v1/sandboxes/{sandbox_id}")
        check(polled.status_code == 200, f"poll {sandbox_id} -> {polled.status_code}")
        state = str(polled.json()["data"]["state"])
        if state == "started":
            return sandbox_id
        check(state != "error", f"sandbox {sandbox_id} entered state 'error'")
        time.sleep(0.5)
    raise SystemExit(f"GATE8 FAIL: sandbox {sandbox_id} is {state!r}, not started")


def wait_gone(client: httpx.Client, sandbox_id: str) -> None:
    deadline = time.time() + DESTROY_TIMEOUT_S
    while time.time() < deadline:
        response = client.get(f"/v1/sandboxes/{sandbox_id}")
        if response.status_code == 404:
            return
        if response.status_code == 200 and response.json()["data"]["state"] in GONE_STATES:
            return
        time.sleep(0.5)
    raise SystemExit(f"GATE8 FAIL: sandbox {sandbox_id} was not destroyed in time")


def run_exec(
    client: httpx.Client, sandbox_id: str, command: str, env: dict[str, str] | None = None
) -> dict[str, Any]:
    body: dict[str, Any] = {"command": command, "timeout_s": EXEC_TIMEOUT_S}
    if env:
        body["env"] = env
    response = client.post(f"/v1/sandboxes/{sandbox_id}/toolbox/process/execute", json=body)
    check(response.status_code == 200, f"exec -> {response.status_code} {response.text}")
    result: dict[str, Any] = response.json()["data"]
    return result


def fetch_command(host: str) -> str:
    """Python urllib fetch: honors the proxy variable and tunnels https with CONNECT."""
    code = (
        "import sys, urllib.request\n"
        "try:\n"
        f"    urllib.request.urlopen('https://{host}/', timeout={FETCH_TIMEOUT_S})\n"
        "except Exception as exc:\n"
        "    print(exc, file=sys.stderr)\n"
        "    sys.exit(1)\n"
    )
    return f"python -c {shlex.quote(code)}"


def check_sandbox_variables(client: httpx.Client, sandbox_id: str) -> None:
    """Echo the injected proxy variables (values masked) and assert each names the sandbox."""
    for name in PROXY_VARIABLES:
        result = run_exec(client, sandbox_id, f'printf %s "${name}"')
        value = result["stdout"]
        present = bool(value) and sandbox_id in value and PROXY_ADDRESS in value
        print(f"  {name}: {'present' if present else 'MISSING'} (value masked)", flush=True)
        check(result["exit_code"] == 0, f"echo {name} exited {result['exit_code']}")
        check(present, f"{name} is missing or does not carry the sandbox id and proxy address")


def run_gate(key: str) -> None:
    headers = {"Authorization": f"Bearer {key}"}
    with httpx.Client(base_url=API, headers=headers, timeout=60) as client:
        sandbox_id = ""
        try:
            snapshot_id = register_snapshot(client)
            step(f"snapshot {snapshot_id} registered from {IMAGE}")
            sandbox_id = create_started(client, snapshot_id)
            step(f"sandbox {sandbox_id} started with allowlist [{ALLOWED_HOST!r}]")

            spec = client.get(f"/v1/sandboxes/{sandbox_id}").json()["data"]
            read_back = spec.get("egress_allowlist")
            check(read_back == [ALLOWED_HOST], f"allowlist not read back: {spec}")
            step("sandbox spec took effect: egress_allowlist read back through the api")

            check_sandbox_variables(client, sandbox_id)
            step("proxy variables are present in the sandbox and carry its id")

            allowed = run_exec(client, sandbox_id, fetch_command(ALLOWED_HOST))
            print(f"  allowlisted fetch: exit {allowed['exit_code']} {allowed['stderr']!r}")
            check(allowed["exit_code"] == 0, f"allowlisted fetch failed: {allowed}")
            step(f"https://{ALLOWED_HOST} fetched through the proxy")

            denied = run_exec(client, sandbox_id, fetch_command(DENIED_HOST))
            print(f"  non-allowlisted fetch: exit {denied['exit_code']} {denied['stderr']!r}")
            check(denied["exit_code"] != 0, f"fetch of {DENIED_HOST} unexpectedly succeeded")
            step(f"https://{DENIED_HOST} refused: not on the allowlist")

            bad_url = f"http://{sandbox_id}:wrong-password@{PROXY_ADDRESS}"
            wrong = dict.fromkeys(PROXY_VARIABLES, bad_url)
            forged = run_exec(client, sandbox_id, fetch_command(ALLOWED_HOST), env=wrong)
            print(f"  wrong-password fetch: exit {forged['exit_code']} {forged['stderr']!r}")
            check(forged["exit_code"] != 0, "fetch with a wrong proxy password succeeded")
            step("allowlisted host refused with a wrong proxy password: credential is checked")
        finally:
            if sandbox_id:
                client.delete(f"/v1/sandboxes/{sandbox_id}")
                wait_gone(client, sandbox_id)
        step("sandbox deleted and destroyed")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="sandfort-gate8-")
    db_path = os.path.join(tmp, "gate8.db")
    processes: list[subprocess.Popen[bytes]] = []
    try:
        env = {
            **os.environ,
            "PYTHONPATH": str(REPO / "src"),
            "SANDFORT_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "SANDFORT_DRIVER": "docker",
            "SANDFORT_API_KEY_PEPPER": os.urandom(16).hex(),
        }
        key = provision(env)
        step("database migrated and org bootstrapped")

        print("NOTE host firewall chain (deploy/host-setup.sh) is linux-only; proxy path only.")
        processes.append(spawn_proxy(env))
        time.sleep(1.0)
        check(processes[0].poll() is None, "egress proxy exited at startup")
        step(f"egress proxy listening on 0.0.0.0:{PROXY_PORT}")

        processes.append(spawn_server(env))
        wait_health(API)
        step(f"server healthy; sandboxes reach the proxy at {PROXY_ADDRESS}")

        run_gate(key)
        print("GATE8 PASS", flush=True)
        return 0
    finally:
        for process in processes:
            stop(process)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
