"""Gate 9: cross-node toolbox routing, end to end against two real server processes.

Two server processes (role ``all``, nodes ``alpha`` and ``beta``) share one temporary sqlite
database and the local Docker daemon. Both carry the same routing secret (generated per run),
each advertises its own ``http://127.0.0.1:<port>`` internal url, jobs mode is on (without it
the lifecycle runs inline and placement is bypassed) and the warm pool is off. Sandboxes are
created through alpha until one is stamped with node beta. Then, through alpha only, against
that beta-owned sandbox:

* an exec returns its output;
* a file uploaded through alpha downloads back byte-identical;
* git init (exec), git add and git commit (git toolbox) produce a sha and a clean tree;
* an async command's SSE logs are followed to the exit event;
* an interactive terminal echoes a line over the websocket and resizes.

Finally beta is stopped and a toolbox call for its sandbox through alpha must answer the
standard envelope with status 503, code ``NODE_UNAVAILABLE`` and a ``Retry-After`` header. Beta
is then started again so its sandboxes can be deleted, and every sandbox is waited on until
destroyed.

Run: .venv/bin/python examples/gate9.py
Requires a local Docker daemon with ``alpine:3.20`` available and outbound network access (the
git step runs ``apk add git`` inside the sandbox). A fresh temporary sqlite database is migrated
and bootstrapped in-process. Prints one progress line per step and exits non-zero on any
failure; both processes and the database are removed.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import httpx
from websockets.asyncio.client import connect

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

ALPHA_PORT = 4203
BETA_PORT = 4204
ALPHA = "alpha"
BETA = "beta"
PORTS = {ALPHA: ALPHA_PORT, BETA: BETA_PORT}
API = f"http://127.0.0.1:{ALPHA_PORT}"
IMAGE = "alpine:3.20"
MAX_SANDBOXES = 8
HEARTBEAT_INTERVAL_S = "1"
HEALTH_TIMEOUT_S = 40.0
REGISTER_TIMEOUT_S = 30.0
START_WAIT_S = 180.0
DESTROY_TIMEOUT_S = 90.0
EXEC_TIMEOUT_S = 120
FOLLOW_TIMEOUT_S = 60.0
PTY_TIMEOUT_S = 20.0
GONE_STATES = frozenset({"destroyed", "deleted"})
UPLOAD_PATH = "/work/payload.bin"
UPLOAD_BYTES = 300_000
REPO_PATH = "/work/repo"
PTY_ROWS = 30
PTY_COLS = 100
EXEC_PROBE = "echo gate9-$((20 + 22))"
PTY_MARKER = "gate9-pty-42"

Processes = dict[str, "subprocess.Popen[bytes]"]


def check(condition: bool, message: str) -> None:
    """Fail the gate (non-zero exit) unless ``condition`` holds."""
    if not condition:
        raise SystemExit(f"GATE9 FAIL: {message}")


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
    raise SystemExit(f"GATE9 FAIL: {base} did not become healthy")


def provision(env: dict[str, str]) -> str:
    """Migrate and bootstrap in-process; return the platform key."""
    os.environ.update(env)
    from sandfort import admin_cli

    admin_cli.migrate()
    key = admin_cli.bootstrap("Gate9", "gate9")
    check(key.startswith("sf_"), "bootstrap did not return an sf_ key")
    return key


def node_url(node_id: str) -> str:
    return f"http://127.0.0.1:{PORTS[node_id]}"


def spawn(node_id: str, env: dict[str, str]) -> subprocess.Popen[bytes]:
    server_env = {
        **env,
        "SANDFORT_ROLE": "all",
        "SANDFORT_PORT": str(PORTS[node_id]),
        "SANDFORT_NODE_ID": node_id,
        "SANDFORT_NODE_INTERNAL_URL": node_url(node_id),
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


def list_nodes(client: httpx.Client) -> dict[str, dict[str, Any]]:
    response = client.get("/v1/nodes")
    check(response.status_code == 200, f"list nodes -> {response.status_code} {response.text}")
    return {node["id"]: node for node in response.json()["data"]}


def advertised_addresses(db_path: str) -> dict[str, str]:
    """Read the advertised address per node (``GET /v1/nodes`` does not carry it)."""
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("SELECT id, internal_url FROM nodes").fetchall()
    return {str(node): str(url) for node, url in rows}


def wait_registered(client: httpx.Client, db_path: str) -> None:
    deadline = time.time() + REGISTER_TIMEOUT_S
    while time.time() < deadline:
        nodes = list_nodes(client)
        addresses = advertised_addresses(db_path)
        fresh = all(name in nodes and not nodes[name]["stale"] for name in PORTS)
        routable = all(addresses.get(name) == node_url(name) for name in PORTS)
        if fresh and routable:
            return
        time.sleep(0.5)
    raise SystemExit("GATE9 FAIL: alpha and beta did not both register fresh, routable nodes")


def create_started(client: httpx.Client, index: int) -> dict[str, Any]:
    created = client.post("/v1/sandboxes", json={"snapshot": IMAGE, "name": f"gate9-{index}"})
    check(created.status_code in (200, 201, 202), f"create -> {created.status_code}")
    sandbox_id = str(created.json()["data"]["id"])
    deadline = time.time() + START_WAIT_S
    state = "unknown"
    while time.time() < deadline:
        polled = client.get(f"/v1/sandboxes/{sandbox_id}")
        check(polled.status_code == 200, f"poll {sandbox_id} -> {polled.status_code}")
        data: dict[str, Any] = polled.json()["data"]
        state = str(data["state"])
        if state == "started":
            return data
        check(state != "error", f"sandbox {sandbox_id} entered state 'error'")
        time.sleep(0.5)
    raise SystemExit(f"GATE9 FAIL: sandbox {sandbox_id} is {state!r}, not started")


def delete_sandbox(client: httpx.Client, sandbox_id: str) -> None:
    """Delete, retrying while a transitional state answers 409."""
    deadline = time.time() + DESTROY_TIMEOUT_S
    while time.time() < deadline:
        response = client.delete(f"/v1/sandboxes/{sandbox_id}")
        if response.status_code != 409:
            return
        time.sleep(0.5)


def wait_gone(client: httpx.Client, sandbox_id: str) -> None:
    deadline = time.time() + DESTROY_TIMEOUT_S
    while time.time() < deadline:
        response = client.get(f"/v1/sandboxes/{sandbox_id}")
        if response.status_code == 404:
            return
        if response.status_code == 200 and response.json()["data"]["state"] in GONE_STATES:
            return
        time.sleep(0.5)
    raise SystemExit(f"GATE9 FAIL: sandbox {sandbox_id} was not destroyed in time")


def toolbox(sandbox_id: str, path: str) -> str:
    return f"/v1/sandboxes/{sandbox_id}/toolbox/{path}"


def run_exec(client: httpx.Client, sandbox_id: str, command: str) -> dict[str, Any]:
    body = {"command": command, "timeout_s": EXEC_TIMEOUT_S}
    response = client.post(toolbox(sandbox_id, "process/execute"), json=body)
    check(response.status_code == 200, f"exec -> {response.status_code} {response.text}")
    result: dict[str, Any] = response.json()["data"]
    return result


def check_exec(client: httpx.Client, sandbox_id: str) -> None:
    result = run_exec(client, sandbox_id, EXEC_PROBE)
    check(result["exit_code"] == 0, f"exec exited {result['exit_code']}: {result['stderr']!r}")
    check(result["stdout"].strip() == "gate9-42", f"unexpected exec output {result['stdout']!r}")


def check_file_round_trip(client: httpx.Client, sandbox_id: str) -> None:
    prepared = run_exec(client, sandbox_id, "mkdir -p /work")
    check(prepared["exit_code"] == 0, f"mkdir /work exited {prepared['exit_code']}")
    payload = os.urandom(UPLOAD_BYTES)
    uploaded = client.put(
        toolbox(sandbox_id, "fs/upload"), params={"path": UPLOAD_PATH}, content=payload
    )
    check(uploaded.status_code == 200, f"upload -> {uploaded.status_code} {uploaded.text}")
    check(uploaded.json()["data"]["size_bytes"] == len(payload), "upload size mismatch")
    downloaded = client.get(toolbox(sandbox_id, "fs/download"), params={"path": UPLOAD_PATH})
    check(downloaded.status_code == 200, f"download -> {downloaded.status_code}")
    check(downloaded.content == payload, "downloaded bytes differ from the uploaded bytes")


def check_git(client: httpx.Client, sandbox_id: str) -> None:
    installed = run_exec(client, sandbox_id, "apk add --no-progress git")
    check(installed["exit_code"] == 0, f"apk add git failed: {installed['stderr']!r}")
    inited = run_exec(client, sandbox_id, f"git init {REPO_PATH}")
    check(inited["exit_code"] == 0, f"git init failed: {inited['stderr']!r}")
    written = run_exec(client, sandbox_id, f"echo gate9 > {REPO_PATH}/NOTES.md")
    check(written["exit_code"] == 0, f"writing NOTES.md failed: {written['stderr']!r}")
    added = client.post(
        toolbox(sandbox_id, "git/add"), json={"path": REPO_PATH, "files": ["NOTES.md"]}
    )
    check(added.status_code == 200, f"git add -> {added.status_code} {added.text}")
    body = {
        "path": REPO_PATH,
        "message": "gate9: routed commit",
        "author_name": "Gate9",
        "author_email": "gate9@sandfort.local",
    }
    commit = client.post(toolbox(sandbox_id, "git/commit"), json=body)
    check(commit.status_code == 200, f"git commit -> {commit.status_code} {commit.text}")
    sha = str(commit.json()["data"]["sha"])
    check(len(sha) >= 7, f"git commit returned no sha: {sha!r}")
    status = client.post(toolbox(sandbox_id, "git/status"), json={"path": REPO_PATH})
    check(status.status_code == 200, f"git status -> {status.status_code} {status.text}")
    check(status.json()["data"]["files"] == [], "work tree is not clean after the commit")
    print(f"  commit {sha[:8]} made through alpha", flush=True)


def parse_sse(lines: Iterable[str]) -> tuple[str, str | None]:
    """Return the stdout text and the exit event's data (``None`` if it never arrived)."""
    output: list[str] = []
    event = ""
    for line in lines:
        if line.startswith("event:"):
            event = line.split(":", 1)[1].strip()
        elif line.startswith("data:") and event == "stdout":
            output.append(line.split(":", 1)[1])
        elif line.startswith("data:") and event == "exit":
            return "".join(output), line.split(":", 1)[1].strip()
    return "".join(output), None


def check_async_logs(client: httpx.Client, sandbox_id: str) -> None:
    created = client.post(toolbox(sandbox_id, "process/sessions"), json={})
    check(created.status_code == 201, f"session -> {created.status_code} {created.text}")
    session_id = str(created.json()["data"]["id"])
    base = f"process/sessions/{session_id}/commands"
    command = "for i in 1 2 3; do echo gate9-line-$i; sleep 1; done"
    started = client.post(
        toolbox(sandbox_id, base),
        params={"async": "true"},
        json={"command": command, "timeout_s": EXEC_TIMEOUT_S},
    )
    check(started.status_code == 202, f"async command -> {started.status_code} {started.text}")
    command_id = str(started.json()["data"]["command"]["id"])
    follow = toolbox(sandbox_id, f"{base}/{command_id}/logs/follow")
    with client.stream("GET", follow, timeout=httpx.Timeout(FOLLOW_TIMEOUT_S)) as response:
        check(response.status_code == 200, f"follow -> {response.status_code}")
        ctype = response.headers.get("content-type", "")
        check("text/event-stream" in ctype, f"follow content type {ctype!r}")
        text, final = parse_sse(response.iter_lines())
    check(final is not None, "the log stream ended without an exit event")
    check('"exit_code":0' in str(final), f"async command did not exit 0: {final}")
    for index in (1, 2, 3):
        check(f"gate9-line-{index}" in text, f"log line {index} missing from the stream: {text!r}")


async def read_until(ws: Any, marker: str) -> str:
    """Read terminal output until ``marker`` shows up (or the timeout elapses)."""
    seen = ""
    deadline = time.time() + PTY_TIMEOUT_S
    while marker not in seen:
        remaining = deadline - time.time()
        check(remaining > 0, f"terminal never produced {marker!r}; saw {seen!r}")
        message = await asyncio.wait_for(ws.recv(), timeout=remaining)
        seen += message.decode(errors="replace") if isinstance(message, bytes) else message
    return seen


async def drive_terminal(url: str, resize: Callable[[], None]) -> None:
    async with connect(url, proxy=None, open_timeout=PTY_TIMEOUT_S) as ws:
        # The input echo shows "$((6 * 7))", so only the executed line contains the marker.
        await ws.send(b"echo gate9-pty-$((6 * 7))\n")
        await read_until(ws, PTY_MARKER)
        print("  terminal echoed the line through alpha", flush=True)
        await asyncio.to_thread(resize)
        await ws.send(b"stty size\n")
        await read_until(ws, f"{PTY_ROWS} {PTY_COLS}")
        print(f"  terminal reports the new size {PTY_ROWS}x{PTY_COLS}", flush=True)


def check_terminal(client: httpx.Client, sandbox_id: str) -> None:
    created = client.post(toolbox(sandbox_id, "pty"), json={"rows": 24, "cols": 80})
    check(created.status_code == 201, f"pty create -> {created.status_code} {created.text}")
    data = created.json()["data"]
    pty_id, token = str(data["pty_id"]), str(data["token"])
    # The websocket_url in the reply is built from the forwarded Host (the owner): dial alpha.
    path = f"/v1/sandboxes/{sandbox_id}/toolbox/pty/{pty_id}/connect"
    url = f"ws://127.0.0.1:{ALPHA_PORT}{path}?token={token}"

    def resize() -> None:
        body = {"rows": PTY_ROWS, "cols": PTY_COLS}
        resized = client.post(toolbox(sandbox_id, f"pty/{pty_id}/resize"), json=body)
        check(resized.status_code == 200, f"pty resize -> {resized.status_code}")
        check(resized.json()["data"]["rows"] == PTY_ROWS, "resize was not applied")

    asyncio.run(drive_terminal(url, resize))
    client.delete(toolbox(sandbox_id, f"pty/{pty_id}"))


def check_owner_down(client: httpx.Client, sandbox_id: str) -> None:
    body = {"command": EXEC_PROBE, "timeout_s": 10}
    response = client.post(toolbox(sandbox_id, "process/execute"), json=body)
    print(f"  stopped-owner call -> {response.status_code} {response.text[:200]}", flush=True)
    check(response.status_code == 503, f"expected 503, got {response.status_code}")
    payload = response.json()
    check(payload["success"] is False, "503 body is not the standard envelope")
    check(payload["error"]["code"] == "NODE_UNAVAILABLE", f"unexpected code: {payload['error']}")
    reason = payload["error"]["details"].get("reason")
    check(reason in ("unreachable", "timeout"), f"unexpected refusal reason {reason!r}")
    retry = response.headers.get("retry-after", "")
    check(retry.isdigit() and int(retry) > 0, f"missing or invalid Retry-After: {retry!r}")


def create_until_beta(client: httpx.Client, ids: list[str]) -> str:
    """Create sandboxes through alpha until one is stamped beta; return that sandbox id."""
    for index in range(MAX_SANDBOXES):
        data = create_started(client, index)
        ids.append(str(data["id"]))
        print(f"  sandbox {ids[-1]} started on node {data['node_id']}", flush=True)
        if data["node_id"] == BETA:
            return ids[-1]
    raise SystemExit(f"GATE9 FAIL: none of {MAX_SANDBOXES} sandboxes landed on {BETA}")


def run_gate(key: str, db_path: str, procs: Processes, env: dict[str, str]) -> None:
    headers = {"Authorization": f"Bearer {key}"}
    with httpx.Client(base_url=API, headers=headers, timeout=60) as client:
        wait_registered(client, db_path)
        step("alpha and beta registered fresh heartbeats with their internal urls")
        ids: list[str] = []
        try:
            beta_id = create_until_beta(client, ids)
            step(f"sandbox {beta_id} is owned by beta; everything below goes through alpha")
            check_exec(client, beta_id)
            step("exec on the beta sandbox returned its output")
            check_file_round_trip(client, beta_id)
            step("file uploaded and downloaded byte-identical")
            check_git(client, beta_id)
            step("git init, add and commit ran in the beta sandbox")
            check_async_logs(client, beta_id)
            step("async command logs followed over SSE to the exit event")
            check_terminal(client, beta_id)
            step("terminal websocket echoed a line and resized")
            stop(procs[BETA])
            check_owner_down(client, beta_id)
            step("owner stopped: 503 NODE_UNAVAILABLE with Retry-After")
        finally:
            if procs[BETA].poll() is not None:
                procs[BETA] = spawn(BETA, env)
                wait_health(node_url(BETA))
            for sandbox_id in ids:
                delete_sandbox(client, sandbox_id)
            for sandbox_id in ids:
                wait_gone(client, sandbox_id)
        step("every sandbox deleted and destroyed")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="sandfort-gate9-")
    db_path = os.path.join(tmp, "gate9.db")
    procs: Processes = {}
    try:
        env = {
            **os.environ,
            "PYTHONPATH": str(REPO / "src"),
            "SANDFORT_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "SANDFORT_DRIVER": "docker",
            "SANDFORT_API_KEY_PEPPER": os.urandom(16).hex(),
            "SANDFORT_ROUTING_SECRET": os.urandom(24).hex(),
            "SANDFORT_NODE_HEARTBEAT_INTERVAL_S": HEARTBEAT_INTERVAL_S,
            "SANDFORT_SANDBOX_JOBS_ENABLED": "true",
            "SANDFORT_WARM_POOL_SIZE": "0",
        }
        key = provision(env)
        step("database migrated and org bootstrapped")

        for node_id in PORTS:
            procs[node_id] = spawn(node_id, env)
        for node_id in PORTS:
            wait_health(node_url(node_id))
        step("alpha and beta processes are healthy")

        run_gate(key, db_path, procs, env)
        print("GATE9 PASS", flush=True)
        return 0
    finally:
        for process in procs.values():
            stop(process)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
