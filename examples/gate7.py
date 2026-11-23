"""Gate 7: multi-node placement, end to end against real server processes.

Proves the scheduler slices together: one api process (role ``all``, node ``alpha``) and one
worker process (role ``worker``, node ``beta``) share a database and the local Docker daemon.
Six sandboxes are created and waited on; placement must spread them over both nodes and every
one must reach ``started``. A sandbox placed on beta can only have started because beta's own
job runner claimed its create job. Placement is read through ``GET /v1/nodes`` (the running
count per node), then everything is deleted and waited on until destroyed.

Run: .venv/bin/python examples/gate7.py
Requires a local Docker daemon with ``alpine:3.20`` available. A fresh temporary sqlite
database is migrated and bootstrapped in-process. Prints one progress line per step and exits
non-zero on any failure; both processes and the database are removed.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

API_PORT = 4199
WORKER_PORT = 4200
API = f"http://127.0.0.1:{API_PORT}"
WORKER = f"http://127.0.0.1:{WORKER_PORT}"
ALPHA = "alpha"
BETA = "beta"
IMAGE = "alpine:3.20"
SANDBOX_COUNT = 6
HEARTBEAT_INTERVAL_S = "1"
HEALTH_TIMEOUT_S = 40.0
REGISTER_TIMEOUT_S = 30.0
START_WAIT_S = 120.0
DESTROY_TIMEOUT_S = 90.0
GONE_STATES = frozenset({"destroyed", "deleted"})


def check(condition: bool, message: str) -> None:
    """Fail the gate (non-zero exit) unless ``condition`` holds."""
    if not condition:
        raise SystemExit(f"GATE7 FAIL: {message}")


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
    raise SystemExit(f"GATE7 FAIL: {base} did not become healthy")


def provision(env: dict[str, str]) -> str:
    """Migrate and bootstrap in-process; return the platform key."""
    os.environ.update(env)
    from sandfort import admin_cli

    admin_cli.migrate()
    key = admin_cli.bootstrap("Gate7", "gate7")
    check(key.startswith("sf_"), "bootstrap did not return an sf_ key")
    return key


def spawn(role: str, port: int, node_id: str, env: dict[str, str]) -> subprocess.Popen[bytes]:
    server_env = {
        **env,
        "SANDFORT_ROLE": role,
        "SANDFORT_PORT": str(port),
        "SANDFORT_NODE_ID": node_id,
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


def wait_registered(client: httpx.Client) -> None:
    deadline = time.time() + REGISTER_TIMEOUT_S
    while time.time() < deadline:
        nodes = list_nodes(client)
        if all(name in nodes and not nodes[name]["stale"] for name in (ALPHA, BETA)):
            return
        time.sleep(0.5)
    raise SystemExit("GATE7 FAIL: alpha and beta did not both register a fresh heartbeat")


def create_started(client: httpx.Client, index: int) -> str:
    created = client.post("/v1/sandboxes", json={"snapshot": IMAGE, "name": f"gate7-{index}"})
    check(created.status_code in (200, 201, 202), f"create -> {created.status_code}")
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
    raise SystemExit(f"GATE7 FAIL: sandbox {sandbox_id} is {state!r}, not started")


def wait_gone(client: httpx.Client, sandbox_id: str) -> None:
    deadline = time.time() + DESTROY_TIMEOUT_S
    while time.time() < deadline:
        response = client.get(f"/v1/sandboxes/{sandbox_id}")
        if response.status_code == 404:
            return
        if response.status_code == 200 and response.json()["data"]["state"] in GONE_STATES:
            return
        time.sleep(0.5)
    raise SystemExit(f"GATE7 FAIL: sandbox {sandbox_id} was not destroyed in time")


def stamped_nodes(db_path: str, ids: list[str]) -> dict[str, int]:
    """Count the created sandboxes per ``node_id`` stamp (the api does not expose it)."""
    marks = ",".join("?" for _ in ids)
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT node_id, COUNT(*) FROM sandboxes WHERE id IN ({marks}) GROUP BY node_id",
            ids,
        ).fetchall()
    return {str(node): int(count) for node, count in rows}


def run_gate(key: str, db_path: str) -> None:
    headers = {"Authorization": f"Bearer {key}"}
    with httpx.Client(base_url=API, headers=headers, timeout=30) as client:
        wait_registered(client)
        step("alpha (api process) and beta (worker process) registered fresh heartbeats")

        ids: list[str] = []
        try:
            for index in range(SANDBOX_COUNT):
                ids.append(create_started(client, index))
                print(f"  sandbox {index + 1}/{SANDBOX_COUNT} started: {ids[-1]}", flush=True)
            step(f"all {SANDBOX_COUNT} sandboxes reached started")

            stamps = stamped_nodes(db_path, ids)
            print(f"  node stamp per node: {stamps}", flush=True)
            check(stamps.get(BETA, 0) >= 1, f"no sandbox carries the beta node stamp: {stamps}")
            step("jobs mode engaged: at least one sandbox is stamped with node beta")

            nodes = list_nodes(client)
            counts = {name: nodes[name]["running_sandboxes"] for name in (ALPHA, BETA)}
            print(f"  running per node: {counts}", flush=True)
            check(counts[ALPHA] > 0, f"no sandbox was placed on alpha: {counts}")
            check(counts[BETA] > 0, f"no sandbox was placed on beta: {counts}")
            check(sum(counts.values()) == SANDBOX_COUNT, f"running counts do not add up: {counts}")
            step("placement spread the sandboxes over alpha and beta")
        finally:
            for sandbox_id in ids:
                client.delete(f"/v1/sandboxes/{sandbox_id}")
            for sandbox_id in ids:
                wait_gone(client, sandbox_id)
        step("every sandbox deleted and destroyed")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="sandfort-gate7-")
    db_path = os.path.join(tmp, "gate7.db")
    processes: list[subprocess.Popen[bytes]] = []
    try:
        env = {
            **os.environ,
            "PYTHONPATH": str(REPO / "src"),
            "SANDFORT_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "SANDFORT_DRIVER": "docker",
            "SANDFORT_API_KEY_PEPPER": os.urandom(16).hex(),
            "SANDFORT_NODE_HEARTBEAT_INTERVAL_S": HEARTBEAT_INTERVAL_S,
            "SANDFORT_SANDBOX_JOBS_ENABLED": "true",
        }
        key = provision(env)
        step("database migrated and org bootstrapped")

        processes.append(spawn("all", API_PORT, ALPHA, env))
        processes.append(spawn("worker", WORKER_PORT, BETA, env))
        wait_health(API)
        wait_health(WORKER)
        step("alpha (api) and beta (worker) processes are healthy")

        run_gate(key, db_path)
        print("GATE7 PASS", flush=True)
        return 0
    finally:
        for process in processes:
            stop(process)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
