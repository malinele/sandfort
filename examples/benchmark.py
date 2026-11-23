"""Reproducible latency benchmark: sandbox create, exec and delete.

Run: .venv/bin/python examples/benchmark.py [--creates 20] [--execs 50] [--deletes 20]
Requires a local Docker daemon. Spawns one api+worker server on a benchmark port
with a temporary SQLite database and drives it through the public SDK. A first
warm-up create (image pre-pull) is excluded from every number. Prints progress,
then one final JSON object with the numbers and their measurement conditions.
Exits non-zero on any failure and removes everything it created.

This is a single-host local measurement, not a service level objective.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "sdk" / "python" / "src"))

from sandfort_sdk import (  # noqa: E402
    Client,
    Conflict,
    InvalidState,
    NotFound,
    SandboxFailedError,
    SandboxTimeoutError,
)

PORT = 4198
BASE = f"http://127.0.0.1:{PORT}"
IMAGE = "alpine:3.20"
DISCLAIMER = "single-host local measurement, not a service level objective"
MIN_PERCENTILE_SAMPLES = 2
DELETE_GONE_TIMEOUT_S = 60.0
CLEANUP_TIMEOUT_S = 60.0
CLEANUP_BACKOFF_S = 0.5
GONE_VERIFY_TIMEOUT_S = 60.0
GONE_VERIFY_POLL_S = 0.5
GONE_STATES = frozenset({"destroyed", "deleted"})
STOP_FROM_STATES = frozenset({"started"})
DELETE_FROM_STATES = frozenset({"stopped", "error"})


def step(n: str, msg: str) -> None:
    print(f"[{n}] {msg}", flush=True)


def wait_health(timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"{BASE}/healthz", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.3)
    raise SystemExit("server did not become healthy")


def spawn_server(env: dict[str, str]) -> subprocess.Popen[bytes]:
    py = str(REPO / ".venv" / "bin" / "python")
    proc = subprocess.Popen(
        [py, "-m", "uvicorn", "--factory", "sandfort.main:create_app", "--port", str(PORT)],
        cwd=REPO, env=env,
    )
    wait_health()
    return proc


def percentiles_ms(samples_s: list[float]) -> dict[str, float]:
    """p50 and p95 in milliseconds via ``statistics.quantiles`` (inclusive method)."""
    if len(samples_s) < MIN_PERCENTILE_SAMPLES:
        raise SystemExit(f"need at least {MIN_PERCENTILE_SAMPLES} samples, got {len(samples_s)}")
    cuts = statistics.quantiles(samples_s, n=100, method="inclusive")
    return {"p50_ms": round(cuts[49] * 1000, 1), "p95_ms": round(cuts[94] * 1000, 1)}


def docker_version() -> str:
    try:
        out = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"cannot read docker daemon version: {exc}") from exc
    if not out:
        raise SystemExit("docker daemon version is empty")
    return out


def wait_gone(client: Client, sandbox_id: str) -> None:
    deadline = time.monotonic() + DELETE_GONE_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            if client.get(sandbox_id).state in GONE_STATES:
                return
        except Exception:  # noqa: BLE001 - a 404 means the sandbox is gone
            return
        time.sleep(0.2)
    raise SystemExit(f"sandbox {sandbox_id} still present after delete")


def measure_creates(client: Client, count: int, ids: list[str]) -> list[float]:
    samples: list[float] = []
    for i in range(count):
        name = f"bench-{i}"
        t0 = time.perf_counter()
        try:
            sbx = client.create_sandbox(name=name, snapshot=IMAGE, wait=True)
        except (SandboxTimeoutError, SandboxFailedError) as exc:
            raise SystemExit(create_failure(client, name, exc, ids)) from exc
        samples.append(time.perf_counter() - t0)
        ids.append(sbx.id)
    return samples


def create_failure(client: Client, name: str, exc: Exception, ids: list[str]) -> str:
    """Describe a create that never reached started; register its id for cleanup."""
    if isinstance(exc, SandboxFailedError):
        found = [(exc.sandbox_id, exc.state)]
    else:
        found = [(s.id, s.state) for s in client.iter_sandboxes() if s.info.name == name]
    for sandbox_id, _state in found:
        if sandbox_id not in ids:
            ids.append(sandbox_id)
    seen = ", ".join(f"{sid} (last seen state: {state})" for sid, state in found)
    return f"benchmark failed: sandbox {name} did not reach started: {seen or 'id unknown'}"


def last_state_after_wait(client: Client, sandbox_id: str) -> str | None:
    """Poll one sandbox up to 60 s; return None once gone, else its last seen state."""
    deadline = time.monotonic() + GONE_VERIFY_TIMEOUT_S
    state = "unknown"
    while time.monotonic() < deadline:
        try:
            state = client.get(sandbox_id).state
        except NotFound:
            return None
        except Exception as exc:  # noqa: BLE001 - keep polling until the window closes
            state = f"{state}, last error: {exc}"
        else:
            if state in GONE_STATES:
                return None
        time.sleep(GONE_VERIFY_POLL_S)
    return state


def assert_all_gone(client: Client, created_ids: list[str]) -> None:
    """Fail unless every created sandbox reports destroyed (or not found) within its window."""
    stuck = []
    for sandbox_id in created_ids:
        state = last_state_after_wait(client, sandbox_id)
        if state is not None:
            stuck.append(f"{sandbox_id} (last state: {state})")
    if stuck:
        raise SystemExit(f"benchmark failed: sandboxes not destroyed within 60 s: {stuck}")


def measure_execs(client: Client, sandbox_id: str, count: int) -> list[float]:
    sbx = client.get(sandbox_id)
    samples: list[float] = []
    for _ in range(count):
        t0 = time.perf_counter()
        result = sbx.process.exec("echo bench")
        samples.append(time.perf_counter() - t0)
        if result.exit_code != 0 or result.stdout.strip() != "bench":
            raise SystemExit(f"unexpected exec result: {result}")
    return samples


def measure_deletes(client: Client, ids: list[str], count: int) -> list[float]:
    samples: list[float] = []
    for sandbox_id in ids[:count]:
        t0 = time.perf_counter()
        client.delete(sandbox_id)
        wait_gone(client, sandbox_id)
        samples.append(time.perf_counter() - t0)
    return samples


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--creates", type=int, default=20, help="measured creates (default 20)")
    parser.add_argument("--execs", type=int, default=50, help="measured execs (default 50)")
    parser.add_argument("--deletes", type=int, default=20, help="measured deletes (default 20)")
    args = parser.parse_args()
    if min(args.creates, args.execs, args.deletes) < MIN_PERCENTILE_SAMPLES:
        parser.error(f"every count must be at least {MIN_PERCENTILE_SAMPLES}")
    if args.deletes > args.creates:
        parser.error("--deletes cannot exceed --creates")
    return args


def remove_sandbox(client: Client, sandbox_id: str) -> str | None:
    """Drive one sandbox to gone; return a description if it is still present after 60 s."""
    deadline = time.monotonic() + CLEANUP_TIMEOUT_S
    state = "unknown"
    while time.monotonic() < deadline:
        try:
            state = client.get(sandbox_id).state
            if state in GONE_STATES:
                return None
            if state in STOP_FROM_STATES:
                client.stop(sandbox_id)
            elif state in DELETE_FROM_STATES:
                client.delete(sandbox_id)
        except NotFound:
            return None
        except (Conflict, InvalidState):
            pass  # transitional state; poll again after the backoff
        except Exception as exc:  # noqa: BLE001 - keep retrying until the window closes
            state = f"{state}, last error: {exc}"
        time.sleep(CLEANUP_BACKOFF_S)
    return f"{sandbox_id} (last seen state: {state})"


def cleanup(key: str, ids: list[str]) -> list[str]:
    """Remove every created sandbox; return those still present once retries are exhausted."""
    try:
        client = Client(base_url=BASE, api_key=key)
    except Exception as exc:  # noqa: BLE001
        return [f"{sandbox_id} (no client: {exc})" for sandbox_id in ids]
    leftovers = (remove_sandbox(client, sandbox_id) for sandbox_id in ids)
    return [item for item in leftovers if item is not None]


def main() -> int:
    args = parse_args()
    version = docker_version()
    tmp = tempfile.mkdtemp(prefix="sandfort-bench-")
    env = {
        **os.environ,
        "SANDFORT_DATABASE_URL": f"sqlite+aiosqlite:///{os.path.join(tmp, 'bench.db')}",
        "SANDFORT_DRIVER": "docker",
        "SANDFORT_API_KEY_PEPPER": os.urandom(16).hex(),
        "PYTHONPATH": "src",
    }
    py = str(REPO / ".venv" / "bin" / "python")
    server: subprocess.Popen[bytes] | None = None
    key = ""
    ids: list[str] = []
    try:
        subprocess.run([py, "-m", "sandfort.admin_cli", "migrate"], cwd=REPO, env=env, check=True)
        out = subprocess.run(
            [py, "-m", "sandfort.admin_cli", "bootstrap",
             "--org-name", "Bench", "--org-slug", "bench"],
            cwd=REPO, env=env, check=True, capture_output=True, text=True,
        ).stdout
        key = next(tok for tok in out.split() if tok.startswith("sf_"))
        server = spawn_server(env)
        client = Client(base_url=BASE, api_key=key)

        warm = client.create_sandbox(name="bench-warmup", snapshot=IMAGE, wait=True)
        ids.append(warm.id)
        client.delete(warm.id)
        wait_gone(client, warm.id)
        ids.remove(warm.id)
        step("0", "warm-up create done (image pre-pulled, excluded from the numbers)")

        creates = measure_creates(client, args.creates, ids)
        create_stats = percentiles_ms(creates)
        step("1", f"{args.creates} creates: {create_stats}")

        execs = measure_execs(client, ids[0], args.execs)
        exec_stats = percentiles_ms(execs)
        step("2", f"{args.execs} execs: {exec_stats}")

        deletes = measure_deletes(client, ids, args.deletes)
        delete_stats = percentiles_ms(deletes)
        assert_all_gone(client, ids[: args.deletes])
        del ids[: args.deletes]
        step("3", f"{args.deletes} deletes: {delete_stats}")

        report = {
            "results": {
                "create": create_stats,
                "exec": exec_stats,
                "delete": delete_stats,
            },
            "conditions": {
                "platform": platform.platform(),
                "docker_server_version": version,
                "python_version": platform.python_version(),
                "date": datetime.date.today().isoformat(),
                "image": IMAGE,
                "image_prepulled_by_warmup": True,
                "create_count": args.creates,
                "exec_count": args.execs,
                "delete_count": args.deletes,
                "create_waits_until_started": True,
                "percentile_method": "statistics.quantiles(n=100, method='inclusive')",
                "note": DISCLAIMER,
            },
        }
        print(json.dumps(report, indent=2), flush=True)
        return 0
    finally:
        leftovers: list[str] = []
        if server is not None:
            leftovers = cleanup(key, ids)
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
        shutil.rmtree(tmp, ignore_errors=True)
        if leftovers:
            print(f"cleanup failed, still present: {leftovers}", file=sys.stderr, flush=True)
            if sys.exc_info()[0] is None:
                raise SystemExit(1)


if __name__ == "__main__":
    raise SystemExit(main())
