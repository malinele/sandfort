"""Gate 3 demo: declarative image, 20 fast sandboxes, snapshot, shared volume,
auto-stop, and a reconciler chaos test (server killed mid-create).

Run: .venv/bin/python examples/gate3.py
Requires a local Docker daemon. Spawns the API server on a temp SQLite
database and drives everything through the public SDK. Exits non-zero if any
step fails.
"""

from __future__ import annotations

import io
import os
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "sdk" / "python" / "src"))

from sandfort_sdk import Client, Image  # noqa: E402

PORT = 4197
BASE = f"http://127.0.0.1:{PORT}"


def wait_health(timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"{BASE}/healthz", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.3)
    raise SystemExit("server did not become healthy")


def step(n: str, msg: str) -> None:
    print(f"[{n}] {msg}", flush=True)


def spawn_server(env: dict[str, str]) -> subprocess.Popen[bytes]:
    py = str(REPO / ".venv" / "bin" / "python")
    proc = subprocess.Popen(
        [py, "-m", "uvicorn", "--factory", "sandfort.main:create_app", "--port", str(PORT)],
        cwd=REPO, env=env,
    )
    wait_health()
    return proc


def poll_snapshot_ready(client: Client, snap_id: str, timeout: float = 180.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = client.snapshots.get(snap_id)
        if snap.state == "ready":
            return
        if snap.state == "error":
            raise SystemExit(f"snapshot {snap_id} failed: {snap}")
        time.sleep(0.5)
    raise SystemExit(f"snapshot {snap_id} not ready in time")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="sandfort-gate3-")
    db = os.path.join(tmp, "gate3.db")
    env = {
        **os.environ,
        "SANDFORT_DATABASE_URL": f"sqlite+aiosqlite:///{db}",
        "SANDFORT_DRIVER": "docker",
        "SANDFORT_API_KEY_PEPPER": os.urandom(16).hex(),
        "PYTHONPATH": "src",
        "SANDFORT_AUTOSTOP_INTERVAL_S": "3",
        "SANDFORT_RECONCILE_INTERVAL_S": "5",
        "SANDFORT_ORPHAN_GRACE_S": "10",
    }
    py = str(REPO / ".venv" / "bin" / "python")
    subprocess.run([py, "-m", "sandfort.admin_cli", "migrate"], cwd=REPO, env=env, check=True)
    out = subprocess.run(
        [py, "-m", "sandfort.admin_cli", "bootstrap",
         "--org-name", "Gate3", "--org-slug", "gate3"],
        cwd=REPO, env=env, check=True, capture_output=True, text=True,
    ).stdout
    key = next(tok for tok in out.split() if tok.startswith("sf_"))

    server = spawn_server(env)
    sandbox_ids: list[str] = []
    try:
        client = Client(base_url=BASE, api_key=key)

        # 1) Declarative image build through the DSL.
        image = (
            Image.debian_slim()
            .add_file("/etc/sandfort-gate3.txt", "declarative build marker\n")
            .env(GATE3="yes")
        )
        snap = client.snapshots.build(image)
        if snap.state != "ready":
            for line in client.snapshots.follow_build_logs(snap.id):
                print("    | " + str(line).rstrip(), flush=True)
            poll_snapshot_ready(client, snap.id)
        step("1", f"declarative image built -> snapshot {snap.id} ready")

        cached = client.snapshots.build(image)
        assert cached.id == snap.id, (cached.id, snap.id)
        step("2", "identical spec reused the cached snapshot (no rebuild)")

        # 2) 20 sandboxes from it, p50 create latency under 1 s.
        latencies: list[float] = []
        for i in range(20):
            t0 = time.monotonic()
            sbx = client.create_sandbox(name=f"gate3-{i}", snapshot=snap.id, wait=True)
            latencies.append(time.monotonic() - t0)
            sandbox_ids.append(sbx.id)
        p50 = statistics.median(latencies)
        p95 = sorted(latencies)[int(0.95 * len(latencies)) - 1]
        assert p50 < 1.0, f"create p50 {p50:.3f}s >= 1s"
        step("3", f"20 sandboxes from the snapshot: create p50={p50 * 1000:.0f}ms "
                  f"p95={p95 * 1000:.0f}ms")

        first = client.get(sandbox_ids[0])
        marker = first.fs.read_bytes("/etc/sandfort-gate3.txt")
        assert marker == b"declarative build marker\n", marker
        step("4", "the built file is inside a running sandbox")

        # 3) Snapshot one sandbox and see the file in a child sandbox.
        first.fs.upload_file("/root/gate3-state.txt", io.BytesIO(b"snapshotted state\n"))
        snap2 = client.snapshots.create_from_sandbox(first.id, name="gate3-state")
        poll_snapshot_ready(client, snap2.id)
        child = client.create_sandbox(name="gate3-child", snapshot=snap2.id, wait=True)
        sandbox_ids.append(child.id)
        got = child.fs.read_bytes("/root/gate3-state.txt")
        assert got == b"snapshotted state\n", got
        step("5", f"snapshot {snap2.id} of a live sandbox -> child sandbox sees the file")

        # 4) Shared volume between two sandboxes.
        vol = client.volumes.create(name="gate3-shared")
        a = client.create_sandbox(name="gate3-vol-a", snapshot="alpine:3.20",
                                  mounts=[(vol.id, "/data")], wait=True)
        b = client.create_sandbox(name="gate3-vol-b", snapshot="alpine:3.20",
                                  mounts=[(vol.id, "/data")], wait=True)
        sandbox_ids.extend([a.id, b.id])
        a.fs.upload_file("/data/shared.txt", io.BytesIO(b"through the volume\n"))
        assert b.fs.read_bytes("/data/shared.txt") == b"through the volume\n"
        try:
            client.volumes.delete(vol.id)
            raise SystemExit("volume delete while mounted should have failed")
        except Exception as exc:  # noqa: BLE001 - we want the 409 class
            assert type(exc).__name__ == "Conflict", exc
        step("6", f"volume {vol.id} shared between two sandboxes; delete while mounted -> 409")

        # 5) Auto-stop fires.
        idle = client.create_sandbox(name="gate3-idle", snapshot="alpine:3.20",
                                     auto_stop_minutes=1, wait=True)
        sandbox_ids.append(idle.id)
        deadline = time.time() + 90
        state = idle.state
        while time.time() < deadline:
            state = client.get(idle.id).state
            if state == "stopped":
                break
            time.sleep(2)
        assert state == "stopped", f"auto-stop did not fire, state={state}"
        step("7", "auto-stop stopped the idle sandbox")

        # 6) Chaos: kill the server mid-create, restart, reconcile.
        chaos_name = "gate3-chaos"

        def fire_create() -> None:
            try:
                httpx.post(
                    f"{BASE}/v1/sandboxes",
                    json={"name": chaos_name, "snapshot": "alpine:3.20"},
                    headers={"Authorization": f"Bearer {key}"},
                    timeout=10,
                )
            except httpx.HTTPError:
                pass  # the kill below is expected to sever this request

        t = threading.Thread(target=fire_create)
        t.start()
        time.sleep(0.35)  # let the request reach the driver work
        server.send_signal(signal.SIGKILL)
        server.wait(timeout=10)
        t.join(timeout=15)
        step("8", "server killed mid-create")

        server = spawn_server(env)
        client = Client(base_url=BASE, api_key=key)
        time.sleep(8)  # startup reconcile + one interval
        rows = list(client.iter_sandboxes())
        transitional = [s for s in rows if s.state in ("creating", "starting", "stopping")]
        assert not transitional, f"stuck transitional rows after restart: {transitional}"
        probe = client.create_sandbox(name="gate3-post-chaos", snapshot="alpine:3.20", wait=True)
        sandbox_ids.append(probe.id)
        step("9", f"restart + reconcile left no stuck rows; follow-up create works "
                  f"({len(rows)} rows scanned)")

        print("GATE 3: PASS")
        return 0
    finally:
        try:
            client = Client(base_url=BASE, api_key=key)
            for sid in sandbox_ids:
                try:
                    client.stop(sid)
                except Exception:  # noqa: BLE001
                    pass
                try:
                    client.delete(sid)
                except Exception:  # noqa: BLE001
                    pass
        except Exception:  # noqa: BLE001
            pass
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    raise SystemExit(main())
