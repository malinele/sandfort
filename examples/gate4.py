"""Gate 4 demo: two orgs, quotas under a concurrent burst, signed webhooks
reaching a live receiver, a usage report, and Grafana-ready metrics.

Run: .venv/bin/python examples/gate4.py
Requires a local Docker daemon. Spawns the API server on a temp SQLite
database with the private-network webhook flag on, plus a local HTTP receiver
that verifies standard-webhooks signatures. Exits non-zero on any failure.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "sdk" / "python" / "src"))

from sandfort_sdk import Client  # noqa: E402

PORT = 4196
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


class Receiver(BaseHTTPRequestHandler):
    """Stores each delivery (headers + body) for later signature checks."""

    deliveries: list[tuple[dict[str, str], bytes]] = []

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        Receiver.deliveries.append(({k.lower(): v for k, v in self.headers.items()}, body))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args: object) -> None:  # silence
        del args


def verify_standard_webhook(secret: str, headers: dict[str, str], body: bytes) -> bool:
    """Reference Standard-Webhooks verification, independent of server code."""
    msg_id = headers["webhook-id"]
    ts = headers["webhook-timestamp"]
    key = base64.b64decode(secret.removeprefix("whsec_"))
    signed = f"{msg_id}.{ts}.".encode() + body
    want = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    got = [part.split(",", 1)[1] for part in headers["webhook-signature"].split()
           if part.startswith("v1,")]
    return any(hmac.compare_digest(want, g) for g in got)


def bootstrap_org(py: str, env: dict[str, str], name: str, slug: str,
                  command: str = "bootstrap") -> str:
    out = subprocess.run(
        [py, "-m", "sandfort.admin_cli", command,
         "--org-name", name, "--org-slug", slug],
        cwd=REPO, env=env, check=True, capture_output=True, text=True,
    ).stdout
    return next(tok for tok in out.split() if tok.startswith("sf_"))


async def burst_creates(key: str, count: int) -> tuple[int, int]:
    """Fire `count` concurrent 1-vCPU creates; return (succeeded, quota_rejected)."""
    async with httpx.AsyncClient(timeout=60) as ac:

        async def one(i: int) -> int:
            resp = await ac.post(
                f"{BASE}/v1/sandboxes",
                json={"name": f"gate4-burst-{i}",
                      "snapshot": "alpine:3.20",
                      "resources": {"cpu_millicores": 1000}},
                headers={"Authorization": f"Bearer {key}"},
            )
            if resp.status_code == 201:
                return 201
            body = resp.json()
            code = (body.get("error") or {}).get("code", "")
            assert resp.status_code == 429 and code == "QUOTA_EXCEEDED", (
                resp.status_code, body)
            return 429

        results = await asyncio.gather(*(one(i) for i in range(count)))
    return results.count(201), results.count(429)


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="sandfort-gate4-")
    db = os.path.join(tmp, "gate4.db")
    env = {
        **os.environ,
        "SANDFORT_DATABASE_URL": f"sqlite+aiosqlite:///{db}",
        "SANDFORT_DRIVER": "docker",
        "SANDFORT_API_KEY_PEPPER": os.urandom(16).hex(),
        "PYTHONPATH": "src",
        "SANDFORT_WEBHOOK_ALLOW_PRIVATE_NETWORKS": "1",
        "SANDFORT_WEBHOOK_DISPATCH_INTERVAL_S": "1",
    }
    py = str(REPO / ".venv" / "bin" / "python")
    subprocess.run([py, "-m", "sandfort.admin_cli", "migrate"], cwd=REPO, env=env, check=True)
    key_a = bootstrap_org(py, env, "Gate4-A", "gate4-a")
    key_b = bootstrap_org(py, env, "Gate4-B", "gate4-b", command="create-org")
    step("1", "two orgs bootstrapped with their own admin keys")

    receiver = None
    for port in range(8400, 8500):
        try:
            receiver = HTTPServer(("127.0.0.1", port), Receiver)
            break
        except OSError:
            continue
    assert receiver is not None, "no free receiver port in 8400-8499"
    threading.Thread(target=receiver.serve_forever, daemon=True).start()
    hook_url = f"http://127.0.0.1:{receiver.server_port}/hook"

    server = subprocess.Popen(
        [py, "-m", "uvicorn", "--factory", "sandfort.main:create_app", "--port", str(PORT)],
        cwd=REPO, env=env,
    )
    created: list[tuple[str, str]] = []
    try:
        wait_health()
        auth_a = {"Authorization": f"Bearer {key_a}"}

        # Quota: org A capped at 10 vCPUs; 50-strong concurrent burst.
        put = httpx.put(f"{BASE}/v1/org/quota", json={"max_vcpus": 10},
                        headers=auth_a, timeout=10)
        assert put.status_code == 200, put.text
        ok_n, rejected_n = asyncio.run(burst_creates(key_a, 50))
        assert (ok_n, rejected_n) == (10, 40), (ok_n, rejected_n)
        step("2", "burst of 50 concurrent 1-vCPU creates: exactly 10 created, "
                  "40 rejected with 429 QUOTA_EXCEEDED")

        # Org isolation: B sees none of A's sandboxes and can create its own.
        client_b = Client(base_url=BASE, api_key=key_b)
        assert list(client_b.iter_sandboxes()) == []
        sb = client_b.create_sandbox(name="gate4-b-own", snapshot="alpine:3.20", wait=True)
        created.append((key_b, sb.id))
        step("3", "org isolation: org B lists zero of org A's sandboxes, creates its own")

        # Webhooks: endpoint on org B, then create/stop/delete to emit events.
        made = httpx.post(f"{BASE}/v1/webhooks",
                          json={"url": hook_url},
                          headers={"Authorization": f"Bearer {key_b}"},
                          timeout=10).json()["data"]
        secret = made["secret"]
        assert secret.startswith("whsec_")
        tgt = client_b.create_sandbox(name="gate4-b-events", snapshot="alpine:3.20", wait=True)
        client_b.stop(tgt.id)
        client_b.delete(tgt.id)
        deadline = time.time() + 30
        wanted = {"sandbox.created", "sandbox.stopped", "sandbox.deleted"}
        seen: set[str] = set()
        while time.time() < deadline and not wanted <= seen:
            for headers, body in list(Receiver.deliveries):
                assert verify_standard_webhook(secret, headers, body), headers
                seen.add(json.loads(body).get("type", ""))
            time.sleep(1)
        assert wanted <= seen, (wanted, seen)
        step("4", f"webhooks delivered to a live receiver with VALID signatures: {sorted(seen)}")

        # Usage report for org A (its 10 burst sandboxes are running).
        time.sleep(3)
        now = datetime.now(UTC)
        usage = httpx.get(
            f"{BASE}/v1/org/usage",
            params={"from": (now - timedelta(hours=1)).isoformat(),
                    "to": (now + timedelta(minutes=1)).isoformat()},
            headers=auth_a, timeout=10,
        ).json()["data"]
        vcpu = next(row for row in usage if "vcpu" in row["dimension"])
        assert vcpu["total"] > 0, usage
        step("5", f"usage report: {vcpu['dimension']}={vcpu['total']:.0f} {vcpu['unit']}")

        # Grafana-ready metrics.
        metrics = httpx.get(f"{BASE}/metrics", timeout=10).text
        for name in ("sandfort_http_requests_total", "sandfort_sandbox_creates_total",
                     "sandfort_driver_calls_total", "sandfort_webhook_deliveries_total"):
            assert name in metrics, name
        step("6", "metrics endpoint exposes the stable catalog (Prometheus text format)")

        print("GATE 4: PASS")
        return 0
    finally:
        try:
            for key, sid in created:
                c = Client(base_url=BASE, api_key=key)
                for action in (c.stop, c.delete):
                    try:
                        action(sid)
                    except Exception:  # noqa: BLE001
                        pass
            ca = Client(base_url=BASE, api_key=key_a)
            for sbx in list(ca.iter_sandboxes()):
                for action in (ca.stop, ca.delete):
                    try:
                        action(sbx.id)
                    except Exception:  # noqa: BLE001
                        pass
        except Exception:  # noqa: BLE001
            pass
        receiver.shutdown()
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    raise SystemExit(main())
