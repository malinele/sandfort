"""Gate 1 demo: the SDK creates a sandbox on real Docker, runs Python, deletes it.

Run: .venv/bin/python examples/quickstart.py
Requires a local Docker daemon. Spawns the API server as a subprocess on a
temp SQLite database, bootstraps an admin key, then drives everything through
the public SDK. Exits non-zero if any step - including the audit-trail and
env-isolation checks - fails.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "sdk" / "python" / "src"))

from sandfort_sdk import Client  # noqa: E402

PORT = 4199
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


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="sandfort-gate1-")
    db = os.path.join(tmp, "gate1.db")
    env = {
        **os.environ,
        "SANDFORT_DATABASE_URL": f"sqlite+aiosqlite:///{db}",
        "SANDFORT_DRIVER": "docker",
        "SANDFORT_API_KEY_PEPPER": os.urandom(16).hex(),
        "PYTHONPATH": "src",
    }
    py = str(REPO / ".venv" / "bin" / "python")
    subprocess.run([py, "-m", "sandfort.admin_cli", "migrate"], cwd=REPO, env=env, check=True)
    out = subprocess.run(
        [py, "-m", "sandfort.admin_cli", "bootstrap",
         "--org-name", "Gate1", "--org-slug", "gate1"],
        cwd=REPO, env=env, check=True, capture_output=True, text=True,
    ).stdout
    key = next(tok for tok in out.split() if tok.startswith("sf_"))

    server = subprocess.Popen(
        [py, "-m", "uvicorn", "--factory", "sandfort.main:create_app", "--port", str(PORT)],
        cwd=REPO, env=env,
    )
    try:
        wait_health()
        client = Client(base_url=BASE, api_key=key)

        sbx = client.create_sandbox(name="gate1-demo", wait=True)
        print(f"[1] created {sbx.id} state={sbx.state}")

        result = sbx.process_exec(argv=["python3", "-c", "print(21 * 2)"])
        assert result.exit_code == 0 and "42" in result.stdout, result
        print(f"[2] exec ok -> {result.stdout.strip()}")

        env_out = sbx.process_exec(argv=["env"])
        leaked = [ln for ln in env_out.stdout.splitlines() if ln.startswith("SANDFORT_")]
        assert not leaked, f"server env leaked into sandbox: {leaked}"
        print("[3] no SANDFORT_ env inside the sandbox")

        client.stop(sbx.id)
        client.delete(sbx.id)
        print(f"[4] deleted {sbx.id}")

        audit = httpx.get(
            f"{BASE}/v1/audit-events",
            headers={"Authorization": f"Bearer {key}"},
            timeout=10,
        ).json()
        data = audit.get("data", audit)
        items = data if isinstance(data, list) else data["items"]
        actions = [row["action"] for row in items]
        for needed in ("sandbox.create", "toolbox.process.execute", "sandbox.delete"):
            assert needed in actions, (needed, actions)
        print(f"[5] audit trail covers create/exec/delete ({len(actions)} rows)")
        print("GATE 1: PASS")
        return 0
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
