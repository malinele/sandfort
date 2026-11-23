"""Gate 5 setup: API + preview proxy in one process, a sandbox running a dev
server behind a preview URL, and a web-terminal PTY — then stays alive so a
real browser (Playwright) can exercise the terminal and the preview page.

Run: .venv/bin/python examples/gate5.py
Prints READY lines with the URLs, verifies the preview URL server-side first,
and keeps serving until killed. Requires a local Docker daemon.
"""

from __future__ import annotations

import io
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

API_PORT = 4195
PROXY_PORT = 4194
BASE = f"http://127.0.0.1:{API_PORT}"
INDEX = b"<html><body><h1>sandfort gate5 dev server</h1></body></html>"


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
    tmp = tempfile.mkdtemp(prefix="sandfort-gate5-")
    db = os.path.join(tmp, "gate5.db")
    env = {
        **os.environ,
        "SANDFORT_DATABASE_URL": f"sqlite+aiosqlite:///{db}",
        "SANDFORT_DRIVER": "docker",
        "SANDFORT_API_KEY_PEPPER": os.urandom(16).hex(),
        "PYTHONPATH": "src",
        "SANDFORT_PROXY_ENABLED": "1",
        "SANDFORT_PROXY_PORT": str(PROXY_PORT),
        "SANDFORT_API_PUBLIC_URL": BASE,
    }
    py = str(REPO / ".venv" / "bin" / "python")
    subprocess.run([py, "-m", "sandfort.admin_cli", "migrate"], cwd=REPO, env=env, check=True)
    out = subprocess.run(
        [py, "-m", "sandfort.admin_cli", "bootstrap",
         "--org-name", "Gate5", "--org-slug", "gate5"],
        cwd=REPO, env=env, check=True, capture_output=True, text=True,
    ).stdout
    key = next(tok for tok in out.split() if tok.startswith("sf_"))

    env["SANDFORT_PORT"] = str(API_PORT)
    server = subprocess.Popen(
        [py, "-c", "from sandfort.main import main; main()"], cwd=REPO, env=env)
    try:
        wait_health()
        client = Client(base_url=BASE, api_key=key)

        sbx = client.create_sandbox(name="gate5-dev", snapshot="python:3.12-slim", wait=True)
        sbx.fs.mkdir("/srv/site", parents=True)
        sbx.fs.upload_file("/srv/site/index.html", io.BytesIO(INDEX))
        session = sbx.process.create_session()
        sbx.process.execute_session_command(
            session.id, "python -m http.server 8080 --directory /srv/site", run_async=True
        )
        time.sleep(1.5)
        print(f"READY sandbox={sbx.id}", flush=True)
        print(f"READY api_key={key}", flush=True)

        minted = httpx.post(
            f"{BASE}/v1/sandboxes/{sbx.id}/preview-tokens",
            json={"port": 8080, "ttl_seconds": 3600},
            headers={"Authorization": f"Bearer {key}"},
            timeout=10,
        ).json()["data"]
        preview_host = minted["url"].split("//", 1)[1].split("/", 1)[0]
        check = httpx.get(
            f"http://127.0.0.1:{PROXY_PORT}/",
            headers={"Host": preview_host},
            params={"sandfort_preview_token": minted["token"]},
            timeout=15,
        )
        assert check.status_code == 200 and b"gate5 dev server" in check.content, (
            check.status_code, check.content[:200])
        print("CHECK preview URL serves the dev server through the proxy", flush=True)
        print(f"READY preview_url=http://{preview_host}/?sandfort_preview_token={minted['token']}",
              flush=True)

        pty = httpx.post(
            f"{BASE}/v1/sandboxes/{sbx.id}/toolbox/pty",
            json={"rows": 24, "cols": 80},
            headers={"Authorization": f"Bearer {key}"},
            timeout=10,
        ).json()["data"]
        terminal = (f"http://127.0.0.1:{PROXY_PORT}/terminal"
                    f"?sandbox={sbx.id}&pty={pty['pty_id']}&token={pty['token']}")
        print(f"READY terminal_url={terminal}", flush=True)
        print("SERVING until killed", flush=True)
        server.wait()
        return 0
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    raise SystemExit(main())
