"""Gate 2 demo: full toolbox on real Docker, on alpine and debian images.

Run: .venv/bin/python examples/gate2.py
Requires a local Docker daemon and outbound network (clones a public repo).
Spawns the API server on a temp SQLite database and drives everything through
the public SDK: fs upload/download, git clone/add/commit, sessions with
persisted cwd, async commands with live SSE log follow, an interactive PTY
with resize, and container logs. Exits non-zero if any step fails.
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

PORT = 4198
BASE = f"http://127.0.0.1:{PORT}"
CLONE_URL = "https://github.com/octocat/Hello-World.git"

APP_PY = b"def add(a: int, b: int) -> int:\n    return a + b\n"
TEST_PY = (
    b"import unittest\n"
    b"from calculator import add\n\n"
    b"class TestAdd(unittest.TestCase):\n"
    b"    def test_add(self) -> None:\n"
    b"        self.assertEqual(add(21, 21), 42)\n\n"
    b"if __name__ == '__main__':\n"
    b"    unittest.main()\n"
)


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


def debian_leg(client: Client, key: str) -> None:
    sbx = client.create_sandbox(name="gate2-debian", snapshot="python:3.12-slim", wait=True)
    step("D1", f"created {sbx.id} (debian) state={sbx.state}")
    try:
        sbx.fs.mkdir("/work/app", parents=True)
        sbx.fs.upload_file("/work/app/calculator.py", io.BytesIO(APP_PY))
        sbx.fs.upload_file("/work/app/test_calculator.py", io.BytesIO(TEST_PY))
        names = [e.name for e in sbx.fs.list_dir("/work/app").entries]
        assert sorted(names) == ["calculator.py", "test_calculator.py"], names
        back = sbx.fs.read_bytes("/work/app/calculator.py")
        assert back == APP_PY
        step("D2", "fs: mkdir + 2 uploads + listing + byte-identical download")

        session = sbx.process.create_session()
        sbx.process.execute_session_command(session.id, "cd /work/app")
        pwd = sbx.process.execute_session_command(session.id, "pwd")
        assert pwd.result is not None and "/work/app" in pwd.result.stdout, pwd
        step("D3", "session: cd /work/app persisted to the next command")

        started = sbx.process.execute_session_command(
            session.id, "python -m unittest discover -v", run_async=True
        )
        assert started.command is not None
        cmd_id = started.command.id
        lines: list[str] = []
        exit_code: int | None = None
        with sbx.process.follow_logs(session.id, cmd_id) as stream:
            for event in stream:
                if event.stream == "exit":
                    exit_code = event.exit_code
                    break
                lines.append(event.line)
                print("    | " + event.line.rstrip(), flush=True)
        joined = "".join(lines)
        assert exit_code == 0, (exit_code, joined)
        assert "OK" in joined, joined
        step("D4", "async unittest run streamed live over SSE and exited 0")

        with sbx.pty.create(rows=24, cols=80) as pty:
            pty.send_bytes(b"echo GATE2-$((6*7))\n")
            buf = b""
            for chunk in pty:
                buf += chunk
                if b"GATE2-42" in buf.replace(b"\r", b""):
                    break
            pty.resize(31, 97)
            time.sleep(0.5)
            pty.send_bytes(b"stty size\n")
            buf = b""
            for chunk in pty:
                buf += chunk
                if b"31 97" in buf.replace(b"\r", b""):
                    break
        step("D5", "pty: echo round-trip + resize reflected by stty size (31 97)")

        with httpx.stream(
            "GET",
            f"{BASE}/v1/sandboxes/{sbx.id}/logs",
            params={"tail": 50},
            headers={"Authorization": f"Bearer {key}"},
            timeout=15,
        ) as resp:
            assert resp.status_code == 200, resp.status_code
            resp.read()
        step("D6", "container logs endpoint serves the tail")
    finally:
        client.stop(sbx.id)
        client.delete(sbx.id)
        step("D7", f"deleted {sbx.id}")


def alpine_leg(client: Client) -> None:
    sbx = client.create_sandbox(name="gate2-alpine", snapshot="alpine:3.20", wait=True)
    step("A1", f"created {sbx.id} (alpine) state={sbx.state}")
    try:
        session = sbx.process.create_session()
        apk = sbx.process.execute_session_command(
            session.id, "apk add --no-progress git", timeout_s=120
        )
        assert apk.result is not None and apk.result.exit_code == 0, apk
        step("A2", "apk add git succeeded (network + busybox session)")

        clone = sbx.git.clone(CLONE_URL, "/work/hello")
        assert clone.path == "/work/hello", clone
        names = [e.name for e in sbx.fs.list_dir("/work/hello").entries]
        assert "README" in names, names
        step("A3", f"cloned {CLONE_URL} -> README present")

        sbx.fs.upload_file("/work/hello/NOTES.md", io.BytesIO(b"gate 2 was here\n"))
        sbx.process.execute_session_command(
            session.id,
            "cd /work/hello && git config user.email gate2@sandfort.local"
            " && git config user.name Gate2",
        )
        sbx.git.add("/work/hello", ["NOTES.md"])
        commit = sbx.git.commit("/work/hello", "docs: gate 2 marker")
        assert commit.sha, commit
        status = sbx.git.status("/work/hello")
        assert status.is_clean, status
        step("A4", f"fs edit + git add/commit ({commit.sha[:8]}) -> clean tree")

        stat = sbx.fs.stat("/work/hello/NOTES.md")
        assert stat.size_bytes == len(b"gate 2 was here\n"), stat
        step("A5", "busybox stat parsed correctly on alpine")
    finally:
        client.stop(sbx.id)
        client.delete(sbx.id)
        step("A6", f"deleted {sbx.id}")


def check_audit(key: str) -> None:
    audit = httpx.get(
        f"{BASE}/v1/audit-events",
        params={"limit": 100},
        headers={"Authorization": f"Bearer {key}"},
        timeout=10,
    ).json()
    data = audit.get("data", audit)
    items = data if isinstance(data, list) else data["items"]
    actions = {row["action"] for row in items}
    needed = {
        "sandbox.create",
        "toolbox.fs.upload",
        "toolbox.git.clone",
        "toolbox.git.commit",
        "toolbox.session.create",
        "toolbox.session.exec",
        "toolbox.pty.create",
        "sandbox.logs.read",
        "sandbox.delete",
    }
    missing = needed - actions
    assert not missing, f"audit actions missing: {missing}"
    step("G1", f"audit trail covers the full toolbox ({len(items)} rows)")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="sandfort-gate2-")
    db = os.path.join(tmp, "gate2.db")
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
         "--org-name", "Gate2", "--org-slug", "gate2"],
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
        debian_leg(client, key)
        alpine_leg(client)
        check_audit(key)
        print("GATE 2: PASS")
        return 0
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
