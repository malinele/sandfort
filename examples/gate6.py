"""Gate 6: enterprise operations, end to end against real server processes.

Proves the sixth delivery phase: process roles (api and worker), org members with roles,
stateless session tokens and the OIDC sign-on exchange. A fresh temporary sqlite database is
migrated and bootstrapped in-process through ``sandfort.admin_cli``, then one api-role and one
worker-role server are started as subprocesses. A tiny local JWKS endpoint (served by this
script) plays the identity provider.

Run: .venv/bin/python examples/gate6.py
Needs no Docker daemon (the ``fake`` driver backs the sandbox routes). Prints one progress
line per step and exits non-zero on any failure; both processes and the database are removed.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

API_PORT = 4196
WORKER_PORT = 4197
JWKS_PORT = 4198
API = f"http://127.0.0.1:{API_PORT}"
WORKER = f"http://127.0.0.1:{WORKER_PORT}"
JWKS_URL = f"http://127.0.0.1:{JWKS_PORT}/jwks.json"
ISSUER = "https://idp.gate6.test"
AUDIENCE = "sandfort-gate6"
KEY_ID = "gate6-key-1"
DEV_EMAIL = "dev@gate6.test"
ADMIN_EMAIL = "admin1@gate6.test"
SECOND_ADMIN_EMAIL = "admin2@gate6.test"
TOKEN_LIFETIME_S = 300
HEALTH_TIMEOUT_S = 40.0


def check(condition: bool, message: str) -> None:
    """Fail the gate (non-zero exit) unless ``condition`` holds."""
    if not condition:
        raise SystemExit(f"GATE6 FAIL: {message}")


def step(message: str) -> None:
    print(f"CHECK {message}", flush=True)


def serve_jwks(document: dict[str, Any]) -> HTTPServer:
    """Serve ``document`` at /jwks.json on localhost from a daemon thread."""
    body = json.dumps(document).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http.server naming
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return None

    server = HTTPServer(("127.0.0.1", JWKS_PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def wait_health(base: str) -> None:
    deadline = time.time() + HEALTH_TIMEOUT_S
    while time.time() < deadline:
        try:
            if httpx.get(f"{base}/healthz", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    raise SystemExit(f"GATE6 FAIL: {base} did not become healthy")


def provision(db_path: str, env: dict[str, str]) -> tuple[str, str]:
    """Migrate and bootstrap in-process; return (platform key, org id)."""
    os.environ.update(env)
    from sandfort import admin_cli

    admin_cli.migrate()
    key = admin_cli.bootstrap("Gate6", "gate6")
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT id FROM organizations WHERE slug = 'gate6'").fetchone()
    check(row is not None, "bootstrap org row missing")
    return key, str(row[0])


def spawn(role: str, port: int, env: dict[str, str]) -> subprocess.Popen[bytes]:
    server_env = {**env, "SANDFORT_ROLE": role, "SANDFORT_PORT": str(port)}
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


def mint_identity_token(private_key: rsa.RSAPrivateKey, email: str) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "gate6-subject-1",
        "email": email,
        "email_verified": True,
        "iat": now,
        "exp": now + TOKEN_LIFETIME_S,
    }
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": KEY_ID})


def add_member(client: httpx.Client, email: str, role: str) -> httpx.Response:
    body = {"email": email, "display_name": email.split("@")[0], "role": role}
    return client.post("/v1/org/members", json=body)


def member_by_email(client: httpx.Client, email: str) -> dict[str, Any] | None:
    listed = client.get("/v1/org/members")
    check(listed.status_code == 200, f"list members -> {listed.status_code}")
    return next((m for m in listed.json()["data"] if m["email"] == email), None)


def run_gate(key: str, private_key: rsa.RSAPrivateKey) -> None:
    with httpx.Client(base_url=API, headers={"Authorization": f"Bearer {key}"}, timeout=15) as c:
        # (3) roles: api serves docs, worker serves health only.
        docs = httpx.get(f"{API}/docs", timeout=10)
        check(docs.status_code == 200, f"api /docs -> {docs.status_code}")
        step("api role serves the openapi docs route")
        business = httpx.get(f"{WORKER}/v1/sandboxes", timeout=10)
        check(business.status_code == 404, f"worker business route -> {business.status_code}")
        worker_health = httpx.get(f"{WORKER}/healthz", timeout=10)
        check(worker_health.status_code == 200, f"worker /healthz -> {worker_health.status_code}")
        step("worker role returns 404 for a business route and ok for /healthz")

        # (4) members: create, list, re-role, remove.
        created = add_member(c, DEV_EMAIL, "developer")
        check(created.status_code == 201, f"create developer -> {created.status_code}")
        dev = member_by_email(c, DEV_EMAIL)
        check(dev is not None and dev["role"] == "developer", f"developer not listed: {dev}")
        step("developer member created and listed")
        patched = c.patch(f"/v1/org/members/{dev['user_id']}", json={"role": "viewer"})
        check(patched.status_code == 200, f"re-role -> {patched.status_code}")
        check(patched.json()["data"]["role"] == "viewer", "re-role response is not viewer")
        dev = member_by_email(c, DEV_EMAIL)
        check(dev is not None and dev["role"] == "viewer", f"viewer role not persisted: {dev}")
        step("member re-roled to viewer")

        first = add_member(c, ADMIN_EMAIL, "admin")
        second = add_member(c, SECOND_ADMIN_EMAIL, "admin")
        check(first.status_code == 201 and second.status_code == 201, "create admins failed")
        first_id = first.json()["data"]["user_id"]
        second_id = second.json()["data"]["user_id"]
        removed = c.delete(f"/v1/org/members/{first_id}")
        check(removed.status_code == 204, f"remove non-last admin -> {removed.status_code}")
        check(member_by_email(c, ADMIN_EMAIL) is None, "removed admin is still listed")
        step("a non-last admin can be removed")
        refused = c.delete(f"/v1/org/members/{second_id}")
        check(refused.status_code == 409, f"remove last admin -> {refused.status_code}")
        check(member_by_email(c, SECOND_ADMIN_EMAIL) is not None, "last admin vanished")
        step("removing the last admin is refused with 409")

    # (5) OIDC exchange for the viewer member.
    identity = mint_identity_token(private_key, DEV_EMAIL)
    exchange = httpx.post(f"{API}/v1/auth/sso/exchange", json={"id_token": identity}, timeout=15)
    check(exchange.status_code == 200, f"sso exchange -> {exchange.status_code} {exchange.text}")
    session = exchange.json()["data"]
    check(bool(session.get("session_token")), "no session token returned")
    check(session["role"] == "viewer", f"session role is {session['role']!r}, not viewer")
    step("identity token exchanged for a viewer session token")

    # (6) the viewer session reads but cannot administer.
    headers = {"Authorization": f"Bearer {session['session_token']}"}
    listed = httpx.get(f"{API}/v1/sandboxes", headers=headers, timeout=15)
    check(listed.status_code == 200, f"viewer list sandboxes -> {listed.status_code}")
    step("viewer session can list sandboxes")
    denied = httpx.post(
        f"{API}/v1/org/members",
        json={"email": "x@gate6.test", "display_name": "x", "role": "viewer"},
        headers=headers,
        timeout=15,
    )
    check(denied.status_code == 403, f"viewer create member -> {denied.status_code}")
    step("viewer session is refused with 403 on an admin endpoint")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="sandfort-gate6-")
    db_path = os.path.join(tmp, "gate6.db")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwks: HTTPServer | None = None
    processes: list[subprocess.Popen[bytes]] = []
    try:
        jwks = serve_jwks({"keys": [{**jwk, "kid": KEY_ID, "use": "sig", "alg": "RS256"}]})
        env = {
            **os.environ,
            "PYTHONPATH": str(REPO / "src"),
            "SANDFORT_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "SANDFORT_DRIVER": "fake",
            "SANDFORT_API_KEY_PEPPER": os.urandom(16).hex(),
            "SANDFORT_SESSION_SECRET": os.urandom(32).hex(),
            "SANDFORT_OIDC_ISSUER": ISSUER,
            "SANDFORT_OIDC_AUDIENCE": AUDIENCE,
            "SANDFORT_OIDC_JWKS_URL": JWKS_URL,
        }
        key, org_id = provision(db_path, env)
        check(key.startswith("sf_"), "bootstrap did not return an sf_ key")
        step("database migrated and org bootstrapped")
        env["SANDFORT_OIDC_ORG_ID"] = org_id

        processes.append(spawn("api", API_PORT, env))
        processes.append(spawn("worker", WORKER_PORT, env))
        wait_health(API)
        wait_health(WORKER)
        step("api and worker processes are healthy")

        run_gate(key, private_key)
        print("GATE6 PASS", flush=True)
        return 0
    finally:
        for process in processes:
            stop(process)
        if jwks is not None:
            jwks.shutdown()
            jwks.server_close()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
