"""Git toolbox against a real local daemon and an authenticated git HTTP server on the host.

Skipped when no daemon is reachable, the git-capable image cannot be pulled, the host has no
``git http-backend``, or the sandbox cannot reach the host. A session-scoped fixture serves a
bare repository through ``git http-backend`` (a stdlib ``http.server`` acting as the CGI
host) behind HTTP basic auth on all interfaces; the sandbox, created with the default open
network policy, reaches it through the Docker Desktop host gateway name. The test clones
with a credential, commits a file written through the fs toolbox, pushes it back with the
credential, then checks that the push landed, that no askpass helper is left, and that the
token is in no process environment, audit row or stored log; an unauthenticated clone fails.
"""

import base64
import contextlib
import hmac
import os
import shutil
import subprocess
import threading
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.base import ExecRequest, SandboxSpec
from sandfort.drivers.docker.client import make_client
from sandfort.ids import new_api_key_id, new_org_id, new_sandbox_id
from sandfort.toolbox.git_credentials import ASKPASS_DIR

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "alpine/git:latest"
PEPPER = "test-pepper"
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX, Scope.AUDIT_READ})
GIT_USER = "sandfort-ci"
GIT_TOKEN = "sf-e2e-git-token-5d1c0b7e93a4"  # fixed throwaway secret of the local test server
HOST_GATEWAY = "host.docker.internal"
REPO_NAME = "repo.git"
BRANCH = "main"
CLONE_PATH = "/work/repo"
CGI_TIMEOUT_S = 60
HOST_GIT_TIMEOUT_S = 60
AUDIT_PAGE = 100
# Every process environment in the sandbox, then the exec's own; ``env`` keeps the exit 0.
ENVIRON_SCRIPT = "cat /proc/[0-9]*/environ 2>/dev/null; echo; env"


# --- host-side git HTTP server ----------------------------------------------------------


def host_git(home: Path, *args: str) -> str:
    """Run the host ``git`` isolated from the user's configuration."""
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("GIT_") and name != "XDG_CONFIG_HOME"
    }
    env.update(
        HOME=str(home),
        GIT_CONFIG_NOSYSTEM="1",
        GIT_AUTHOR_NAME="Seed",
        GIT_AUTHOR_EMAIL="seed@sandfort.test",
        GIT_COMMITTER_NAME="Seed",
        GIT_COMMITTER_EMAIL="seed@sandfort.test",
    )
    completed = subprocess.run(
        ["git", *args],
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=HOST_GIT_TIMEOUT_S,
    )
    return completed.stdout.strip()


def parse_cgi(output: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
    head, separator, payload = output.partition(b"\r\n\r\n")
    if not separator:
        head, _, payload = output.partition(b"\n\n")
    status = 200
    headers: list[tuple[str, str]] = []
    for line in head.decode("latin-1").splitlines():
        name, _, value = line.partition(":")
        if name.lower() == "status":
            status = int(value.split()[0])
        elif name and name.lower() != "content-length":
            headers.append((name.strip(), value.strip()))
    return status, headers, payload


def make_handler(projects: Path, backend: Path, home: Path) -> type[BaseHTTPRequestHandler]:
    basic = base64.b64encode(f"{GIT_USER}:{GIT_TOKEN}".encode()).decode()
    expected = f"Basic {basic}".encode()

    class GitBackendHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._serve()

        def do_POST(self) -> None:
            self._serve()

        def log_message(self, format: str, *args: Any) -> None:
            return  # keep pytest output quiet

        def _serve(self) -> None:
            supplied = self.headers.get("Authorization", "").encode()
            if not hmac.compare_digest(supplied, expected):
                challenge = [("WWW-Authenticate", 'Basic realm="sandfort-test"')]
                self._reply(401, challenge, b"authentication required\n")
                return
            body = self._read_body()
            path, _, query = self.path.partition("?")
            env = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(home),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_PROJECT_ROOT": str(projects),
                "GIT_HTTP_EXPORT_ALL": "1",
                "GATEWAY_INTERFACE": "CGI/1.1",
                "REQUEST_METHOD": self.command,
                "PATH_INFO": unquote(path),
                "QUERY_STRING": query,
                "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                "CONTENT_LENGTH": str(len(body)),
                "REMOTE_USER": GIT_USER,  # enables receive-pack (push)
                "REMOTE_ADDR": self.client_address[0],
            }
            encoding = self.headers.get("Content-Encoding")
            if encoding:
                env["HTTP_CONTENT_ENCODING"] = encoding
            completed = subprocess.run(
                [str(backend)],
                input=body,
                env=env,
                capture_output=True,
                check=False,
                timeout=CGI_TIMEOUT_S,
            )
            if not completed.stdout:
                self._reply(500, [], completed.stderr or b"http-backend produced no output\n")
                return
            self._reply(*parse_cgi(completed.stdout))

        def _read_body(self) -> bytes:
            if self.headers.get("Transfer-Encoding", "").lower() != "chunked":
                length = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(length) if length else b""
            chunks: list[bytes] = []
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip(), 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass  # optional trailers
                    return b"".join(chunks)
                chunks.append(self.rfile.read(size))
                self.rfile.readline()

        def _reply(self, status: int, headers: list[tuple[str, str]], payload: bytes) -> None:
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    return GitBackendHandler


@dataclass(frozen=True)
class GitServer:
    port: int
    bare: Path
    home: Path

    @property
    def url(self) -> str:
        return f"http://{HOST_GATEWAY}:{self.port}/{REPO_NAME}"

    def head(self) -> str:
        ref = f"refs/heads/{BRANCH}"
        return host_git(self.home, "--git-dir", str(self.bare), "rev-parse", ref)


def seed_bare_repository(root: Path, home: Path) -> Path:
    projects = root / "projects"
    projects.mkdir()
    bare = projects / REPO_NAME
    seed = root / "seed"
    host_git(home, "init", "--bare", f"--initial-branch={BRANCH}", str(bare))
    host_git(home, "init", f"--initial-branch={BRANCH}", str(seed))
    (seed / "README.md").write_text("seed\n")
    host_git(home, "-C", str(seed), "add", "README.md")
    host_git(home, "-C", str(seed), "commit", "-m", "seed")
    host_git(home, "-C", str(seed), "push", str(bare), BRANCH)
    return bare


@pytest.fixture(scope="session")
def git_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[GitServer]:
    if shutil.which("git") is None:
        pytest.skip("the host has no git")
    root = tmp_path_factory.mktemp("git-http")
    home = root / "home"
    home.mkdir()
    try:
        backend = Path(host_git(home, "--exec-path")) / "git-http-backend"
        bare = seed_bare_repository(root, home)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"host git cannot prepare the test repository: {exc}")
    if not backend.exists():
        pytest.skip(f"the host git has no http-backend at {backend}")
    server = ThreadingHTTPServer(("0.0.0.0", 0), make_handler(bare.parent, backend, home))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield GitServer(port=server.server_address[1], bare=bare, home=home)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# --- app and sandbox ----------------------------------------------------------------------


@pytest.fixture(scope="module")
def client() -> Any:
    try:
        docker_client = make_client()
        docker_client.ping()
    except Exception as exc:
        pytest.skip(f"no reachable Docker daemon: {exc}")
    return docker_client


@pytest.fixture
def image(client: Any) -> str:
    try:
        client.images.get(IMAGE)
    except docker.errors.ImageNotFound:
        try:
            client.images.pull(IMAGE)
        except Exception as exc:
            pytest.skip(f"cannot pull {IMAGE}: {exc}")
    return IMAGE


@pytest.fixture
async def app(tmp_path: Path, client: Any, image: str) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'docker-git.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="docker", database_url=url, api_key_pepper=PEPPER))
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def http(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as session:
        yield session


@pytest.fixture
async def started_sandbox(
    app: FastAPI, client: Any, image: str
) -> AsyncIterator[tuple[str, str, str]]:
    """``(api_key, sandbox_id, ref)`` for a real git-capable container registered as started."""
    org = Org(id=new_org_id(), name="Acme", slug=f"acme-{uuid.uuid4().hex[:6]}", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored_key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    sandbox_id = new_sandbox_id()
    spec = SandboxSpec(
        sandbox_id=sandbox_id,
        org_id=org.id,
        name=f"sf-{sandbox_id}",
        image=image,
        resources=ResourceSpec(cpu_millicores=1000, memory_mib=512, disk_gib=1),
        labels={"suite": "test_docker_git"},
    )
    ref = ""
    try:
        info = await app.state.driver.create(spec)
        ref = info.ref
        await app.state.driver.start(ref)
        sandbox = Sandbox(
            id=sandbox_id,
            org_id=org.id,
            name=sandbox_id,
            state=SandboxState.STARTED,
            image_ref=image,
            driver="docker",
            driver_ref=ref,
            started_at=NOW,
            created_at=NOW,
            updated_at=NOW,
        )
        async with UnitOfWork(app.state.session_factory) as uow:
            await uow.orgs.add(org)
            await uow.api_keys.add(stored_key)
            await uow.sandboxes.add(sandbox)
            await uow.commit()
        yield generated.key, sandbox_id, ref
    finally:
        if ref:
            with contextlib.suppress(docker.errors.NotFound):
                client.api.remove_container(ref, v=True, force=True)


# --- helpers ------------------------------------------------------------------------------


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def toolbox_path(sandbox_id: str, *parts: str) -> str:
    return "/".join([f"/v1/sandboxes/{sandbox_id}/toolbox", *parts])


async def post(http: httpx.AsyncClient, key: str, path: str, payload: dict[str, Any]) -> Any:
    response = await http.post(path, headers=auth(key), json=payload)
    assert response.status_code == 200, response.text
    assert GIT_TOKEN not in response.text
    return response.json()["data"]


async def require_host_reachable(app: FastAPI, ref: str, url: str) -> None:
    """Skip unless the sandbox reaches the host server (it answers 401 without a credential)."""
    request = ExecRequest(
        argv=["git", "ls-remote", url], env={"GIT_TERMINAL_PROMPT": "0"}, timeout_s=60.0
    )
    probe = await app.state.driver.exec(ref, request)
    stderr = probe.stderr.decode(errors="replace")
    if not any(sign in stderr for sign in ("could not read Username", "Authentication failed")):
        pytest.skip(f"the sandbox cannot reach the host git server: {stderr.strip()}")


def stored_log_bytes(app: FastAPI) -> bytes:
    runtime = getattr(app.state, "session_runtime", None)
    if runtime is None:
        return b""
    buckets = runtime.logs._orgs.values()
    logs = [log for bucket in buckets for log in bucket.logs.values()]
    return b"".join(chunk.data for log in logs for chunk in log.read(0).chunks)


# --- test ---------------------------------------------------------------------------------


async def test_credentialed_clone_commit_push_leaves_no_credential_behind(
    git_server: GitServer,
    app: FastAPI,
    http: httpx.AsyncClient,
    started_sandbox: tuple[str, str, str],
    tmp_path: Path,
) -> None:
    key, sandbox_id, ref = started_sandbox
    await require_host_reachable(app, ref, git_server.url)
    before = git_server.head()
    credential = {"username": GIT_USER, "token": GIT_TOKEN}

    cloned = await post(
        http,
        key,
        toolbox_path(sandbox_id, "git", "clone"),
        {"url": git_server.url, "path": CLONE_PATH, "credential": credential},
    )
    uploaded = await http.put(
        toolbox_path(sandbox_id, "fs", "upload"),
        headers=auth(key),
        params={"path": f"{CLONE_PATH}/hello.txt"},
        content=b"hello from the sandbox\n",
    )
    await post(
        http,
        key,
        toolbox_path(sandbox_id, "git", "add"),
        {"path": CLONE_PATH, "files": ["hello.txt"]},
    )
    committed = await post(
        http,
        key,
        toolbox_path(sandbox_id, "git", "commit"),
        {
            "path": CLONE_PATH,
            "message": "add hello",
            "author_name": "Sandfort CI",
            "author_email": "ci@sandfort.test",
        },
    )
    await post(
        http,
        key,
        toolbox_path(sandbox_id, "git", "push"),
        {
            "path": CLONE_PATH,
            "remote": "origin",
            "branch": BRANCH,
            "credential": credential,
            "remote_url": git_server.url,
        },
    )

    assert cloned["path"] == CLONE_PATH
    assert uploaded.status_code == 200, uploaded.text
    after = git_server.head()
    assert after != before
    assert after == committed["sha"]

    listing = await http.get(
        toolbox_path(sandbox_id, "fs", "list"), headers=auth(key), params={"path": ASKPASS_DIR}
    )
    assert listing.status_code == 200, listing.text
    assert listing.json()["data"]["entries"] == []

    environs = await post(
        http,
        key,
        toolbox_path(sandbox_id, "process", "execute"),
        {"argv": ["sh", "-c", ENVIRON_SCRIPT]},
    )
    assert "PATH=" in environs["stdout"]
    assert GIT_TOKEN not in environs["stdout"] + environs["stderr"]

    audit = await http.get("/v1/audit-events", headers=auth(key), params={"limit": AUDIT_PAGE})
    assert audit.status_code == 200, audit.text
    actions = {event["action"] for event in audit.json()["data"]}
    expected = {"toolbox.git.clone", "toolbox.git.add", "toolbox.git.commit", "toolbox.git.push"}
    assert expected <= actions
    assert GIT_TOKEN not in audit.text
    assert GIT_TOKEN.encode() not in stored_log_bytes(app)
    for stored in tmp_path.glob("docker-git.db*"):
        assert GIT_TOKEN.encode() not in stored.read_bytes()

    anonymous = await http.post(
        toolbox_path(sandbox_id, "git", "clone"),
        headers=auth(key),
        json={"url": git_server.url, "path": "/work/anonymous"},
    )
    assert anonymous.status_code == 409, anonymous.text
    assert GIT_TOKEN not in anonymous.text
