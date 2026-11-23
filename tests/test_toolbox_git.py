"""``/v1/sandboxes/{id}/toolbox/git``: FakeDriver, temp SQLite, httpx ASGI transport.

Daemon-free. Every git operation and every askpass helper step is an exec, so the FakeDriver
exec handler is scripted per test and records each request: tests assert the exact argv,
that ``GIT_ASKPASS`` is set on the credentialed git exec only, that the helper is removed
even when the operation fails, and that the token never shows up in an argv, environment,
audit row, stored log or response body. Assertions go through HTTP status codes and bodies
only (the routes sit behind the app factory, so route tables are never introspected).
"""

import shutil
import subprocess
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.schemas.toolbox_git import GitCredential
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.base import ExecRequest, ExecResult
from sandfort.drivers.errors import DriverError
from sandfort.drivers.fake import FakeDriver
from sandfort.errors import Unprocessable
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.toolbox.git import parse_status
from sandfort.toolbox.git_credentials import (
    ASKPASS_DIR,
    REDACTED,
    WRITE_ARGV0,
    WRITE_SCRIPT,
    ephemeral_askpass,
    redact,
    render_askpass,
    strip_userinfo,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
FULL_ACCESS = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.TOOLBOX})
USERNAME = "deploy-bot"
TOKEN = "ghp_SandfortUnitTestToken0123456789"
CREDENTIAL = {"username": USERNAME, "token": TOKEN}
URL = "https://git.example.test/acme/app.git"
REPO = "/work/app"
SHA = "0123456789abcdef0123456789abcdef01234567"
NO_PROMPT = {"GIT_TERMINAL_PROMPT": "0"}
NULL_CONFIG = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
BASE_URL = "https://git.example.test/"
HARDENING = [
    "-c",
    "credential.helper=",
    "-c",
    "core.hooksPath=/nonexistent/sandfort-no-hooks",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "http.sslVerify=true",
    "-c",
    "http.proxy=",
]
TARGET_PINS = [
    "-c",
    f"credential.username={USERNAME}",
    "-c",
    f"url.{BASE_URL}.insteadOf={BASE_URL}",
]

type Outcome = ExecResult | Exception | Callable[[ExecRequest], ExecResult]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'git.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    settings = Settings(driver="fake", database_url=url, api_key_pepper=PEPPER)
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
def driver(app: FastAPI) -> FakeDriver:
    fake = app.state.driver
    assert isinstance(fake, FakeDriver)
    return fake


async def add_org(app: FastAPI, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


async def add_key(app: FastAPI, org_id: str, scopes: frozenset[Scope]) -> str:
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=scopes,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "acme")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id, FULL_ACCESS)


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def call(
    client: httpx.AsyncClient, method: str, path: str, key: str, *, status: int, **kwargs: Any
) -> httpx.Response:
    response = await client.request(method, path, headers=auth(key), **kwargs)
    assert response.status_code == status, response.text
    assert response.json()["success"] is (status < 400)
    return response


def git_path(sandbox_id: str, action: str) -> str:
    return f"{BASE}/{sandbox_id}/toolbox/git/{action}"


async def post_git(
    client: httpx.AsyncClient,
    key: str,
    sandbox_id: str,
    action: str,
    payload: dict[str, Any],
    *,
    status: int = 200,
) -> httpx.Response:
    path = git_path(sandbox_id, action)
    return await call(client, "POST", path, key, status=status, json=payload)


async def create_sandbox(client: httpx.AsyncClient, key: str) -> str:
    response = await call(client, "POST", BASE, key, status=201, json={})
    sandbox_id: str = response.json()["data"]["id"]
    return sandbox_id


def out(text: str) -> ExecResult:
    return ExecResult(exit_code=0, stdout=text.encode())


def failed(stderr: str, exit_code: int = 128) -> ExecResult:
    return ExecResult(exit_code=exit_code, stderr=stderr.encode())


def subcommand(argv: Sequence[str]) -> str:
    """The git subcommand after global ``-C <dir>`` / ``-c <key=value>`` options."""
    args = list(argv[1:])
    while args[:1] in (["-C"], ["-c"]):
        args = args[2:]
    return args[0] if args else ""


class ScriptedExec:
    """FakeDriver exec handler: git outcomes by subcommand, helper outcomes by program name."""

    def __init__(
        self,
        git: Mapping[str, Outcome] | None = None,
        helpers: Mapping[str, Outcome] | None = None,
    ) -> None:
        # A credentialed push/pull first asks the repo which url its remote points at.
        self.git: dict[str, Outcome] = {"remote": out(URL), **(git or {})}
        self.helpers = dict(helpers or {})
        self.seen: list[ExecRequest] = []

    def __call__(self, env: Mapping[str, str], request: ExecRequest) -> ExecResult:
        self.seen.append(request)
        if request.argv[0] == "git":
            outcome = self.git.get(subcommand(request.argv), ExecResult(exit_code=0))
        else:
            outcome = self.helpers.get(request.argv[0], ExecResult(exit_code=0))
        if isinstance(outcome, Exception):
            raise outcome
        return outcome if isinstance(outcome, ExecResult) else outcome(request)

    def argvs(self) -> list[list[str]]:
        return [list(request.argv) for request in self.seen]

    def git_requests(self) -> list[ExecRequest]:
        return [request for request in self.seen if request.argv[0] == "git"]


def script(
    driver: FakeDriver,
    git: Mapping[str, Outcome] | None = None,
    helpers: Mapping[str, Outcome] | None = None,
) -> ScriptedExec:
    handler = ScriptedExec(git, helpers)
    driver.exec_handler = handler
    return handler


def leaking(request: ExecRequest) -> ExecResult:
    """A remote that echoes the token and helper path back on both streams."""
    helper = request.env.get("GIT_ASKPASS", "")
    text = f"remote: https://{USERNAME}:{TOKEN}@git.example.test {TOKEN} {helper}\n"
    return ExecResult(exit_code=0, stdout=text.encode(), stderr=text.encode())


def assert_token_absent(requests: Sequence[ExecRequest]) -> None:
    for request in requests:
        assert all(TOKEN not in part for part in request.argv)
        assert all(TOKEN not in value for value in request.env.values())


async def audit_events(app: FastAPI, org_id: str) -> list[Any]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(await uow.audit.list(org_id, limit=200))


def stored_log_bytes(app: FastAPI) -> bytes:
    """Everything held by the in-process command log store (empty when never created)."""
    runtime = getattr(app.state, "session_runtime", None)
    if runtime is None:
        return b""
    logs = [log for bucket in runtime.logs._orgs.values() for log in bucket.logs.values()]
    return b"".join(chunk.data for log in logs for chunk in log.read(0).chunks)


# --- argv composition -----------------------------------------------------------------


async def test_clone_without_credential_runs_one_git_exec_without_askpass(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver)

    response = await post_git(client, key, sandbox_id, "clone", {"url": URL, "path": REPO})

    assert response.json()["data"] == {"path": REPO, "output": ""}
    assert handler.argvs() == [["git", "clone", "--", URL, REPO]]
    assert handler.seen[0].env == NO_PROMPT


async def test_clone_with_credential_sets_askpass_on_the_git_exec_only(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver)
    payload = {"url": URL, "path": REPO, "branch": "main", "depth": 1, "credential": CREDENTIAL}

    await post_git(client, key, sandbox_id, "clone", payload)

    mkdir, write, clone, remove = handler.seen
    helper = write.argv[-1]
    assert helper.startswith(f"{ASKPASS_DIR}/askpass-")
    assert list(mkdir.argv) == ["mkdir", "-p", "-m", "700", ASKPASS_DIR]
    assert list(write.argv) == ["sh", "-c", WRITE_SCRIPT, WRITE_ARGV0, helper]
    assert write.stdin == render_askpass(GitCredential(username=USERNAME, token=TOKEN), URL)
    assert list(clone.argv) == [
        "git",
        *HARDENING,
        *TARGET_PINS,
        "clone",
        "--branch",
        "main",
        "--depth",
        "1",
        "--",
        URL,
        REPO,
    ]
    assert clone.env == {**NO_PROMPT, **NULL_CONFIG, "GIT_ASKPASS": helper}
    assert list(remove.argv) == ["rm", "-f", helper]
    with_askpass = ["GIT_ASKPASS" in request.env for request in handler.seen]
    assert with_askpass == [False, False, True, False]
    assert_token_absent(handler.seen)


@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_status_parses_porcelain_output(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, method: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    porcelain = (
        "## main...origin/main [ahead 2, behind 1]\x00 M src/app.py\x00"
        "R  new.txt\x00old.txt\x00?? notes.md\x00"
    )
    handler = script(driver, git={"status": out(porcelain)})
    request: dict[str, Any] = (
        {"params": {"path": REPO}} if method == "GET" else {"json": {"path": REPO}}
    )

    response = await call(
        client, method, git_path(sandbox_id, "status"), key, status=200, **request
    )

    assert handler.argvs() == [["git", "-C", REPO, "status", "--porcelain=v1", "--branch", "-z"]]
    assert handler.seen[0].env == {}
    assert response.json()["data"] == {
        "branch": "main",
        "ahead": 2,
        "behind": 1,
        "files": [
            {"path": "src/app.py", "index": " ", "worktree": "M"},
            {"path": "new.txt", "index": "R", "worktree": " "},
            {"path": "notes.md", "index": "?", "worktree": "?"},
        ],
    }


def test_parse_status_handles_unborn_and_detached_heads() -> None:
    unborn = parse_status(b"## No commits yet on main\x00A  README.md\x00")
    detached = parse_status(b"## HEAD (no branch)\x00")

    assert (unborn.branch, unborn.ahead, unborn.behind) == ("main", 0, 0)
    assert [(f.path, f.index, f.worktree) for f in unborn.files] == [("README.md", "A", " ")]
    assert detached.branch is None and detached.files == ()


async def test_add_passes_paths_after_double_dash(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver)

    await post_git(client, key, sandbox_id, "add", {"path": REPO, "files": ["a.txt", "-odd"]})
    await post_git(client, key, sandbox_id, "add", {"path": REPO})

    assert handler.argvs() == [
        ["git", "-C", REPO, "add", "--", "a.txt", "-odd"],
        ["git", "-C", REPO, "add", "--", "."],
    ]


async def test_commit_passes_author_as_config_and_returns_head_sha(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver, git={"rev-parse": out(SHA + "\n")})
    payload = {
        "path": REPO,
        "message": "initial import",
        "author_name": "Ada Lovelace",
        "author_email": "ada@example.test",
    }

    response = await post_git(client, key, sandbox_id, "commit", payload)

    assert response.json()["data"] == {"sha": SHA}
    assert handler.argvs() == [
        [
            "git",
            "-C",
            REPO,
            "-c",
            "user.name=Ada Lovelace",
            "-c",
            "user.email=ada@example.test",
            "commit",
            "-m",
            "initial import",
        ],
        ["git", "-C", REPO, "rev-parse", "HEAD"],
    ]


@pytest.mark.parametrize("action", ["push", "pull"])
async def test_credentialed_push_and_pull_use_a_fresh_helper_each_time(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, action: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver)
    payload = {"path": REPO, "branch": "main", "credential": CREDENTIAL, "remote_url": URL}

    for _ in range(2):
        await post_git(client, key, sandbox_id, action, payload)

    gits = [request for request in handler.git_requests() if subcommand(request.argv) == action]
    helpers = [request.env["GIT_ASKPASS"] for request in gits]
    expected = ["git", "-C", REPO, *HARDENING, *TARGET_PINS, action, URL, "main"]
    assert [list(request.argv) for request in gits] == [expected, expected]
    assert len(set(helpers)) == 2
    removed = [request.argv[-1] for request in handler.seen if request.argv[0] == "rm"]
    assert removed == helpers
    assert all(request.env.items() >= NULL_CONFIG.items() for request in gits)
    assert_token_absent(handler.seen)


async def test_credentialed_push_resolves_the_remote_url_without_the_askpass_env(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver)

    payload = {"path": REPO, "credential": CREDENTIAL, "remote_url": URL}

    await post_git(client, key, sandbox_id, "push", payload)

    lookup = handler.seen[0]
    expected = ["git", "-C", REPO, *HARDENING, "remote", "get-url", "--push", "origin"]
    assert list(lookup.argv) == expected
    assert lookup.env == {**NO_PROMPT, **NULL_CONFIG}


@pytest.mark.parametrize("action", ["push", "pull"])
async def test_push_and_pull_without_credential_have_no_askpass(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, action: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver)

    await post_git(client, key, sandbox_id, action, {"path": REPO})

    assert handler.argvs() == [["git", "-C", REPO, action, "origin"]]
    assert handler.seen[0].env == NO_PROMPT


# --- cleanup ----------------------------------------------------------------------------


async def test_helper_is_removed_when_the_git_exec_fails(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)

    def rejected(request: ExecRequest) -> ExecResult:
        helper = request.env["GIT_ASKPASS"]
        return failed(f"fatal: auth failed for 'https://{USERNAME}:{TOKEN}@h/' via {helper}")

    handler = script(driver, git={"push": rejected})

    payload = {"path": REPO, "credential": CREDENTIAL, "remote_url": URL}

    response = await post_git(client, key, sandbox_id, "push", payload, status=409)

    helper = handler.git_requests()[-1].env["GIT_ASKPASS"]
    assert [argv[0] for argv in handler.argvs()] == ["git", "mkdir", "sh", "git", "rm"]
    assert handler.argvs()[-1] == ["rm", "-f", helper]
    assert TOKEN not in response.text and helper not in response.text
    assert REDACTED in response.json()["error"]["message"]


async def test_helper_is_removed_when_the_driver_raises(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver, git={"clone": DriverError("connection reset by sandbox")})
    payload = {"url": URL, "path": REPO, "credential": CREDENTIAL}

    await post_git(client, key, sandbox_id, "clone", payload, status=502)

    assert [argv[0] for argv in handler.argvs()] == ["mkdir", "sh", "git", "rm"]


async def test_failed_install_runs_no_git_but_still_removes(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver, helpers={"sh": failed("read-only file system", 1)})
    payload = {"path": REPO, "credential": CREDENTIAL, "remote_url": URL}

    await post_git(client, key, sandbox_id, "pull", payload, status=502)

    assert [argv[0] for argv in handler.argvs()] == ["git", "mkdir", "sh", "rm"]


async def test_cleanup_failure_after_success_is_reported(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    script(driver, helpers={"rm": failed("device busy", 1)})
    payload = {"path": REPO, "credential": CREDENTIAL, "remote_url": URL}

    response = await post_git(client, key, sandbox_id, "push", payload, status=502)

    assert response.json()["error"]["message"] == "could not remove the git credential helper"


class StubDriver:
    def __init__(self, failing: str | None = None) -> None:
        self.failing = failing
        self.seen: list[ExecRequest] = []

    async def exec(self, ref: str, request: ExecRequest) -> ExecResult:
        self.seen.append(request)
        return failed("nope", 1) if request.argv[0] == self.failing else ExecResult(exit_code=0)


@pytest.mark.parametrize("failing", [None, "rm"])
async def test_operation_error_wins_and_helper_removal_still_runs(failing: str | None) -> None:
    stub = StubDriver(failing)
    credential = GitCredential(username=USERNAME, token=TOKEN)

    with pytest.raises(RuntimeError, match="boom"):
        async with ephemeral_askpass(stub, "ref-1", credential, URL) as askpass:
            raise RuntimeError("boom")

    assert [request.argv[0] for request in stub.seen] == ["mkdir", "sh", "rm"]
    assert list(stub.seen[-1].argv) == ["rm", "-f", askpass.path]


# --- secrecy ----------------------------------------------------------------------------


async def test_token_never_reaches_audit_logs_or_responses(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    driver: FakeDriver,
    tmp_path: Path,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver, git={"clone": leaking, "push": leaking, "pull": leaking})
    secret_url = f"https://{USERNAME}:hunter2-in-url@git.example.test/acme/app.git"
    requests = [
        ("clone", {"url": secret_url, "path": REPO, "credential": CREDENTIAL}),
        (
            "push",
            {"path": REPO, "remote": secret_url, "credential": CREDENTIAL, "remote_url": URL},
        ),
        ("pull", {"path": REPO, "credential": CREDENTIAL, "remote_url": URL}),
    ]

    responses = [
        await post_git(client, key, sandbox_id, action, payload) for action, payload in requests
    ]

    for response in responses:
        assert TOKEN not in response.text and ASKPASS_DIR not in response.text
        assert REDACTED in response.json()["data"]["output"]
    assert_token_absent(handler.seen)
    events = await audit_events(app, org_id)
    rows = [event.model_dump_json() for event in events]
    actions = sorted(event.action for event in events if event.action.startswith("toolbox.git."))
    assert actions == ["toolbox.git.clone", "toolbox.git.pull", "toolbox.git.push"]
    assert all(TOKEN not in row and "hunter2-in-url" not in row for row in rows)
    clone_event = next(event for event in events if event.action == "toolbox.git.clone")
    assert clone_event.details["url"] == URL
    auditor = await add_key(app, org_id, frozenset({Scope.AUDIT_READ}))
    listed = await call(client, "GET", "/v1/audit-events", auditor, status=200)
    assert TOKEN not in listed.text and "hunter2-in-url" not in listed.text
    assert TOKEN.encode() not in stored_log_bytes(app)
    for stored in tmp_path.glob("git.db*"):
        assert TOKEN.encode() not in stored.read_bytes()


async def test_invalid_credential_is_rejected_without_echo_or_exec(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver)
    bad = {"username": USERNAME, "token": TOKEN + "\nexit 0"}
    payload = {"path": REPO, "credential": bad, "remote_url": URL}

    response = await post_git(client, key, sandbox_id, "push", payload, status=422)

    assert TOKEN not in response.text
    assert handler.seen == []


@pytest.mark.parametrize(
    ("action", "payload"),
    [
        ("push", {"path": REPO, "remote": "--receive-pack=evil"}),
        ("pull", {"path": REPO, "branch": "-q"}),
        ("clone", {"url": "--upload-pack=evil", "path": REPO}),
        ("status", {"path": "relative/repo"}),
    ],
)
async def test_option_like_or_invalid_arguments_run_nothing(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, action: str, payload: dict[str, Any]
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver)

    await post_git(client, key, sandbox_id, action, payload, status=422)

    assert handler.seen == []


def test_redact_scrubs_raw_and_encoded_secrets_and_url_userinfo() -> None:
    token = "t0k/en+x"
    helper = f"{ASKPASS_DIR}/askpass-ab12"
    text = f"https://bot:{quote(token, safe='')}@h/r.git failed: {token} via {helper}"

    scrubbed = redact(text, token, helper, None)

    assert scrubbed == f"https://h/r.git failed: {REDACTED} via {REDACTED}"
    assert "t0k" not in redact("tail " + token[:5], token, truncated=True)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://u:p@host/r.git", "https://host/r.git"),
        ("https://u:p@ss@host/r.git", "https://host/r.git"),
        ("git@github.com:org/r.git", "github.com:org/r.git"),
        ("https://host/path@v1", "https://host/path@v1"),
        ("origin", "origin"),
    ],
)
def test_strip_userinfo(url: str, expected: str) -> None:
    assert strip_userinfo(url) == expected


def run_askpass(tmp_path: Path, credential: GitCredential, url: str, prompt: str) -> Any:
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("no sh on this host")
    helper = tmp_path / "askpass"
    helper.write_bytes(render_askpass(credential, url))
    return subprocess.run([shell, str(helper), prompt], capture_output=True, check=False)


@pytest.mark.parametrize(
    "prompt",
    [
        "Password for 'https://git.example.test': ",
        f"Password for 'https://{USERNAME}@git.example.test': ",
    ],
)
def test_askpass_script_answers_the_expected_host_password_prompt_verbatim(
    tmp_path: Path, prompt: str
) -> None:
    credential = GitCredential(username="bot's", token="p'a$s`w\"d\\n x")

    completed = run_askpass(tmp_path, credential, URL, prompt)

    assert completed.returncode == 0
    assert completed.stdout.decode() == credential.token + "\n"


@pytest.mark.parametrize(
    "prompt",
    [
        "Password for 'https://evil.example.test': ",
        f"Password for 'https://{USERNAME}@evil.example.test': ",
        "Password for 'https://evil.example.test/git.example.test': ",
        "Password for 'https://git.example.test.evil.test': ",
        "Password for 'http://git.example.test': ",
        "Username for 'https://git.example.test': ",
        "Username for 'https://evil.example.test': ",
        "Enter passphrase: ",
        "",
    ],
)
def test_askpass_script_refuses_every_other_prompt(tmp_path: Path, prompt: str) -> None:
    credential = GitCredential(username=USERNAME, token=TOKEN)

    completed = run_askpass(tmp_path, credential, URL, prompt)

    assert completed.returncode != 0
    assert completed.stdout == b""


def test_askpass_script_quotes_the_baked_host_literal_safely(tmp_path: Path) -> None:
    credential = GitCredential(username=USERNAME, token=TOKEN)
    hostile = "https://u@h'$(touch pwn).test:8443/r.git"
    prompt = "Password for 'https://h'$(touch pwn).test:8443': "

    completed = run_askpass(tmp_path, credential, hostile, prompt)

    assert completed.stdout.decode() == TOKEN + "\n"
    assert not (Path.cwd() / "pwn").exists()


@pytest.mark.parametrize("url", ["git@github.com:acme/app.git", "ssh://h/r.git", "origin", ""])
def test_askpass_script_requires_an_http_remote_url(url: str) -> None:
    with pytest.raises(Unprocessable):
        render_askpass(GitCredential(username=USERNAME, token=TOKEN), url)


# --- auth and scoping -------------------------------------------------------------------


async def test_unauthenticated_request_is_rejected(
    client: httpx.AsyncClient, driver: FakeDriver
) -> None:
    handler = script(driver)

    response = await client.post(
        git_path("sbx_00000000000000000000000000", "clone"),
        json={"url": URL, "path": REPO, "credential": CREDENTIAL},
    )

    assert response.status_code == 401
    assert TOKEN not in response.text
    assert handler.seen == []


async def test_sandbox_of_another_org_is_not_found(
    app: FastAPI, client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    other_key = await add_key(app, await add_org(app, "globex"), FULL_ACCESS)
    handler = script(driver)
    payload = {"path": REPO, "credential": CREDENTIAL, "remote_url": URL}

    response = await post_git(client, other_key, sandbox_id, "push", payload, status=404)

    assert response.json()["error"]["code"] == "NOT_FOUND"
    assert handler.seen == []
