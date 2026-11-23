"""Round 64: a sandbox image without git says so instead of "command not found: git".

The default image (python:3.12-slim) has no git. The runner answers exit 127 with
``command not found: git``; the toolbox keeps the 409 class but names the cause and an image
that has git, with ``details.reason`` ``git_missing``. Other failures, other missing programs
and other exit codes keep the ``operation_failed`` mapping. FakeDriver, temp SQLite, httpx.
"""

import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from sandfort.api.app import create_app  # noqa: E402
from sandfort.config import Settings  # noqa: E402
from sandfort.drivers.base import ExecResult  # noqa: E402
from sandfort.drivers.fake import FakeDriver  # noqa: E402
from sandfort.toolbox.git import is_git_missing  # noqa: E402
from test_toolbox_git import (  # noqa: E402
    FULL_ACCESS,
    PEPPER,
    REPO,
    URL,
    add_key,
    add_org,
    call,
    create_sandbox,
    failed,
    git_path,
    post_git,
    script,
)

MESSAGE = (
    "git is not installed in this sandbox's image (the default python:3.12-slim has no git); "
    "create the sandbox from an image that has git, for example snapshot python:3.12"
)
RUNNER_MISSING = "command not found: git\n"
SHELL_MISSING = "sh: 1: git: not found\n"
BASH_MISSING = "bash: git: command not found\n"
NOT_GIT_MISSING = [
    ("command not found: node\n", 127),
    ("fatal: not a git repository\n", 128),
    ("command not found: git\n", 1),
    ("", 127),
    ("fatal: could not read from remote: git: not found in the remote's docs\n", 127),
]


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'git.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
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


@pytest.fixture
async def key(app: FastAPI) -> str:
    return await add_key(app, await add_org(app, "acme"), FULL_ACCESS)


def assert_git_missing(response: httpx.Response) -> None:
    error = response.json()["error"]
    assert error["code"] == "CONFLICT"
    assert error["message"] == MESSAGE
    assert error["details"]["reason"] == "git_missing"


# --- detection ----------------------------------------------------------------------------


@pytest.mark.parametrize("stderr", [RUNNER_MISSING, SHELL_MISSING, BASH_MISSING])
def test_missing_git_binary_is_recognised(stderr: str) -> None:
    assert is_git_missing(ExecResult(exit_code=127, stderr=stderr.encode()))


@pytest.mark.parametrize(("stderr", "exit_code"), NOT_GIT_MISSING)
def test_other_failures_are_not_a_missing_git(stderr: str, exit_code: int) -> None:
    assert not is_git_missing(ExecResult(exit_code=exit_code, stderr=stderr.encode()))


def test_missing_git_text_on_stdout_alone_is_ignored() -> None:
    assert not is_git_missing(ExecResult(exit_code=127, stdout=RUNNER_MISSING.encode()))


# --- the routes ---------------------------------------------------------------------------

CLONE = {"url": URL, "path": REPO}
PATH_ONLY = {"path": REPO}
ADD = {"path": REPO, "files": ["a.txt"]}
COMMIT = {"path": REPO, "message": "m", "author_name": "A", "author_email": "a@example.test"}


@pytest.mark.parametrize(
    ("action", "payload", "subcommand"),
    [
        ("clone", CLONE, "clone"),
        ("add", ADD, "add"),
        ("commit", COMMIT, "commit"),
        ("push", PATH_ONLY, "push"),
        ("pull", PATH_ONLY, "pull"),
    ],
)
async def test_a_missing_git_is_a_clear_409_on_every_operation(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    action: str,
    payload: dict[str, Any],
    subcommand: str,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    script(driver, git={subcommand: failed(RUNNER_MISSING, exit_code=127)})

    response = await post_git(client, key, sandbox_id, action, payload, status=409)

    assert_git_missing(response)
    assert "command not found" not in response.text


async def test_status_with_a_missing_git_is_a_clear_409(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    script(driver, git={"status": failed(RUNNER_MISSING, exit_code=127)})

    response = await call(
        client, "GET", git_path(sandbox_id, "status"), key, status=409, params=PATH_ONLY
    )

    assert_git_missing(response)


async def test_other_missing_commands_keep_operation_failed(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    script(driver, git={"clone": failed("command not found: node\n", exit_code=127)})

    response = await post_git(client, key, sandbox_id, "clone", CLONE, status=409)

    error = response.json()["error"]
    assert error["details"]["reason"] == "operation_failed"
    assert error["details"]["exit_code"] == 127
