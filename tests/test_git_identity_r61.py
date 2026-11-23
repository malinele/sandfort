"""Round 61: a commit without a git identity answers a clear 422, not git's raw text.

Git's "Author identity unknown ... git config --global" failure used to surface as a 409
carrying the raw stderr, including advice to run ``git config --global``. The toolbox now
detects that failure and answers 422 ``UNPROCESSABLE`` with a fixed message; commits that
pass an author keep working and other git failures keep the 409 ``operation_failed``
mapping. FakeDriver, temp SQLite, httpx over ASGI.
"""

import sys
from collections.abc import AsyncIterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from sandfort.api.app import create_app  # noqa: E402
from sandfort.config import Settings  # noqa: E402
from sandfort.drivers.base import ExecRequest, ExecResult  # noqa: E402
from sandfort.drivers.fake import FakeDriver  # noqa: E402
from sandfort.toolbox.git import is_missing_identity  # noqa: E402
from test_toolbox_git import (  # noqa: E402
    FULL_ACCESS,
    PEPPER,
    REPO,
    SHA,
    add_key,
    add_org,
    create_sandbox,
    failed,
    out,
    post_git,
    script,
)

MESSAGE = (
    "git needs an author for this commit: pass author_name and author_email, "
    "or set user.name and user.email in the sandbox"
)
UNKNOWN_IDENTITY = (
    "Author identity unknown\n\n*** Please tell me who you are.\n\nRun\n\n"
    '  git config --global user.email "you@example.com"\n'
    '  git config --global user.name "Your Name"\n\n'
    "to set your account's default identity.\n"
    "Omit --global to set the identity only in this repository.\n\n"
    "fatal: unable to auto-detect email address (got 'root@abc123.(none)')\n"
)
EMPTY_IDENT = "fatal: empty ident name (for <root@abc123.(none)>) not allowed\n"
USE_CONFIG_ONLY_NAME = "fatal: no name was given and auto-detection is disabled\n"
USE_CONFIG_ONLY_EMAIL = "fatal: no email was given and auto-detection is disabled\n"
GERMAN_IDENTITY = (
    "Autoridentität unbekannt\n\n*** Bitte teilen Sie mir mit, wer Sie sind.\n\n"
    "fatal: Konnte E-Mail-Adresse nicht automatisch erkennen (got 'root@abc123.(none)')\n"
)
NOTHING_TO_COMMIT = "On branch main\nnothing to commit, working tree clean\n"
BARE = {"path": REPO, "message": "initial import"}
WITH_AUTHOR = {**BARE, "author_name": "Ada Lovelace", "author_email": "ada@example.test"}
NAME_ONLY = {**BARE, "author_name": "Ada Lovelace"}
EMAIL_ONLY = {**BARE, "author_email": "ada@example.test"}


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


# --- detection ----------------------------------------------------------------------------


@pytest.mark.parametrize("stderr", [UNKNOWN_IDENTITY, EMPTY_IDENT])
def test_identity_failures_are_recognised(stderr: str) -> None:
    assert is_missing_identity(ExecResult(exit_code=128, stderr=stderr.encode()))


@pytest.mark.parametrize("text", [NOTHING_TO_COMMIT, "fatal: not a git repository\n", ""])
def test_other_failures_are_not_identity_failures(text: str) -> None:
    assert not is_missing_identity(ExecResult(exit_code=1, stderr=text.encode()))
    assert not is_missing_identity(ExecResult(exit_code=1, stdout=text.encode()))


# --- the route ----------------------------------------------------------------------------


@pytest.mark.parametrize("stderr", [UNKNOWN_IDENTITY, EMPTY_IDENT])
async def test_commit_without_identity_is_a_clear_422(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, stderr: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver, git={"commit": failed(stderr)})

    response = await post_git(client, key, sandbox_id, "commit", BARE, status=422)

    error = response.json()["error"]
    assert error["code"] == "UNPROCESSABLE"
    assert error["message"] == MESSAGE
    assert "git config" not in response.text
    assert "--global" not in response.text
    assert "Author identity unknown" not in response.text
    assert all("rev-parse" not in argv for argv in handler.argvs())


async def test_identity_text_on_stdout_alone_is_not_an_identity_failure(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    """A pre-commit hook may print the phrase on stdout; only stderr is scanned."""
    sandbox_id = await create_sandbox(client, key)
    hook_output = ExecResult(exit_code=1, stdout=UNKNOWN_IDENTITY.encode())
    script(driver, git={"commit": hook_output})

    response = await post_git(client, key, sandbox_id, "commit", BARE, status=409)

    assert response.json()["error"]["details"]["reason"] == "operation_failed"


@pytest.mark.parametrize("stderr", [USE_CONFIG_ONLY_NAME, USE_CONFIG_ONLY_EMAIL])
def test_use_config_only_failures_are_recognised(stderr: str) -> None:
    assert is_missing_identity(ExecResult(exit_code=128, stderr=stderr.encode()))


def test_identity_marker_on_stdout_is_ignored() -> None:
    assert not is_missing_identity(ExecResult(exit_code=1, stdout=UNKNOWN_IDENTITY.encode()))


@pytest.mark.parametrize("stderr", [USE_CONFIG_ONLY_NAME, USE_CONFIG_ONLY_EMAIL])
async def test_use_config_only_commit_is_a_clear_422(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, stderr: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    script(driver, git={"commit": failed(stderr)})

    response = await post_git(client, key, sandbox_id, "commit", BARE, status=422)

    assert response.json()["error"]["message"] == MESSAGE


def translated_unless_c_locale(request: ExecRequest) -> ExecResult:
    """A git with German message files: English only when the C locale is requested."""
    if request.env.get("LC_ALL") == "C" and request.env.get("LANGUAGE") == "C":
        return failed(UNKNOWN_IDENTITY)
    return failed(GERMAN_IDENTITY)


async def test_commit_requests_the_c_locale_so_the_english_markers_match(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver, git={"commit": translated_unless_c_locale})

    response = await post_git(client, key, sandbox_id, "commit", BARE, status=422)

    assert response.json()["error"]["message"] == MESSAGE
    commit = handler.git_requests()[0]
    assert commit.env["LC_ALL"] == "C"
    assert commit.env["LANGUAGE"] == "C"


def test_a_translated_message_is_not_recognised_without_the_c_locale() -> None:
    assert not is_missing_identity(ExecResult(exit_code=128, stderr=GERMAN_IDENTITY.encode()))


@pytest.mark.parametrize(
    ("payload", "stderr", "field"),
    [
        (BARE, UNKNOWN_IDENTITY, "author_name"),
        (NAME_ONLY, UNKNOWN_IDENTITY, "author_email"),
        (EMAIL_ONLY, EMPTY_IDENT, "author_name"),
        (NAME_ONLY, USE_CONFIG_ONLY_EMAIL, "author_email"),
    ],
)
async def test_details_field_names_the_missing_half_of_the_author(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    payload: dict[str, str],
    stderr: str,
    field: str,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    script(driver, git={"commit": failed(stderr)})

    response = await post_git(client, key, sandbox_id, "commit", payload, status=422)

    assert response.json()["error"]["details"]["field"] == field


async def test_half_an_author_that_git_rejects_gets_the_same_422(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    script(driver, git={"commit": failed(UNKNOWN_IDENTITY)})

    response = await post_git(client, key, sandbox_id, "commit", NAME_ONLY, status=422)

    assert response.json()["error"]["message"] == MESSAGE


async def test_commit_with_author_still_works(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    script(driver, git={"rev-parse": out(SHA + "\n")})

    response = await post_git(client, key, sandbox_id, "commit", WITH_AUTHOR)

    assert response.json()["data"] == {"sha": SHA}


async def test_commit_succeeds_without_author_when_the_sandbox_has_an_identity(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    script(driver, git={"rev-parse": out(SHA + "\n")})

    response = await post_git(client, key, sandbox_id, "commit", BARE)

    assert response.json()["data"] == {"sha": SHA}


async def test_other_commit_failures_keep_the_409_mapping(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    script(driver, git={"commit": failed(NOTHING_TO_COMMIT, 1)})

    response = await post_git(client, key, sandbox_id, "commit", BARE, status=409)

    error = response.json()["error"]
    assert error["code"] == "CONFLICT"
    assert error["details"]["reason"] == "operation_failed"
    assert error["details"]["exit_code"] == 1
    assert "nothing to commit" in error["message"]
