"""Round 58 (isolation audit H3): credentialed push and pull are bound to the caller's url.

The host the askpass helper answers for used to come from ``git remote get-url`` inside the
sandbox, which sandbox code controls. Now a credentialed push or pull carries ``remote_url``;
the service refuses with 422 ``UNPROCESSABLE`` when the repository's remote names another
scheme or host, and hands git the caller's url instead of the remote name. Uncredentialed
push and pull by remote name are unchanged. FakeDriver, temp SQLite, httpx over ASGI.
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
from sandfort_sdk.git import Git  # noqa: E402
from sandfort_sdk.git import GitCredential as SdkCredential  # noqa: E402

from sandfort.api.app import create_app  # noqa: E402
from sandfort.api.schemas.toolbox_git import GitCredential  # noqa: E402
from sandfort.config import Settings  # noqa: E402
from sandfort.drivers.fake import FakeDriver  # noqa: E402
from sandfort.errors import Unprocessable  # noqa: E402
from sandfort.toolbox.git_credentials import render_askpass, require_same_target  # noqa: E402
from test_toolbox_git import (  # noqa: E402
    CREDENTIAL,
    FULL_ACCESS,
    HARDENING,
    NO_PROMPT,
    NULL_CONFIG,
    PEPPER,
    REPO,
    TARGET_PINS,
    TOKEN,
    URL,
    USERNAME,
    add_key,
    add_org,
    assert_token_absent,
    audit_events,
    create_sandbox,
    out,
    post_git,
    script,
    subcommand,
)

EVIL_URL = "https://attacker.example.test/acme/app.git"
ACTIONS = ["push", "pull"]


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
async def org_id(app: FastAPI) -> str:
    return await add_org(app, "acme")


@pytest.fixture
async def key(app: FastAPI, org_id: str) -> str:
    return await add_key(app, org_id, FULL_ACCESS)


def bound(**extra: Any) -> dict[str, Any]:
    return {"path": REPO, "credential": CREDENTIAL, "remote_url": URL, **extra}


async def git_events(app: FastAPI, org_id: str, action: str) -> list[Any]:
    return [e for e in await audit_events(app, org_id) if e.action == f"toolbox.git.{action}"]


# --- mismatch refused ---------------------------------------------------------------------


@pytest.mark.parametrize("action", ACTIONS)
async def test_planted_remote_url_is_refused_before_any_helper_exists(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, action: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver, git={"remote": out(EVIL_URL + "\n")})

    response = await post_git(client, key, sandbox_id, action, bound(), status=422)

    error = response.json()["error"]
    assert error["code"] == "UNPROCESSABLE"
    assert error["details"] == {"field": "remote_url"}
    assert "attacker" not in response.text
    assert TOKEN not in response.text
    assert [subcommand(argv) for argv in handler.argvs()] == ["remote"]
    assert_token_absent(handler.seen)


@pytest.mark.parametrize(
    "resolved",
    [
        "http://git.example.test/acme/app.git",
        "https://git.example.test:8443/acme/app.git",
        "git@git.example.test:acme/app.git",
        "",
    ],
)
async def test_other_scheme_port_or_non_http_remote_is_refused(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, resolved: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver, git={"remote": out(resolved)})

    response = await post_git(client, key, sandbox_id, "push", bound(), status=422)

    assert response.json()["error"]["code"] == "UNPROCESSABLE"
    assert [subcommand(argv) for argv in handler.argvs()] == ["remote"]


async def test_a_literal_url_remote_for_another_host_is_refused_without_exec(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver)

    await post_git(client, key, sandbox_id, "push", bound(remote=EVIL_URL), status=422)

    assert handler.seen == []


@pytest.mark.parametrize("action", ACTIONS)
async def test_credential_without_remote_url_is_refused(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, action: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver)
    payload = {"path": REPO, "credential": CREDENTIAL}

    response = await post_git(client, key, sandbox_id, action, payload, status=422)

    assert "remote_url" in response.text
    assert TOKEN not in response.text
    assert handler.seen == []


async def test_non_http_remote_url_is_refused_without_exec(
    client: httpx.AsyncClient, key: str, driver: FakeDriver
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver)
    payload = bound(remote_url="ssh://git.example.test/acme/app.git")

    await post_git(client, key, sandbox_id, "pull", payload, status=422)

    assert handler.seen == []


# --- match passes ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", ACTIONS)
async def test_matching_remote_runs_git_against_the_callers_url(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, action: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    resolved = "https://someone@GIT.example.test/acme/other.git\n"
    handler = script(driver, git={"remote": out(resolved)})

    await post_git(client, key, sandbox_id, action, bound(branch="main"))

    lookup, mkdir, write, run, remove = handler.seen
    push_flag = ["--push"] if action == "push" else []
    get_url = ["remote", "get-url", *push_flag, "origin"]
    assert list(lookup.argv) == ["git", "-C", REPO, *HARDENING, *get_url]
    assert lookup.env == {**NO_PROMPT, **NULL_CONFIG}
    assert mkdir.argv[0] == "mkdir"
    assert remove.argv[0] == "rm"
    assert write.stdin == render_askpass(GitCredential(username=USERNAME, token=TOKEN), URL)
    expected = ["git", "-C", REPO, *HARDENING, *TARGET_PINS, action, URL, "main"]
    assert list(run.argv) == expected
    assert run.env["GIT_ASKPASS"] == remove.argv[-1]
    assert_token_absent(handler.seen)


async def test_userinfo_in_remote_url_never_reaches_the_argv_or_audit(
    client: httpx.AsyncClient, key: str, driver: FakeDriver, app: FastAPI, org_id: str
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver)
    secret_url = f"https://{USERNAME}:{TOKEN}@git.example.test/acme/app.git"

    await post_git(client, key, sandbox_id, "push", bound(remote_url=secret_url))

    pushed = [argv for argv in handler.argvs() if subcommand(argv) == "push"]
    assert pushed == [["git", "-C", REPO, *HARDENING, *TARGET_PINS, "push", URL]]
    assert_token_absent(handler.seen)
    events = await git_events(app, org_id, "push")
    assert [event.details["remote_url"] for event in events] == [URL]


# --- uncredentialed by name unchanged -------------------------------------------------------


@pytest.mark.parametrize("action", ACTIONS)
async def test_uncredentialed_push_and_pull_by_name_are_unchanged(
    client: httpx.AsyncClient,
    key: str,
    driver: FakeDriver,
    app: FastAPI,
    org_id: str,
    action: str,
) -> None:
    sandbox_id = await create_sandbox(client, key)
    handler = script(driver)

    await post_git(client, key, sandbox_id, action, {"path": REPO, "branch": "main"})

    assert handler.argvs() == [["git", "-C", REPO, action, "origin", "main"]]
    assert handler.seen[0].env == NO_PROMPT
    (event,) = await git_events(app, org_id, action)
    assert event.details["remote"] == "origin"
    assert event.details["authenticated"] is False
    assert "remote_url" not in event.details


# --- units ----------------------------------------------------------------------------------


def test_same_target_ignores_host_case_path_and_userinfo() -> None:
    require_same_target("https://bot@GIT.Example.Test/x/y.git", URL)


@pytest.mark.parametrize(
    "resolved",
    [EVIL_URL, "https://git.example.test.attacker.test/a.git", "file:///srv/repo.git"],
)
def test_same_target_refuses_other_hosts(resolved: str) -> None:
    with pytest.raises(Unprocessable) as caught:
        require_same_target(resolved, URL)
    assert "attacker" not in str(caught.value)


class RecordingTransport:
    def __init__(self) -> None:
        self.bodies: list[Any] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.bodies.append(kwargs.get("json"))
        return type("Reply", (), {"data": {"path": REPO, "output": ""}})()


def test_sdk_sends_remote_url_and_requires_it_with_a_credential() -> None:
    transport = RecordingTransport()
    git = Git("sbx_1", transport)  # type: ignore[arg-type]
    credential = SdkCredential(username=USERNAME, token=TOKEN)

    git.push(REPO, branch="main", credential=credential, remote_url=URL)
    git.pull(REPO)
    with pytest.raises(ValueError, match="remote_url"):
        git.pull(REPO, credential=credential)

    pushed, pulled = transport.bodies
    assert pushed == {
        "path": REPO,
        "remote": "origin",
        "branch": "main",
        "remote_url": URL,
        "credential": {"username": USERNAME, "token": TOKEN},
    }
    assert pulled == {"path": REPO, "remote": "origin"}
