"""Key revoke cascade in the SDK and the CLI (round 58).

The server revokes a key's live descendants only with ``cascade=true`` and always lists them as
``dependants``. The SDK revoke methods (sync, async, client facade) take a ``cascade`` keyword
(default false) and send it; ``key revoke --cascade`` passes it on, and a revoke without it
prints a hint naming the live dependants and the command that revokes them.
"""

import asyncio
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import AsyncClient, Client  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
PARENT_ID = "key_parent"
CREATED = "2026-11-01T10:00:00Z"
REVOKED = "2026-11-10T10:00:00Z"
RUNNER = CliRunner()
CHILD_ID = "key_child"
CHILD_NAME = "child-one"
GRANDCHILD_ID = "key_grandchild"
GRANDCHILD_NAME = "child-two"


def key_data(key_id: str, name: str, revoked: bool = False) -> dict[str, Any]:
    return {
        "id": key_id,
        "name": name,
        "prefix": "sf_abcd",
        "scopes": ["sandboxes:read"],
        "sandbox_labels": None,
        "max_sandboxes": None,
        "created_at": CREATED,
        "last_used_at": None,
        "expires_at": None,
        "revoked_at": REVOKED if revoked else None,
        "created_by": None,
        "status": "revoked" if revoked else "active",
    }


def reply(cascade: bool, dependants: list[dict[str, Any]]) -> httpx.Response:
    data = {**key_data(PARENT_ID, "parent", True), "cascade": cascade, "dependants": dependants}
    return httpx.Response(200, json={"success": True, "data": data, "error": None, "meta": None})


def live_dependants() -> list[dict[str, Any]]:
    return [
        key_data(CHILD_ID, CHILD_NAME),
        key_data(GRANDCHILD_ID, GRANDCHILD_NAME),
    ]


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    config.save_profile(BASE, KEY)


@pytest.fixture
def server() -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


def query_of(route: Any) -> dict[str, str]:
    return dict(route.calls.last.request.url.params)


def test_sync_revoke_sends_cascade_true(server: respx.MockRouter) -> None:
    route = server.delete(f"/v1/api-keys/{PARENT_ID}").mock(
        return_value=reply(True, live_dependants())
    )
    with Client(BASE, KEY) as client:
        info = client.revoke_api_key(PARENT_ID, cascade=True)
    assert query_of(route) == {"cascade": "true"}
    assert info.id == PARENT_ID
    assert info.cascade is True
    assert len(info.dependants) == len(live_dependants())


def test_sync_revoke_without_cascade_does_not_ask_for_it(server: respx.MockRouter) -> None:
    route = server.delete(f"/v1/api-keys/{PARENT_ID}").mock(return_value=reply(False, []))
    with Client(BASE, KEY) as client:
        client.revoke_api_key(PARENT_ID)
    assert query_of(route).get("cascade") in (None, "false")


def test_sync_revoke_answers_cascade_and_dependants(server: respx.MockRouter) -> None:
    server.delete(f"/v1/api-keys/{PARENT_ID}").mock(return_value=reply(False, live_dependants()))
    with Client(BASE, KEY) as client:
        info = client.revoke_api_key(PARENT_ID)
    assert info.cascade is False
    assert [dep.id for dep in info.dependants] == [CHILD_ID, GRANDCHILD_ID]


def test_async_revoke_sends_cascade_true(server: respx.MockRouter) -> None:
    route = server.delete(f"/v1/api-keys/{PARENT_ID}").mock(
        return_value=reply(True, live_dependants())
    )

    async def run() -> str:
        async with AsyncClient(BASE, KEY) as client:
            info = await client.revoke_api_key(PARENT_ID, cascade=True)
            return info.id

    assert asyncio.run(run()) == PARENT_ID
    assert query_of(route) == {"cascade": "true"}


def test_cli_cascade_flag_is_sent(server: respx.MockRouter) -> None:
    route = server.delete(f"/v1/api-keys/{PARENT_ID}").mock(
        return_value=reply(True, live_dependants())
    )
    result = RUNNER.invoke(create_app(None), ["key", "revoke", PARENT_ID, "--cascade"])
    assert result.exit_code == 0, result.output
    assert query_of(route) == {"cascade": "true"}
    assert result.stdout.splitlines() == [f"revoked {PARENT_ID} (parent)"]
    assert "not revoked" not in result.stderr


def test_cli_without_cascade_prints_hint_with_live_dependants(server: respx.MockRouter) -> None:
    route = server.delete(f"/v1/api-keys/{PARENT_ID}").mock(
        return_value=reply(False, live_dependants())
    )
    result = RUNNER.invoke(create_app(None), ["key", "revoke", PARENT_ID])
    assert result.exit_code == 0, result.output
    assert query_of(route).get("cascade") in (None, "false")
    assert result.stdout.splitlines() == [f"revoked {PARENT_ID} (parent)"]
    for text in (CHILD_ID, CHILD_NAME, GRANDCHILD_ID, GRANDCHILD_NAME):
        assert text in result.stderr
    assert f"sandfort key revoke {CHILD_ID} {GRANDCHILD_ID}" in result.stderr


def test_cli_without_dependants_prints_no_hint(server: respx.MockRouter) -> None:
    server.delete(f"/v1/api-keys/{PARENT_ID}").mock(return_value=reply(False, []))
    result = RUNNER.invoke(create_app(None), ["key", "revoke", PARENT_ID])
    assert result.exit_code == 0, result.output
    assert result.stderr == ""


def test_cli_json_keeps_stdout_a_single_document(server: respx.MockRouter) -> None:
    server.delete(f"/v1/api-keys/{PARENT_ID}").mock(return_value=reply(False, live_dependants()))
    result = RUNNER.invoke(create_app(None), ["--json", "key", "revoke", PARENT_ID])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["id"] == PARENT_ID
    assert payload["cascade"] is False
    assert [dep["id"] for dep in payload["dependants"]] == [CHILD_ID, GRANDCHILD_ID]


def test_cli_help_lists_cascade() -> None:
    result = RUNNER.invoke(create_app(None), ["key", "revoke", "--help"])
    assert result.exit_code == 0
    assert "--cascade" in result.stdout
