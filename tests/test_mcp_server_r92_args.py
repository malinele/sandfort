"""MCP tool arguments after review: no bool-to-int coercion, a bounded start wait, SDK names pinned.

A JSON true must not become a 1 minute auto-delete timer, a start wait must not hold a worker
thread for years, and the keyword names the tools send must exist on the real SDK client.
"""

import asyncio
import inspect
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "mcp_server"))

import pytest  # noqa: E402

pytest.importorskip("mcp.server.mcpserver")

import sandfort_mcp  # noqa: E402
from sandfort_sdk import Client  # noqa: E402

from test_mcp_server_r92 import CREATE_OPTIONS, StubClient  # noqa: E402

MAX_WAIT = 600
TOO_LONG = "error: wait_timeout_seconds must be at most 600"


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> StubClient:
    client = StubClient()

    def holder_get() -> StubClient:
        client.calls.append(("holder", None))
        return client

    monkeypatch.setattr(sandfort_mcp, "HOLDER", SimpleNamespace(get=holder_get))
    return client


def call(tool: str, arguments: dict[str, Any]) -> str:
    """Call a tool through the MCP argument validation, as a client would."""
    try:
        result = asyncio.run(sandfort_mcp.mcp.call_tool(tool, arguments))
    except Exception as exc:  # the framework refuses invalid arguments with an exception
        return f"refused: {exc}"
    return str(result)


def made_calls(client: StubClient, kind: str) -> list[Any]:
    return [args for name, args in client.calls if name == kind]


@pytest.mark.parametrize(
    ("option", "value"), [("auto_delete_minutes", True), ("auto_stop_minutes", False)]
)
def test_a_boolean_timer_is_refused_and_nothing_is_created(
    stub: StubClient, option: str, value: bool
) -> None:
    outcome = call("create_sandbox", {option: value})
    assert made_calls(stub, "create") == []
    assert "refused" in outcome or "error" in outcome


def test_an_integer_timer_still_reaches_the_sdk(stub: StubClient) -> None:
    call("create_sandbox", {"auto_delete_minutes": 5})
    expected = {"name": None, "snapshot": None, "auto_delete_minutes": 5}
    assert made_calls(stub, "create") == [expected]


def test_a_boolean_start_wait_is_refused_and_nothing_is_started(stub: StubClient) -> None:
    call("start_sandbox", {"sandbox_id": "sbx_1", "wait_timeout_seconds": True})
    assert made_calls(stub, "start") == []


def test_a_start_wait_over_the_cap_is_refused_before_any_lookup(stub: StubClient) -> None:
    assert sandfort_mcp.start_sandbox("sbx_1", wait_timeout_seconds=MAX_WAIT + 1) == TOO_LONG
    assert stub.calls == []


def test_a_huge_start_wait_is_refused_without_an_exception(stub: StubClient) -> None:
    assert sandfort_mcp.start_sandbox("sbx_1", wait_timeout_seconds=10**400) == TOO_LONG
    assert stub.calls == []


def test_a_start_wait_at_the_cap_is_sent(stub: StubClient) -> None:
    sandfort_mcp.start_sandbox("sbx_1", wait_timeout_seconds=MAX_WAIT)
    assert made_calls(stub, "start") == [("sbx_1", True, MAX_WAIT)]


def test_create_options_exist_on_the_real_sdk_client() -> None:
    params = inspect.signature(Client.create_sandbox).parameters
    for name in ("name", "snapshot", *CREATE_OPTIONS):
        assert name in params, name
    for name in CREATE_OPTIONS:
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY, name


def test_start_keywords_exist_on_the_real_sdk_client() -> None:
    params = inspect.signature(Client.start).parameters
    for name in ("wait", "wait_timeout_s"):
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY, name
