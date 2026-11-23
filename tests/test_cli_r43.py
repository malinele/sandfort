"""CLI/SDK round 43: finite ``--wait-timeout`` and the key list ``status`` filter.

``--wait-timeout nan`` and ``inf`` used to pass the usage check and die in the transport with a
raw traceback; they are now the usage error "must be a finite number greater than 0" (exit 2,
also under ``--json``). ``key list --status active|revoked`` and the SDK ``list_api_keys(status=)``
forward the server's ``status`` query parameter; the SDK rejects other strings before any request.
"""

import asyncio
import sys
from collections.abc import Callable
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
from sandfort_sdk._transport import client_kwargs  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
KEYS_URL = "/v1/api-keys"
REVOKED_AT = "2026-11-07T10:00:00Z"
RUNNER = CliRunner()
NON_FINITE = ["nan", "inf", "-inf", "NaN", "Infinity"]
FINITE_MESSAGE = "must be a finite number greater than 0"

Handler = Callable[[httpx.Request], httpx.Response]


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def key_json(key_id: str, **extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": key_id,
        "name": "ci",
        "prefix": "sf_ab12",
        "scopes": ["sandboxes:read"],
        "sandbox_labels": None,
        "max_sandboxes": None,
        "created_at": "2026-11-06T10:00:00Z",
        "last_used_at": None,
        "expires_at": None,
        "revoked_at": None,
        "created_by": "key_0",
    }
    return {**base, **extra}


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def router() -> Any:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


# --- --wait-timeout must be finite ---------------------------------------------------------


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize("value", NON_FINITE)
@pytest.mark.parametrize("command", [["start", SID], ["create", "demo"]])
def test_non_finite_wait_timeout_is_a_usage_error(
    router: Any, command: list[str], value: str, as_json: bool
) -> None:
    any_request = router.route().respond(500)

    result = invoke(["sandbox", *command, "--wait", f"--wait-timeout={value}"], as_json=as_json)

    assert result.exit_code == 2, result.output
    assert FINITE_MESSAGE in result.output and "--wait-timeout" in result.output
    assert "Traceback" not in result.output
    assert not isinstance(result.exception, (ValueError, OSError))
    assert any_request.call_count == 0


@pytest.mark.parametrize("command", [["start", SID], ["create", "demo"]])
def test_zero_and_negative_wait_timeout_keep_the_usage_error(
    router: Any, command: list[str]
) -> None:
    any_request = router.route().respond(500)

    for value in ("0", "-1"):
        result = invoke(["sandbox", *command, "--wait", f"--wait-timeout={value}"])

        assert result.exit_code == 2
        assert FINITE_MESSAGE in result.output

    assert any_request.call_count == 0


# --- key list --status ---------------------------------------------------------------------


@pytest.mark.parametrize("status", ["active", "revoked"])
def test_key_list_status_sends_the_query_and_renders(router: Any, status: str) -> None:
    revoked_at = REVOKED_AT if status == "revoked" else None
    rows = [key_json(f"key_{status}", revoked_at=revoked_at)]
    route = router.get(KEYS_URL).respond(200, json=envelope(rows))

    result = invoke(["key", "list", "--status", status])

    assert result.exit_code == 0, result.output
    assert route.call_count == 1
    assert route.calls.last.request.url.params["status"] == status
    assert f"key_{status}" in result.stdout


def test_key_list_without_status_sends_no_status_param(router: Any) -> None:
    route = router.get(KEYS_URL).respond(200, json=envelope([key_json("key_a")]))

    result = invoke(["key", "list"])

    assert result.exit_code == 0, result.output
    assert "status" not in route.calls.last.request.url.params


def test_key_list_status_revoked_is_not_hidden_client_side(router: Any) -> None:
    rows = [key_json("key_gone", revoked_at=REVOKED_AT)]
    router.get(KEYS_URL).respond(200, json=envelope(rows))

    result = invoke(["key", "list", "--status", "revoked"], as_json=True)

    assert result.exit_code == 0, result.output
    assert '"key_gone"' in result.stdout


def test_key_list_bogus_status_is_a_usage_error(router: Any) -> None:
    route = router.get(KEYS_URL).respond(200, json=envelope([]))

    result = invoke(["key", "list", "--status", "bogus"])

    assert result.exit_code == 2
    assert "--status" in result.output
    assert route.call_count == 0


# --- SDK list_api_keys(status=) ------------------------------------------------------------


def capture(seen: list[httpx.Request]) -> Handler:
    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=envelope([key_json("key_1")]))

    return handle


def sync_client(handler: Handler) -> Client:
    client = Client(BASE, KEY, max_retries=0)
    client._transport._http.close()
    client._transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return client


async def async_client(handler: Handler) -> AsyncClient:
    client = AsyncClient(BASE, KEY, max_retries=0)
    await client._transport._http.aclose()
    client._transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return client


@pytest.mark.parametrize("status", ["active", "revoked"])
def test_sync_sdk_forwards_the_status_filter(status: str) -> None:
    seen: list[httpx.Request] = []

    keys = sync_client(capture(seen)).list_api_keys(status=status)  # type: ignore[arg-type]

    assert [key.id for key in keys] == ["key_1"]
    assert seen[0].url.params["status"] == status


def test_sync_sdk_without_status_sends_no_query() -> None:
    seen: list[httpx.Request] = []

    sync_client(capture(seen)).list_api_keys()

    assert seen[0].url.query == b""


@pytest.mark.parametrize("status", ["bogus", "expired", "", "ACTIVE"])
def test_sync_sdk_rejects_other_strings_before_any_request(status: str) -> None:
    seen: list[httpx.Request] = []

    with pytest.raises(ValueError, match="status"):
        sync_client(capture(seen)).list_api_keys(status=status)  # type: ignore[arg-type]

    assert seen == []


@pytest.mark.parametrize("status", ["active", "revoked"])
def test_async_sdk_forwards_the_status_filter(status: str) -> None:
    seen: list[httpx.Request] = []

    async def run() -> None:
        client = await async_client(capture(seen))
        keys = await client.list_api_keys(status=status)  # type: ignore[arg-type]
        assert [key.id for key in keys] == ["key_1"]

    asyncio.run(run())

    assert seen[0].url.params["status"] == status


@pytest.mark.parametrize("status", ["bogus", "expired", ""])
def test_async_sdk_rejects_other_strings_before_any_request(status: str) -> None:
    seen: list[httpx.Request] = []

    async def run() -> None:
        client = await async_client(capture(seen))
        with pytest.raises(ValueError, match="status"):
            await client.list_api_keys(status=status)  # type: ignore[arg-type]

    asyncio.run(run())

    assert seen == []
