"""SDK r32b: list ``order`` (sync, async, iter, CLI) and a create-timeout message that says
what the cleanup did (the id it deleted, or that the create may still finish)."""

import json
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import SandboxTimeoutError  # noqa: E402
from sandfort_sdk._create_cleanup import NameCheck, delete_after_timeout  # noqa: E402
from sandfort_sdk.handles import create_timeout_error  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

from test_sdk_r30 import (  # noqa: E402
    BASE,
    KEY,
    ONE_SANDBOX,
    SANDBOXES,
    SID,
    WAIT_S,
    Router,
    async_client,
    create_times_out,
    failed,
    fresh_listing,
    listing,
    sandbox_json,
    sync_client,
)

RUNNER = CliRunner()
OTHER_SID = "sbx_02HZZZZZZZZZZZZZZZZZZZZZZZ"


def two_pages() -> Router:
    """Two listing pages: the first names a cursor, the second ends the listing."""
    first = httpx.Response(
        200, json={"success": True, "data": [sandbox_json()], "meta": {"next_cursor": "c1"}}
    )
    return Router({("GET", SANDBOXES): [first, listing(sandbox_json(id=OTHER_SID))]})


def orders(router: Router) -> list[str | None]:
    return [r.url.params.get("order") for r in router.seen("GET", SANDBOXES)]


# --- 1. order is sent only when given ----------------------------------------------------


def test_list_sandboxes_sends_order_only_when_given() -> None:
    router = Router({("GET", SANDBOXES): listing(sandbox_json())})
    client, _ = sync_client(router)

    client.list_sandboxes()
    client.list_sandboxes(order="desc", state="started")

    first, second = router.seen("GET", SANDBOXES)
    assert "order" not in first.url.params
    assert second.url.params["order"] == "desc"
    assert second.url.params["state"] == "started"


def test_iter_sandboxes_sends_the_same_order_on_every_page() -> None:
    router = two_pages()
    client, _ = sync_client(router)

    ids = [sandbox.id for sandbox in client.iter_sandboxes(order="asc")]

    assert ids == [SID, OTHER_SID]
    assert orders(router) == ["asc", "asc"]
    assert router.seen("GET", SANDBOXES)[1].url.params["cursor"] == "c1"


def test_iter_sandboxes_without_order_never_sends_it() -> None:
    router = two_pages()
    client, _ = sync_client(router)

    list(client.iter_sandboxes())

    assert orders(router) == [None, None]


async def test_async_list_and_iter_send_order_only_when_given() -> None:
    router = Router({("GET", SANDBOXES): listing(sandbox_json())})
    client, _ = await async_client(router)

    await client.list_sandboxes()
    await client.list_sandboxes(order="desc")
    items = [sandbox.id async for sandbox in client.iter_sandboxes(order="asc")]

    assert items == [SID]
    assert orders(router) == [None, "desc", "asc"]
    await client.aclose()


async def test_async_iter_without_order_never_sends_it() -> None:
    router = two_pages()
    client, _ = await async_client(router)

    items = [sandbox.id async for sandbox in client.iter_sandboxes()]

    assert items == [SID, OTHER_SID]
    assert orders(router) == [None, None]
    await client.aclose()


# --- 2. the create-timeout message says what the cleanup did -----------------------------


def test_timed_out_create_whose_cleanup_deleted_it_names_the_id() -> None:
    router = create_times_out(found=[listing(), fresh_listing(state="pending")])
    client, _ = sync_client(router)

    with pytest.raises(SandboxTimeoutError) as caught:
        client.create_sandbox(name="demo", wait_timeout_s=WAIT_S, idempotency_key="key-1")

    assert str(caught.value) == (
        f"creating sandbox 'demo' did not finish within {WAIT_S:g} s; the sandbox it made "
        f"({SID}) was deleted, so nothing is left behind"
    )
    assert caught.value.sandbox_id == SID
    assert len(router.seen("DELETE", ONE_SANDBOX)) == 1


def test_timed_out_create_whose_name_was_held_keeps_the_may_still_finish_text() -> None:
    router = create_times_out(found=fresh_listing())
    client, _ = sync_client(router)

    with pytest.raises(SandboxTimeoutError) as caught:
        client.create_sandbox(name="demo", wait_timeout_s=WAIT_S, idempotency_key="key-1")

    message = str(caught.value)
    assert "may still finish on the server" in message
    assert "key-1" in message and "was deleted" not in message
    assert caught.value.sandbox_id is None
    assert router.seen("DELETE", ONE_SANDBOX) == []


def test_timed_out_create_whose_delete_failed_keeps_the_may_still_finish_text() -> None:
    router = create_times_out(found=[listing(), fresh_listing(state="pending")])
    router.routes[("DELETE", ONE_SANDBOX)] = [failed(500, "INTERNAL")]
    client, _ = sync_client(router, max_retries=0)

    with pytest.raises(SandboxTimeoutError) as caught:
        client.create_sandbox(name="demo", wait_timeout_s=WAIT_S)

    assert "may still finish on the server" in str(caught.value)
    assert caught.value.sandbox_id is None
    assert len(router.seen("DELETE", ONE_SANDBOX)) == 1


async def test_async_timed_out_create_whose_cleanup_deleted_it_names_the_id() -> None:
    router = create_times_out(found=[listing(), fresh_listing(state="pending")])
    client, _ = await async_client(router)

    with pytest.raises(SandboxTimeoutError) as caught:
        await client.create_sandbox(name="demo", wait_timeout_s=WAIT_S)

    assert f"the sandbox it made ({SID}) was deleted" in str(caught.value)
    assert caught.value.sandbox_id == SID
    await client.aclose()


async def test_async_timed_out_create_whose_name_was_held_keeps_the_text() -> None:
    router = create_times_out(found=fresh_listing())
    client, _ = await async_client(router)

    with pytest.raises(SandboxTimeoutError) as caught:
        await client.create_sandbox(name="demo", wait_timeout_s=WAIT_S)

    assert "may still finish on the server" in str(caught.value)
    assert router.seen("DELETE", ONE_SANDBOX) == []
    await client.aclose()


def test_delete_after_timeout_returns_none_without_a_check_or_a_free_name() -> None:
    def never(_: str) -> object:
        raise AssertionError("no request may be made")

    now = datetime.now(UTC)
    held = NameCheck("demo", free=False, holder=SID)

    assert delete_after_timeout(None, now, never, never) is None
    assert delete_after_timeout(held, now, never, never) is None


def test_create_timeout_error_without_a_deleted_id_keeps_todays_text() -> None:
    error = create_timeout_error("demo", "key-1", 1.0)

    assert str(error) == (
        "creating sandbox 'demo' did not finish within 1 s; the create may still finish on "
        "the server; resending the same call with the idempotency key 'key-1' returns the "
        "sandbox"
    )
    assert error.sandbox_id is None


# --- 3. CLI ------------------------------------------------------------------------------


@pytest.fixture
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def mock(profile: None) -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router


def envelope(data: object) -> dict[str, object]:
    return {"success": True, "data": data, "error": None, "meta": None}


def fresh_sandbox() -> dict[str, object]:
    return sandbox_json(state="pending", created_at=datetime.now(UTC).isoformat())


def test_cli_sandbox_list_sends_order_only_when_given(mock: respx.MockRouter) -> None:
    route = mock.get(SANDBOXES).respond(200, json=envelope([sandbox_json()]))

    plain = RUNNER.invoke(create_app(None), ["--json", "sandbox", "list"])
    newest = RUNNER.invoke(create_app(None), ["--json", "sandbox", "list", "--order", "desc"])

    assert plain.exit_code == 0, plain.output
    assert newest.exit_code == 0, newest.output
    assert json.loads(newest.stdout)[0]["id"] == SID
    assert [call.request.url.params.get("order") for call in route.calls] == [None, "desc"]


def test_cli_sandbox_list_rejects_an_unknown_order(mock: respx.MockRouter) -> None:
    route = mock.get(SANDBOXES).respond(200, json=envelope([]))

    result = RUNNER.invoke(create_app(None), ["sandbox", "list", "--order", "newest"])

    assert result.exit_code == 2
    assert route.call_count == 0


def test_cli_create_timeout_says_the_sandbox_was_deleted(mock: respx.MockRouter) -> None:
    mock.post(SANDBOXES).mock(side_effect=httpx.ReadTimeout("still running"))
    mock.get(SANDBOXES).mock(
        side_effect=[
            httpx.Response(200, json=envelope([])),
            httpx.Response(200, json=envelope([fresh_sandbox()])),
        ]
    )
    deleted = mock.delete(ONE_SANDBOX).respond(
        200, json=envelope(sandbox_json(state="destroying"))
    )

    result = RUNNER.invoke(
        create_app(None), ["sandbox", "create", "demo", "--wait", "--wait-timeout", "1"]
    )

    assert result.exit_code != 0
    assert deleted.call_count == 1
    assert f"({SID}) was deleted" in result.output
    assert "may still finish" not in result.output
