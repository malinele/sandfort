"""SDK r57: ``stop_cause`` on ``list_sandboxes`` and ``iter_sandboxes`` (sync and async).

The query parameter is sent only when the argument is given, on every page of an iteration.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
from sandfort_sdk import SANDBOX_STOP_CAUSE_AUTO_STOP  # noqa: E402

from test_sdk_r30 import (  # noqa: E402
    SANDBOXES,
    SID,
    Router,
    async_client,
    listing,
    sandbox_json,
    sync_client,
)

OTHER_SID = "sbx_02HZZZZZZZZZZZZZZZZZZZZZZZ"


def two_pages() -> Router:
    """Two listing pages: the first names a cursor, the second ends the listing."""
    first = httpx.Response(
        200, json={"success": True, "data": [sandbox_json()], "meta": {"next_cursor": "c1"}}
    )
    return Router({("GET", SANDBOXES): [first, listing(sandbox_json(id=OTHER_SID))]})


def causes(router: Router) -> list[str | None]:
    return [r.url.params.get("stop_cause") for r in router.seen("GET", SANDBOXES)]


def test_list_sandboxes_sends_stop_cause_only_when_given() -> None:
    router = Router({("GET", SANDBOXES): listing(sandbox_json())})
    client, _ = sync_client(router)

    client.list_sandboxes()
    client.list_sandboxes(stop_cause=SANDBOX_STOP_CAUSE_AUTO_STOP, state="stopped")

    first, second = router.seen("GET", SANDBOXES)
    assert "stop_cause" not in first.url.params
    assert second.url.params["stop_cause"] == "auto_stop"
    assert second.url.params["state"] == "stopped"


def test_iter_sandboxes_sends_the_same_stop_cause_on_every_page() -> None:
    router = two_pages()
    client, _ = sync_client(router)

    ids = [sandbox.id for sandbox in client.iter_sandboxes(stop_cause="oom_killed")]

    assert ids == [SID, OTHER_SID]
    assert causes(router) == ["oom_killed", "oom_killed"]
    assert router.seen("GET", SANDBOXES)[1].url.params["cursor"] == "c1"


def test_iter_sandboxes_without_stop_cause_never_sends_it() -> None:
    router = two_pages()
    client, _ = sync_client(router)

    list(client.iter_sandboxes())

    assert causes(router) == [None, None]


async def test_async_list_sends_stop_cause_only_when_given() -> None:
    router = Router({("GET", SANDBOXES): listing(sandbox_json())})
    client, _ = await async_client(router)

    await client.list_sandboxes()
    await client.list_sandboxes(stop_cause="requested")

    assert causes(router) == [None, "requested"]
    await client.aclose()


async def test_async_iter_sends_the_same_stop_cause_on_every_page() -> None:
    router = two_pages()
    client, _ = await async_client(router)

    ids = [sandbox.id async for sandbox in client.iter_sandboxes(stop_cause="unknown")]

    assert ids == [SID, OTHER_SID]
    assert causes(router) == ["unknown", "unknown"]
    await client.aclose()


def test_a_value_outside_the_literal_is_still_sent_as_given() -> None:
    router = Router({("GET", SANDBOXES): listing(sandbox_json())})
    client, _ = sync_client(router)

    client.list_sandboxes(stop_cause="nope")  # type: ignore[arg-type]

    assert causes(router) == ["nope"]


async def test_async_value_outside_the_literal_is_still_sent_as_given() -> None:
    router = Router({("GET", SANDBOXES): listing(sandbox_json())})
    client, _ = await async_client(router)

    await client.list_sandboxes(stop_cause="nope")  # type: ignore[arg-type]

    assert causes(router) == ["nope"]
    await client.aclose()
