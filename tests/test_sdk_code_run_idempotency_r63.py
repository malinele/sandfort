"""r63: ``code_run`` takes ``idempotency_key`` like ``exec`` (sync, async, Process and Sandbox).

The key is sent as ``Idempotency-Key`` and validated locally (1 to 255 printable ASCII
characters); ``replayed`` is set from the ``Idempotent-Replayed`` header; a keyed POST is
resent after a 503 and an unkeyed one never is.
"""

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sandfort_sdk import ExecResult, ServiceUnavailable  # noqa: E402

from test_sdk_r30 import (  # noqa: E402
    ONE_SANDBOX,
    SID,
    Router,
    async_client,
    failed,
    ok,
    sync_client,
)

CODE_RUN = f"{ONE_SANDBOX}/toolbox/process/code-run"
HEADER = "Idempotency-Key"
KEY = "run-1"
MAX_KEY_LENGTH = 255
RESULT = {
    "exit_code": 0,
    "stdout": "hi\n",
    "stderr": "",
    "timed_out": False,
    "truncated": False,
    "duration_ms": 3,
}
RUN_ARGS: dict[str, Any] = {"language": "python", "code": "print('hi')"}


def result_reply(replayed: bool = False) -> httpx.Response:
    headers = {"Idempotent-Replayed": "true"} if replayed else None
    body = {"success": True, "data": RESULT, "meta": None}
    return httpx.Response(200, json=body, headers=headers)


def router_for(*answers: httpx.Response | Exception) -> Router:
    return Router({("GET", ONE_SANDBOX): ok(), ("POST", CODE_RUN): list(answers)})


def posts(router: Router) -> list[httpx.Request]:
    return router.seen("POST", CODE_RUN)


def via_process(client: Any) -> Callable[..., ExecResult]:
    process = client.get(SID).process
    return lambda **kw: process.code_run(**RUN_ARGS, **kw)  # type: ignore[no-any-return]


def via_sandbox(client: Any) -> Callable[..., ExecResult]:
    sandbox = client.get(SID)
    return lambda **kw: sandbox.code_run(**RUN_ARGS, **kw)  # type: ignore[no-any-return]


SYNC_FACADES = [via_process, via_sandbox]


@pytest.mark.parametrize("facade", SYNC_FACADES)
def test_the_key_is_sent_as_the_idempotency_key_header(facade: Callable[..., Any]) -> None:
    router = router_for(result_reply())
    client, _ = sync_client(router)

    facade(client)(idempotency_key=KEY)

    (request,) = posts(router)
    assert request.headers[HEADER] == KEY


@pytest.mark.parametrize("facade", SYNC_FACADES)
def test_without_a_key_no_header_is_sent_and_the_result_is_not_replayed(
    facade: Callable[..., Any],
) -> None:
    router = router_for(result_reply())
    client, _ = sync_client(router)

    result = facade(client)()

    (request,) = posts(router)
    assert HEADER not in request.headers
    assert result.replayed is False


@pytest.mark.parametrize("facade", SYNC_FACADES)
def test_a_replayed_answer_sets_replayed_on_the_result(facade: Callable[..., Any]) -> None:
    client, _ = sync_client(router_for(result_reply(replayed=True)))

    result = facade(client)(idempotency_key=KEY)

    assert result.replayed is True
    assert result.stdout == "hi\n"


@pytest.mark.parametrize(
    "key", ["", "x" * (MAX_KEY_LENGTH + 1), "café", "line\nbreak", " padded", "padded "]
)
@pytest.mark.parametrize("facade", SYNC_FACADES)
def test_a_bad_key_is_refused_locally_before_any_request(
    facade: Callable[..., Any], key: str
) -> None:
    router = router_for(result_reply())
    client, _ = sync_client(router)

    with pytest.raises(ValueError, match="idempotency_key"):
        facade(client)(idempotency_key=key)

    assert posts(router) == []


def test_the_longest_allowed_key_is_accepted() -> None:
    router = router_for(result_reply())
    client, _ = sync_client(router)

    via_process(client)(idempotency_key="k" * MAX_KEY_LENGTH)

    assert len(posts(router)) == 1


def test_a_keyed_post_is_resent_after_a_503() -> None:
    router = router_for(failed(503, "CAPACITY"), result_reply())
    client, sleeps = sync_client(router)

    result = via_process(client)(idempotency_key=KEY)

    sent = posts(router)
    assert len(sent) == 2
    assert {request.headers[HEADER] for request in sent} == {KEY}
    assert len(sleeps) == 1
    assert result.exit_code == 0


def test_an_unkeyed_post_is_never_resent_after_a_503() -> None:
    router = router_for(failed(503, "CAPACITY"), result_reply())
    client, sleeps = sync_client(router)

    with pytest.raises(ServiceUnavailable):
        via_process(client)()

    assert len(posts(router)) == 1
    assert sleeps == []


# --- async -------------------------------------------------------------------------------


@pytest.mark.parametrize("on_sandbox", [False, True])
async def test_async_sends_the_key_and_sets_replayed(on_sandbox: bool) -> None:
    router = router_for(result_reply(replayed=True))
    client, _ = await async_client(router)
    sandbox = await client.get(SID)
    target = sandbox if on_sandbox else sandbox.process

    result = await target.code_run(**RUN_ARGS, idempotency_key=KEY)

    (request,) = posts(router)
    assert request.headers[HEADER] == KEY
    assert result.replayed is True


async def test_async_without_a_key_sends_no_header() -> None:
    router = router_for(result_reply())
    client, _ = await async_client(router)
    sandbox = await client.get(SID)

    result = await sandbox.code_run(**RUN_ARGS)

    (request,) = posts(router)
    assert HEADER not in request.headers
    assert result.replayed is False


@pytest.mark.parametrize("on_sandbox", [False, True])
async def test_async_a_bad_key_is_refused_locally(on_sandbox: bool) -> None:
    router = router_for(result_reply())
    client, _ = await async_client(router)
    sandbox = await client.get(SID)
    target = sandbox if on_sandbox else sandbox.process

    with pytest.raises(ValueError, match="idempotency_key"):
        await target.code_run(**RUN_ARGS, idempotency_key="")

    assert posts(router) == []


async def test_async_a_keyed_post_is_resent_after_a_503_and_an_unkeyed_one_is_not() -> None:
    keyed = router_for(failed(503, "CAPACITY"), result_reply())
    client, sleeps = await async_client(keyed)
    sandbox = await client.get(SID)

    result = await sandbox.code_run(**RUN_ARGS, idempotency_key=KEY)

    assert len(posts(keyed)) == 2
    assert len(sleeps) == 1
    assert result.exit_code == 0

    unkeyed = router_for(failed(503, "CAPACITY"), result_reply())
    client, sleeps = await async_client(unkeyed)
    sandbox = await client.get(SID)
    with pytest.raises(ServiceUnavailable):
        await sandbox.code_run(**RUN_ARGS)

    assert len(posts(unkeyed)) == 1
    assert sleeps == []
