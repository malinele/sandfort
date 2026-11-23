"""r61: ``POST .../toolbox/process/execute`` honours ``Idempotency-Key`` like create does.

Same key and body replays the stored answer without running the command again; another body is
a 422; a running first request is a 409; a failed first attempt does not pin the key; the key is
scoped to the API key and the sandbox. Requests without the header run every time.
"""

import asyncio
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

import test_stop_reason_delete_reset as base
from sandfort.api.openapi import build_document
from sandfort.api.routes.toolbox import process as process_routes
from sandfort.auth.api_keys import generate_api_key
from sandfort.clock import SystemClock
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey
from sandfort.domain.sandbox import SandboxState
from sandfort.drivers.base import ExecRequest, ExecResult
from sandfort.drivers.errors import DriverError
from sandfort.drivers.fake import FakeDriver
from sandfort.errors import NotFound
from sandfort.ids import new_api_key_id
from sandfort.services.idempotency import IdempotencyService

app = base.app
client = base.client
driver = base.driver
fast_settle = base.fast_settle
org_id = base.org_id
key = base.key
kicks = base.kicks

HEADER = "Idempotency-Key"
REPLAYED = "idempotent-replayed"
EXECUTE = "/v1/sandboxes/{sandbox_id}/toolbox/process/execute"
MARKER = "idem-run"
BODY = {"command": MARKER}
MAX_KEY_LENGTH = 255
SECOND_RUN = 2


class Runs:
    """Counts the commands that reach the driver and lets a test script the first ones.

    ``script`` holds answers for the first runs, in order: an exception to raise, or a
    callable returning the result (it may change the row first, as a stop or a reset would).
    """

    def __init__(self) -> None:
        self.count = 0
        self.fail_first = False
        self.hold_first: asyncio.Event | None = None
        self.started = asyncio.Event()
        self.script: list[Exception | Callable[[], Awaitable[ExecResult]]] = []

    async def exec(self, original: Any, ref: str, request: ExecRequest) -> ExecResult:
        if request.argv[-1] != MARKER:
            return await original(ref, request)  # type: ignore[no-any-return]
        self.count += 1
        number = self.count
        self.started.set()
        if self.script:
            step = self.script.pop(0)
            if isinstance(step, Exception):
                raise step
            return await step()
        if number == 1 and self.fail_first:
            raise DriverError("the runtime failed")
        if number == 1 and self.hold_first is not None:
            await self.hold_first.wait()
        return ExecResult(exit_code=0, stdout=f"run {number}".encode())


@pytest.fixture
def runs(driver: FakeDriver, monkeypatch: pytest.MonkeyPatch) -> Runs:
    counter = Runs()
    original = driver.exec

    async def exec_(ref: str, request: ExecRequest) -> ExecResult:
        return await counter.exec(original, ref, request)

    monkeypatch.setattr(driver, "exec", exec_)
    return counter


async def execute(
    client: httpx.AsyncClient,
    key: str,
    sandbox_id: str,
    body: dict[str, Any] = BODY,
    idempotency_key: str | None = None,
) -> httpx.Response:
    headers = {"Authorization": f"Bearer {key}"}
    if idempotency_key is not None:
        headers[HEADER] = idempotency_key
    path = EXECUTE.format(sandbox_id=sandbox_id)
    return await client.post(path, headers=headers, json=body)


async def test_the_same_key_and_body_replays_and_the_command_runs_once(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)

    first = await execute(client, key, sandbox_id, idempotency_key="k-replay")
    replay = await execute(client, key, sandbox_id, idempotency_key="k-replay")

    assert first.status_code == replay.status_code == 200, replay.text
    assert REPLAYED not in first.headers
    assert replay.headers[REPLAYED] == "true"
    assert replay.json() == first.json()
    assert first.json()["data"]["stdout"] == "run 1"
    assert runs.count == 1


async def test_the_body_is_compared_in_canonical_form(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    body = {"command": MARKER, "timeout_s": 5}
    reordered = {"timeout_s": 5, "command": MARKER}

    await execute(client, key, sandbox_id, body, idempotency_key="k-canon")
    replay = await execute(client, key, sandbox_id, reordered, idempotency_key="k-canon")

    assert replay.headers[REPLAYED] == "true"
    assert runs.count == 1


async def test_the_same_key_with_another_body_answers_422_and_does_not_run(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    await execute(client, key, sandbox_id, idempotency_key="k-mismatch")

    other = await execute(
        client, key, sandbox_id, {"command": MARKER, "cwd": "/tmp"}, idempotency_key="k-mismatch"
    )

    assert other.status_code == 422, other.text
    assert other.json()["error"]["code"] == "IDEMPOTENCY_MISMATCH"
    assert runs.count == 1


async def test_without_the_header_every_request_runs(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)

    first = await execute(client, key, sandbox_id)
    second = await execute(client, key, sandbox_id)

    assert first.json()["data"]["stdout"] == "run 1"
    assert second.json()["data"]["stdout"] == "run 2"
    assert REPLAYED not in second.headers
    assert runs.count == SECOND_RUN


async def test_a_key_whose_first_request_is_running_answers_409_in_progress(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    runs.hold_first = asyncio.Event()
    running = asyncio.create_task(execute(client, key, sandbox_id, idempotency_key="k-busy"))
    await asyncio.wait_for(runs.started.wait(), timeout=5)

    busy = await execute(client, key, sandbox_id, idempotency_key="k-busy")
    runs.hold_first.set()
    first = await running

    assert busy.status_code == 409, busy.text
    assert busy.json()["error"]["details"]["reason"] == "in_progress"
    assert first.status_code == 200
    assert runs.count == 1


async def test_a_failed_first_attempt_does_not_pin_the_key(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    runs.fail_first = True

    failed = await execute(client, key, sandbox_id, idempotency_key="k-fail")
    retry = await execute(client, key, sandbox_id, idempotency_key="k-fail")
    replay = await execute(client, key, sandbox_id, idempotency_key="k-fail")

    assert failed.status_code >= 500, failed.text
    assert retry.status_code == 200, retry.text
    assert REPLAYED not in retry.headers
    assert retry.json()["data"]["stdout"] == "run 2"
    assert replay.headers[REPLAYED] == "true"
    assert runs.count == SECOND_RUN


async def test_a_command_cut_short_by_a_gone_client_does_not_pin_the_key(
    client: httpx.AsyncClient,
    key: str,
    runs: Runs,
    monkeypatch: pytest.MonkeyPatch,
    completes: list[int],
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    runs.hold_first = asyncio.Event()  # never set: the cancel ends the first run
    watcher = process_routes._watch_disconnect

    async def gone(_: Any) -> None:
        return None

    monkeypatch.setattr(process_routes, "_watch_disconnect", gone)
    await execute(client, key, sandbox_id, idempotency_key="k-gone")
    monkeypatch.setattr(process_routes, "_watch_disconnect", watcher)
    assert completes == []  # the placeholder answer of the cancelled run is not stored

    retry = await execute(client, key, sandbox_id, idempotency_key="k-gone")

    assert retry.status_code == 200, retry.text
    assert REPLAYED not in retry.headers
    assert retry.json()["data"]["stdout"] == "run 2"
    assert runs.count == SECOND_RUN


async def test_two_sandboxes_with_the_same_key_and_body_do_not_replay_each_other(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    one = await base.create_sandbox(client, key)
    two = await base.create_sandbox(client, key)

    first = await execute(client, key, one, idempotency_key="k-shared")
    second = await execute(client, key, two, idempotency_key="k-shared")
    again = await execute(client, key, two, idempotency_key="k-shared")

    assert REPLAYED not in second.headers
    assert second.json()["data"]["stdout"] == "run 2"
    assert first.json()["data"]["stdout"] == "run 1"
    assert again.headers[REPLAYED] == "true"
    assert runs.count == SECOND_RUN


async def test_the_longest_allowed_key_works_and_a_longer_one_is_refused_as_create_does(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    longest = "k" * MAX_KEY_LENGTH

    first = await execute(client, key, sandbox_id, idempotency_key=longest)
    replay = await execute(client, key, sandbox_id, idempotency_key=longest)
    too_long = await execute(client, key, sandbox_id, idempotency_key=longest + "k")

    assert first.status_code == 200, first.text
    assert replay.headers[REPLAYED] == "true"
    assert too_long.status_code == 422, too_long.text
    assert too_long.json()["error"]["code"] == "VALIDATION_ERROR"
    assert runs.count == 1


def test_the_execute_operation_documents_the_key_and_how_long_it_is_kept() -> None:
    operation = build_document()["paths"][EXECUTE]["post"]
    names = {parameter["name"] for parameter in operation["parameters"]}

    assert HEADER in names
    assert "Idempotency-Key" in operation["description"]
    assert "one day" in operation["description"]
    assert "at most once per server process" in operation["description"]


# --- r61 review fixes -------------------------------------------------------------------------

REPLAY_ACTION = "sandbox.exec.replay"
UNAVAILABLE = "IDEMPOTENCY_RESULT_UNAVAILABLE"
TOO_LARGE_TEXT = (
    "this command already ran; its output was too large to keep for replay"
    "; use a new Idempotency-Key to run it again"
)
KEEP_LIMIT = 256 * 1024
REPLAYS = 2


@pytest.fixture
async def other_key(app: FastAPI, org_id: str) -> str:
    generated = generate_api_key(base.PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="other",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=base.FULL_ACCESS,
        created_at=base.NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


@pytest.fixture
def completes(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """The statuses the guard stored, in order (one entry per ``complete`` call)."""
    seen: list[int] = []
    original = IdempotencyService.complete

    async def spy(self: IdempotencyService, *args: Any, **kwargs: Any) -> None:
        seen.append(args[4])  # org_id, key_id, key, request_hash, status, body
        await original(self, *args, **kwargs)

    monkeypatch.setattr(IdempotencyService, "complete", spy)
    return seen


async def lifecycle(client: httpx.AsyncClient, key: str, sandbox_id: str, action: str) -> None:
    method, path = ("DELETE", "") if action == "delete" else ("POST", f"/{action}")
    await base.send(client, method, f"{base.BASE}/{sandbox_id}{path}", key)


def answer(
    result: ExecResult, before: Callable[[], Awaitable[None]] | None = None
) -> Callable[[], Awaitable[ExecResult]]:
    async def step() -> ExecResult:
        if before is not None:
            await before()
        return result

    return step


async def test_a_409_and_a_4xx_are_not_stored_and_a_retry_after_start_runs(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    runs.script.append(NotFound("gone for a moment"))
    refused = await execute(client, key, sandbox_id, idempotency_key="k-4xx")
    await lifecycle(client, key, sandbox_id, "stop")
    stopped = await execute(client, key, sandbox_id, idempotency_key="k-409")
    await lifecycle(client, key, sandbox_id, "start")

    retry_4xx = await execute(client, key, sandbox_id, idempotency_key="k-4xx")
    retry_409 = await execute(client, key, sandbox_id, idempotency_key="k-409")

    assert (refused.status_code, stopped.status_code) == (404, 409)
    assert REPLAYED not in retry_4xx.headers and REPLAYED not in retry_409.headers
    assert retry_4xx.json()["data"]["stdout"] == "run 2"
    assert retry_409.json()["data"]["stdout"] == "run 3"


async def test_another_api_key_of_the_same_org_does_not_replay(
    client: httpx.AsyncClient, key: str, other_key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)

    await execute(client, key, sandbox_id, idempotency_key="k-keys")
    other = await execute(client, other_key, sandbox_id, idempotency_key="k-keys")

    assert other.status_code == 200, other.text
    assert REPLAYED not in other.headers
    assert other.json()["data"]["stdout"] == "run 2"


async def test_a_replay_on_a_stopped_sandbox_answers_the_stopped_error(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    await execute(client, key, sandbox_id, idempotency_key="k-stop")
    await lifecycle(client, key, sandbox_id, "stop")

    stopped = await execute(client, key, sandbox_id, idempotency_key="k-stop")
    await lifecycle(client, key, sandbox_id, "start")
    restarted = await execute(client, key, sandbox_id, idempotency_key="k-stop")

    assert stopped.status_code == 409, stopped.text
    assert stopped.json()["error"]["details"]["reason"] == "no_container"
    assert REPLAYED not in stopped.headers
    assert REPLAYED not in restarted.headers  # a new start is a new run of the sandbox
    assert restarted.json()["data"]["stdout"] == "run 2"
    assert runs.count == SECOND_RUN


async def test_a_replay_on_a_deleted_sandbox_does_not_replay(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    await execute(client, key, sandbox_id, idempotency_key="k-del")
    await lifecycle(client, key, sandbox_id, "delete")

    gone = await execute(client, key, sandbox_id, idempotency_key="k-del")

    assert gone.status_code in (404, 409), gone.text
    assert REPLAYED not in gone.headers
    assert runs.count == 1


async def test_a_reset_sandbox_runs_the_command_again(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    await execute(client, key, sandbox_id, idempotency_key="k-reset")
    await lifecycle(client, key, sandbox_id, "reset")

    after = await execute(client, key, sandbox_id, idempotency_key="k-reset")
    again = await execute(client, key, sandbox_id, idempotency_key="k-reset")

    assert after.status_code == 200, after.text
    assert REPLAYED not in after.headers
    assert after.json()["data"]["stdout"] == "run 2"
    assert again.headers[REPLAYED] == "true"
    assert runs.count == SECOND_RUN


GONE_CASES = [
    pytest.param({"state": SandboxState.STOPPED}, "sandbox_stopped", id="stop"),
    pytest.param({"driver_ref": base.NEW_REF}, "sandbox_reset", id="reset"),
    pytest.param({"state": SandboxState.DESTROYING}, "sandbox_deleted", id="delete"),
]


@pytest.mark.parametrize(("changes", "expected"), GONE_CASES)
async def test_an_explicit_stop_reset_or_delete_outcome_releases_the_key(
    app: FastAPI,
    client: httpx.AsyncClient,
    key: str,
    org_id: str,
    runs: Runs,
    kicks: list[str],
    completes: list[int],
    changes: dict[str, Any],
    expected: str,
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    change = base.change_row(app, org_id, sandbox_id, **changes)
    runs.script.append(answer(ExecResult(exit_code=137, sandbox_stopped=True), change))

    first = await execute(client, key, sandbox_id, idempotency_key="k-died")

    assert first.status_code == 200, first.text
    assert first.json()["data"]["stop_reason"] == expected
    assert completes == []  # nothing stored: the key is free for a retry
    assert runs.count == 1


async def test_a_reset_outcome_lets_a_retry_in_the_new_run_execute(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str, runs: Runs, kicks: list[str]
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    change = base.change_row(app, org_id, sandbox_id, driver_ref=base.NEW_REF)
    runs.script.append(answer(ExecResult(exit_code=137, sandbox_stopped=True), change))

    first = await execute(client, key, sandbox_id, idempotency_key="k-died")
    retry = await execute(client, key, sandbox_id, idempotency_key="k-died")

    assert first.json()["data"]["stop_reason"] == "sandbox_reset"
    assert retry.status_code == 200, retry.text
    assert REPLAYED not in retry.headers
    assert retry.json()["data"]["stdout"] == "run 2"


async def test_a_death_the_driver_reports_keeps_the_key_pinned_while_the_row_reads_started(
    client: httpx.AsyncClient, key: str, runs: Runs, kicks: list[str], completes: list[int]
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    runs.script.append(answer(ExecResult(exit_code=137, sandbox_stopped=True, stdout=b"p")))

    first = await execute(client, key, sandbox_id, idempotency_key="k-oom")
    retry = await execute(client, key, sandbox_id, idempotency_key="k-oom")

    assert first.json()["data"]["stop_reason"] == "sandbox_stopped"
    assert completes == [200]  # the answer is stored
    assert retry.headers[REPLAYED] == "true"
    assert retry.json() == first.json()
    assert runs.count == 1  # the command did not run twice in the same generation


async def test_two_resets_under_a_frozen_clock_each_start_a_new_generation(
    client: httpx.AsyncClient, key: str, runs: Runs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(SystemClock, "now", lambda self: base.NOW)
    sandbox_id = await base.create_sandbox(client, key)

    await execute(client, key, sandbox_id, idempotency_key="k-frozen")
    await lifecycle(client, key, sandbox_id, "reset")
    after_one = await execute(client, key, sandbox_id, idempotency_key="k-frozen")
    await lifecycle(client, key, sandbox_id, "reset")
    after_two = await execute(client, key, sandbox_id, idempotency_key="k-frozen")
    replay = await execute(client, key, sandbox_id, idempotency_key="k-frozen")

    assert REPLAYED not in after_one.headers
    assert after_one.json()["data"]["stdout"] == "run 2"
    assert REPLAYED not in after_two.headers
    assert after_two.json()["data"]["stdout"] == "run 3"
    assert replay.headers[REPLAYED] == "true"
    assert runs.count == REPLAYS + 1


def test_a_truncated_output_is_stored_as_a_marker_and_never_as_the_answer() -> None:
    body = {"data": {"stdout": "short", "stderr": "", "truncated": True}}

    kept = process_routes._kept_answer(200, body)

    assert kept.body[process_routes.STORED_UNAVAILABLE] is True
    assert process_routes.STORED_ANSWER not in kept.body


async def test_a_failing_store_does_not_crash_the_request_and_frees_the_key(
    client: httpx.AsyncClient, key: str, runs: Runs, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox_id = await base.create_sandbox(client, key)

    async def broken(
        self: IdempotencyService, org_id: str, key_id: str | None, slot: str, *_: Any
    ) -> None:
        self.abandon(org_id, key_id, slot)  # complete() releases the claim in a finally
        raise OSError("disk full")

    monkeypatch.setattr(IdempotencyService, "complete", broken)

    first = await execute(client, key, sandbox_id, idempotency_key="k-store")
    retry = await execute(client, key, sandbox_id, idempotency_key="k-store")

    assert first.status_code == 200, first.text
    assert first.json()["data"]["stdout"] == "run 1"
    assert retry.status_code == 200, retry.text  # nothing was kept, and no claim is stuck
    assert REPLAYED not in retry.headers
    assert retry.json()["data"]["stdout"] == "run 2"


@pytest.mark.parametrize(
    "result",
    [
        ExecResult(exit_code=0, stdout=b"o" * (KEEP_LIMIT - 10), stderr=b"e" * 11),
        ExecResult(exit_code=0, stdout=b"short", truncated=True),
    ],
    ids=["too-large", "truncated"],
)
async def test_an_output_not_kept_answers_409_result_unavailable_and_does_not_run(
    client: httpx.AsyncClient, key: str, runs: Runs, result: ExecResult
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    runs.script.append(answer(result))

    first = await execute(client, key, sandbox_id, idempotency_key="k-big")
    retry = await execute(client, key, sandbox_id, idempotency_key="k-big")

    assert first.status_code == 200, first.text
    assert first.json()["data"]["stdout"] == result.stdout.decode()
    assert retry.status_code == 409, retry.text
    assert retry.json()["error"]["code"] == UNAVAILABLE
    assert retry.json()["error"]["message"] == TOO_LARGE_TEXT
    assert runs.count == 1


async def test_an_output_at_the_limit_is_kept(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    half = KEEP_LIMIT // 2
    runs.script.append(answer(ExecResult(exit_code=0, stdout=b"o" * half, stderr=b"e" * half)))

    await execute(client, key, sandbox_id, idempotency_key="k-limit")
    replay = await execute(client, key, sandbox_id, idempotency_key="k-limit")

    assert replay.headers[REPLAYED] == "true"
    assert runs.count == 1


async def test_every_replay_writes_one_audit_row_with_the_original_request_id(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    first = await execute(client, key, sandbox_id, idempotency_key="k-audit")
    replays = [
        await execute(client, key, sandbox_id, idempotency_key="k-audit") for _ in range(REPLAYS)
    ]

    async with UnitOfWork(app.state.session_factory) as uow:
        since = base.NOW - timedelta(days=3650)
        rows = await uow.audit.list(org_id, action=REPLAY_ACTION, since=since)

    assert [row.target_id for row in rows] == [sandbox_id] * REPLAYS
    assert {row.outcome.value for row in rows} == {"success"}
    original = first.headers["x-request-id"]
    assert [row.details["original_request_id"] for row in rows] == [original] * REPLAYS
    assert [row.request_id for row in rows] == [r.headers["x-request-id"] for r in replays]


def test_the_stored_key_is_prefixed_so_it_never_meets_a_create_key() -> None:
    scoped = process_routes.sandbox_scoped_key("sbx_1", "ref-1", "k")

    assert scoped.startswith("exec:")
    assert scoped != process_routes.sandbox_scoped_key("sbx_1", "ref-2", "k")
