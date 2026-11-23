"""r63: request parsing is strict and answers in the envelope.

* a request body with a repeated object key (any depth) is a 422 ``VALIDATION_ERROR``;
* a deep nesting or an integer of too many digits is a 422, not a bare 400;
* a non-JSON body is a 415 ``UNSUPPORTED_MEDIA_TYPE``;
* a past ``expires_at`` is a 422;
* ``?cascade=`` takes only lowercase ``true`` or ``false``;
* idempotency compares the validated request (defaults applied), code-run honours the key like
  exec, an empty or long key is a 422 on every keyed route, a header sent twice is a 422 and a
  replay of an output that was not kept is audited ``denied``.
"""

import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

import test_stop_reason_delete_reset as base
from sandfort.api.schemas.toolbox_process import ExecuteRequest
from sandfort.api.text_guard import MAX_DEPTH, MAX_INT_DIGITS, body_findings
from sandfort.auth.api_keys import generate_api_key
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Scope
from sandfort.drivers.base import ExecRequest, ExecResult
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_api_key_id
from sandfort.services.idempotency import (
    IdempotencyService,
    canonical_body_hash,
    model_body_hash,
)

app = base.app
client = base.client
driver = base.driver
fast_settle = base.fast_settle
org_id = base.org_id
key = base.key
kicks = base.kicks

KEYS = "/v1/api-keys"
SANDBOXES = "/v1/sandboxes"
EXECUTE = "/v1/sandboxes/{sandbox_id}/toolbox/process/execute"
CODE_RUN = "/v1/sandboxes/{sandbox_id}/toolbox/process/code-run"
SESSIONS = "/v1/sandboxes/{sandbox_id}/toolbox/process/sessions"
HEADER = "Idempotency-Key"
REPLAYED = "idempotent-replayed"
MARKER = "r63-run"
JSON_TYPE = {"Content-Type": "application/json"}
DEEP_ARRAY = 100_000
HUGE_INTEGER_DIGITS = 5_000
KEEP_LIMIT = 256 * 1024
UNPROCESSABLE = 422
UNSUPPORTED = 415


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def admin(app: FastAPI, org_id: str) -> str:
    """A key that may administer API keys and use sandboxes."""
    generated = generate_api_key(base.PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org_id,
        name="admin",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=base.FULL_ACCESS | {Scope.API_KEYS_ADMIN},
        created_at=base.NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def post_raw(
    client: httpx.AsyncClient,
    token: str,
    path: str,
    content: bytes | str,
    headers: dict[str, str] | None = None,
    method: str = "POST",
) -> httpx.Response:
    sent = {**bearer(token), **(JSON_TYPE if headers is None else headers)}
    return await client.request(method, path, content=content, headers=sent)


def first_error(response: httpx.Response) -> dict[str, Any]:
    error: dict[str, Any] = response.json()["error"]["details"]["errors"][0]
    return error


def assert_validation_envelope(response: httpx.Response) -> None:
    body = response.json()
    assert response.status_code == UNPROCESSABLE, response.text
    assert body["success"] is False
    assert body["error"]["code"] == "VALIDATION_ERROR"


# ---- 1. duplicate object keys


async def test_a_repeated_top_level_key_is_refused_and_nothing_is_revoked(
    client: httpx.AsyncClient, admin: str
) -> None:
    child = (
        await client.post(
            KEYS, json={"name": "c", "scopes": ["sandboxes:read"]}, headers=bearer(admin)
        )
    ).json()["data"]

    response = await post_raw(
        client, admin, f"{KEYS}/{child['id']}", '{"cascade":false,"cascade":true}', method="DELETE"
    )

    assert_validation_envelope(response)
    assert first_error(response)["msg"] == "duplicate key 'cascade' in the request body"
    assert first_error(response)["loc"] == ["body"]
    assert first_error(response)["type"] == "duplicate_key"
    listed = (await client.get(KEYS, headers=bearer(admin))).json()["data"]
    assert [row["revoked_at"] for row in listed if row["id"] == child["id"]] == [None]


async def test_a_repeated_key_in_a_nested_object_is_located_at_that_object(
    client: httpx.AsyncClient, key: str
) -> None:
    response = await post_raw(client, key, SANDBOXES, '{"labels":{"a":"1","a":"2"}}')

    assert_validation_envelope(response)
    assert first_error(response)["loc"] == ["body", "labels"]
    assert first_error(response)["msg"] == "duplicate key 'a' in the request body"


async def test_a_repeated_key_inside_an_array_element_is_located_by_index(
    client: httpx.AsyncClient, key: str
) -> None:
    response = await post_raw(client, key, SANDBOXES, '{"volumes":[{"x":1},{"x":1,"x":2}]}')

    assert_validation_envelope(response)
    assert first_error(response)["loc"] == ["body", "volumes", "1"]


async def test_a_repeated_key_is_found_after_an_escape_decodes_it(
    client: httpx.AsyncClient, key: str
) -> None:
    response = await post_raw(client, key, SANDBOXES, '{"name":"a","\\u006eame":"b"}')

    assert first_error(response)["msg"] == "duplicate key 'name' in the request body"


async def test_the_repeated_key_is_escaped_in_the_message(
    client: httpx.AsyncClient, key: str
) -> None:
    response = await post_raw(client, key, SANDBOXES, '{"a\\nb":1,"a\\nb":2}')

    assert first_error(response)["msg"] == "duplicate key 'a\\nb' in the request body"


async def test_the_same_key_in_different_objects_is_fine(
    client: httpx.AsyncClient, key: str
) -> None:
    response = await post_raw(client, key, SANDBOXES, '{"labels":{"a":"1"},"env":{"a":"2"}}')

    assert response.status_code == 201, response.text


# ---- 2. depth, integers, content types, past expiry


async def test_a_100000_deep_array_is_a_422_in_the_envelope(
    client: httpx.AsyncClient, key: str
) -> None:
    response = await post_raw(client, key, SANDBOXES, "[" * DEEP_ARRAY + "]" * DEEP_ARRAY)

    assert_validation_envelope(response)
    assert first_error(response)["type"] == "nesting_too_deep"
    assert first_error(response)["loc"] == ["body"]


async def test_a_nesting_just_over_the_cap_is_refused_and_the_cap_itself_is_not() -> None:
    over = b'{"a":' * (MAX_DEPTH + 1) + b"1" + b"}" * (MAX_DEPTH + 1)
    within = b'{"a":' * MAX_DEPTH + b"1" + b"}" * MAX_DEPTH

    assert [f.kind for f in body_findings(over)] == ["nesting_too_deep"]
    assert body_findings(within) == []


async def test_a_5000_digit_integer_is_a_422_in_the_envelope(
    client: httpx.AsyncClient, key: str
) -> None:
    body = '{"auto_stop_minutes":' + "9" * HUGE_INTEGER_DIGITS + "}"

    response = await post_raw(client, key, SANDBOXES, body)

    assert_validation_envelope(response)
    assert first_error(response)["type"] == "integer_too_long"
    assert first_error(response)["loc"] == ["body"]


def test_the_integer_cap_counts_digits_and_ignores_the_sign() -> None:
    longest = "1" * MAX_INT_DIGITS

    assert body_findings(f"[{longest}]".encode()) == []
    assert body_findings(f"[-{longest}]".encode()) == []
    assert [f.kind for f in body_findings(f"[{longest}1]".encode())] == ["integer_too_long"]
    assert body_findings(b'["' + b"1" * 5000 + b'"]') == []


@pytest.mark.parametrize(
    "content_type", ["text/plain", "application/x-www-form-urlencoded", "application/xml"]
)
async def test_a_non_json_body_is_a_415_in_the_envelope(
    client: httpx.AsyncClient, key: str, content_type: str
) -> None:
    response = await post_raw(
        client, key, SANDBOXES, '{"name":"x"}', headers={"Content-Type": content_type}
    )

    body = response.json()
    assert response.status_code == UNSUPPORTED, response.text
    assert body["success"] is False
    assert body["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE"
    assert body["error"]["request_id"] == response.headers["x-request-id"]


async def test_json_and_structured_json_content_types_are_accepted(
    client: httpx.AsyncClient, key: str
) -> None:
    for content_type in ("application/json; charset=utf-8", "application/vnd.sandfort+json"):
        response = await post_raw(
            client, key, SANDBOXES, "{}", headers={"Content-Type": content_type}
        )

        assert response.status_code == 201, response.text


async def test_an_empty_body_with_another_content_type_is_not_refused(
    client: httpx.AsyncClient, key: str
) -> None:
    sandbox_id = await base.create_sandbox(client, key)

    response = await post_raw(
        client, key, f"{SANDBOXES}/{sandbox_id}/stop", b"", headers={"Content-Type": "text/plain"}
    )

    assert response.status_code != UNSUPPORTED, response.text


async def test_a_past_expires_at_is_a_422_validation_error(
    client: httpx.AsyncClient, admin: str
) -> None:
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()

    response = await client.post(
        KEYS,
        json={"name": "late", "scopes": ["sandboxes:read"], "expires_at": past},
        headers=bearer(admin),
    )

    assert_validation_envelope(response)
    assert first_error(response)["loc"] == ["body", "expires_at"]
    assert first_error(response)["msg"] == "expires_at must be in the future"


# ---- 3. strict cascade


async def mint(client: httpx.AsyncClient, admin: str) -> str:
    response = await client.post(
        KEYS, json={"name": "c", "scopes": ["sandboxes:read"]}, headers=bearer(admin)
    )
    key_id: str = response.json()["data"]["id"]
    return key_id


@pytest.mark.parametrize("value", ["yes", "on", "1", "TRUE", "True", "0", "off", "t", ""])
async def test_cascade_accepts_only_lowercase_true_or_false(
    client: httpx.AsyncClient, admin: str, value: str
) -> None:
    target = await mint(client, admin)

    response = await client.delete(f"{KEYS}/{target}?cascade={value}", headers=bearer(admin))

    assert_validation_envelope(response)
    assert first_error(response)["loc"] == ["query", "cascade"]
    listed = (await client.get(KEYS, headers=bearer(admin))).json()["data"]
    assert [row["revoked_at"] for row in listed if row["id"] == target] == [None]


@pytest.mark.parametrize("value", ["true", "false"])
async def test_cascade_true_and_false_are_accepted(
    client: httpx.AsyncClient, admin: str, value: str
) -> None:
    target = await mint(client, admin)

    response = await client.delete(f"{KEYS}/{target}?cascade={value}", headers=bearer(admin))

    assert response.status_code == 200, response.text
    assert response.json()["data"]["cascade"] is (value == "true")


# ---- 4-5. idempotency over the validated request


class Runs:
    """Counts the commands that reach the driver; ``big`` makes them print too much to keep."""

    def __init__(self) -> None:
        self.count = 0
        self.big = False


@pytest.fixture
def runs(driver: FakeDriver, monkeypatch: pytest.MonkeyPatch) -> Runs:
    counter = Runs()
    original = driver.exec

    async def exec_(ref: str, request: ExecRequest) -> ExecResult:
        ran = request.argv[-1] == MARKER or (
            request.argv[0] == "bash" and request.argv[1].endswith("/main.sh")
        )
        if not ran:
            return await original(ref, request)
        counter.count += 1
        out = b"o" * (KEEP_LIMIT + 1) if counter.big else f"run {counter.count}".encode()
        return ExecResult(exit_code=0, stdout=out)

    monkeypatch.setattr(driver, "exec", exec_)
    return counter


async def keyed(
    client: httpx.AsyncClient,
    token: str,
    path: str,
    body: dict[str, Any],
    idempotency_key: str | None,
) -> httpx.Response:
    headers = bearer(token)
    if idempotency_key is not None:
        headers[HEADER] = idempotency_key
    return await client.post(path, json=body, headers=headers)


EXEC_VARIANTS = [
    pytest.param({"timeout_s": 60}, id="timeout-explicit-default"),
    pytest.param({"timeout_s": 60.0}, id="timeout-float"),
    pytest.param({"env": {}}, id="empty-env"),
    pytest.param({"stdin": None}, id="null-stdin"),
    pytest.param({"cwd": None}, id="null-cwd"),
    pytest.param({"timeout_s": 60.0, "env": {}, "stdin": None, "cwd": None}, id="all"),
]


@pytest.mark.parametrize("extra", EXEC_VARIANTS)
async def test_exec_compares_the_request_with_defaults_applied(
    client: httpx.AsyncClient, key: str, runs: Runs, extra: dict[str, Any]
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    path = EXECUTE.format(sandbox_id=sandbox_id)

    first = await keyed(client, key, path, {"command": MARKER}, "k-canon")
    second = await keyed(client, key, path, {"command": MARKER, **extra}, "k-canon")

    assert second.status_code == 200, second.text
    assert second.headers[REPLAYED] == "true"
    assert second.json() == first.json()
    assert runs.count == 1


async def test_exec_with_another_value_is_still_a_mismatch(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    path = EXECUTE.format(sandbox_id=sandbox_id)
    await keyed(client, key, path, {"command": MARKER}, "k-other")

    other = await keyed(client, key, path, {"command": MARKER, "timeout_s": 61}, "k-other")

    assert other.status_code == UNPROCESSABLE, other.text
    assert other.json()["error"]["code"] == "IDEMPOTENCY_MISMATCH"
    assert runs.count == 1


async def test_a_sandbox_create_compares_the_request_with_defaults_applied(
    client: httpx.AsyncClient, key: str
) -> None:
    first = await keyed(client, key, SANDBOXES, {"name": "same"}, "k-create")
    second = await keyed(
        client, key, SANDBOXES, {"name": "same", "env": {}, "labels": {}}, "k-create"
    )

    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    assert second.headers[REPLAYED] == "true"
    assert second.json()["data"]["id"] == first.json()["data"]["id"]


async def test_a_record_stored_with_the_raw_body_hash_still_replays(
    app: FastAPI, org_id: str
) -> None:
    service: IdempotencyService = app.state.idempotency_service
    raw = b'{"command":"x", "timeout_s":60.0}'
    model = ExecuteRequest(command="x", timeout_s=60)
    operation = "POST /demo"
    await service.begin(org_id, "key_1", "k-legacy", canonical_body_hash(raw))
    await service.complete(org_id, "key_1", "k-legacy", canonical_body_hash(raw), 200, {"ok": 1})

    stored = await service.begin(
        org_id,
        "key_1",
        "k-legacy",
        model_body_hash(operation, model),
        (canonical_body_hash(raw),),
    )

    assert stored is not None
    assert stored.body == {"ok": 1}


# ---- code-run honours Idempotency-Key


async def test_code_run_replays_the_same_key_and_body_and_runs_once(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    path = CODE_RUN.format(sandbox_id=sandbox_id)
    body = {"language": "bash", "code": "echo hi"}

    first = await keyed(client, key, path, body, "k-code")
    replay = await keyed(
        client, key, path, {**body, "timeout_s": 60.0, "env": {}, "argv": []}, "k-code"
    )

    assert first.status_code == replay.status_code == 200, replay.text
    assert REPLAYED not in first.headers
    assert replay.headers[REPLAYED] == "true"
    assert replay.json() == first.json()
    assert runs.count == 1


async def test_code_run_with_another_body_is_a_mismatch_and_does_not_run(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    path = CODE_RUN.format(sandbox_id=sandbox_id)
    await keyed(client, key, path, {"language": "bash", "code": "echo 1"}, "k-code-2")

    other = await keyed(client, key, path, {"language": "bash", "code": "echo 2"}, "k-code-2")

    assert other.status_code == UNPROCESSABLE, other.text
    assert other.json()["error"]["code"] == "IDEMPOTENCY_MISMATCH"
    assert runs.count == 1


async def test_code_run_scopes_the_key_to_the_sandbox_and_the_api_key(
    client: httpx.AsyncClient, key: str, admin: str, runs: Runs
) -> None:
    one = await base.create_sandbox(client, key)
    two = await base.create_sandbox(client, key)
    body = {"language": "bash", "code": "echo hi"}

    await keyed(client, key, CODE_RUN.format(sandbox_id=one), body, "k-scope")
    other_sandbox = await keyed(client, key, CODE_RUN.format(sandbox_id=two), body, "k-scope")
    other_key = await keyed(client, admin, CODE_RUN.format(sandbox_id=one), body, "k-scope")

    assert REPLAYED not in other_sandbox.headers
    assert REPLAYED not in other_key.headers
    assert runs.count == 3  # noqa: PLR2004


async def test_code_run_without_the_header_runs_every_time(
    client: httpx.AsyncClient, key: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    path = CODE_RUN.format(sandbox_id=sandbox_id)
    body = {"language": "bash", "code": "echo hi"}

    await keyed(client, key, path, body, None)
    await keyed(client, key, path, body, None)

    assert runs.count == 2  # noqa: PLR2004


async def test_a_code_run_replay_is_audited_like_an_exec_replay(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    path = CODE_RUN.format(sandbox_id=sandbox_id)
    body = {"language": "bash", "code": "echo hi"}
    first = await keyed(client, key, path, body, "k-audit-code")
    await keyed(client, key, path, body, "k-audit-code")

    rows = await replay_rows(app, org_id)

    assert [row.outcome.value for row in rows] == ["success"]
    assert rows[0].details["original_request_id"] == first.headers["x-request-id"]


async def replay_rows(app: FastAPI, org_id: str) -> list[Any]:
    async with UnitOfWork(app.state.session_factory) as uow:
        return list(
            await uow.audit.list(
                org_id, action="sandbox.exec.replay", since=base.NOW - timedelta(days=3650)
            )
        )


# ---- the replay of an output that was not kept is denied


async def test_a_409_result_unavailable_replay_is_audited_denied_with_its_reason(
    app: FastAPI, client: httpx.AsyncClient, key: str, org_id: str, runs: Runs
) -> None:
    sandbox_id = await base.create_sandbox(client, key)
    path = EXECUTE.format(sandbox_id=sandbox_id)
    runs.big = True
    await keyed(client, key, path, {"command": MARKER}, "k-big")

    retry = await keyed(client, key, path, {"command": MARKER}, "k-big")

    assert retry.status_code == 409, retry.text
    assert retry.json()["error"]["code"] == "IDEMPOTENCY_RESULT_UNAVAILABLE"
    rows = await replay_rows(app, org_id)
    assert [row.outcome.value for row in rows] == ["denied"]
    assert rows[0].details["reason"] == "result_unavailable"
    assert rows[0].details["original_request_id"] is not None
    async with UnitOfWork(app.state.session_factory) as uow:
        everything = await uow.audit.list(org_id, since=base.NOW - timedelta(days=3650), limit=200)
    denied = [r for r in everything if r.action in ("request.denied", "sandbox.exec.replay")]
    assert [r.action for r in denied] == ["sandbox.exec.replay"]  # one row for the refusal


# ---- 6. the key header: bounds and a duplicate


KeyedCall = Callable[
    [httpx.AsyncClient, str, str, list[tuple[str, str]]], Awaitable[httpx.Response]
]


async def call_exec(
    client: httpx.AsyncClient, token: str, sandbox_id: str, extra: list[tuple[str, str]]
) -> httpx.Response:
    return await client.post(
        EXECUTE.format(sandbox_id=sandbox_id),
        json={"command": MARKER},
        headers=[*bearer(token).items(), *extra],
    )


async def call_code_run(
    client: httpx.AsyncClient, token: str, sandbox_id: str, extra: list[tuple[str, str]]
) -> httpx.Response:
    return await client.post(
        CODE_RUN.format(sandbox_id=sandbox_id),
        json={"language": "bash", "code": "echo hi"},
        headers=[*bearer(token).items(), *extra],
    )


async def call_session(
    client: httpx.AsyncClient, token: str, sandbox_id: str, extra: list[tuple[str, str]]
) -> httpx.Response:
    return await client.post(
        SESSIONS.format(sandbox_id=sandbox_id), json={}, headers=[*bearer(token).items(), *extra]
    )


async def call_create(
    client: httpx.AsyncClient, token: str, sandbox_id: str, extra: list[tuple[str, str]]
) -> httpx.Response:
    return await client.post(SANDBOXES, json={}, headers=[*bearer(token).items(), *extra])


CALLS = [
    pytest.param(call_exec, id="exec"),
    pytest.param(call_code_run, id="code-run"),
    pytest.param(call_session, id="session-create"),
    pytest.param(call_create, id="sandbox-create"),
]


@pytest.mark.parametrize("call", CALLS)
@pytest.mark.parametrize("bad", ["", "k" * 256], ids=["empty", "too-long"])
async def test_an_empty_or_long_key_is_a_422_validation_error_on_every_keyed_route(
    client: httpx.AsyncClient, key: str, runs: Runs, call: KeyedCall, bad: str
) -> None:
    sandbox_id = await base.create_sandbox(client, key)

    response = await call(client, key, sandbox_id, [(HEADER, bad)])

    assert_validation_envelope(response)
    assert first_error(response)["loc"][0] == "header"
    assert runs.count == 0


@pytest.mark.parametrize("call", CALLS)
async def test_two_different_key_headers_are_a_422(
    client: httpx.AsyncClient, key: str, runs: Runs, call: KeyedCall
) -> None:
    sandbox_id = await base.create_sandbox(client, key)

    response = await call(client, key, sandbox_id, [(HEADER, "one"), (HEADER, "two")])

    assert_validation_envelope(response)
    assert first_error(response)["loc"] == ["header", HEADER]
    assert first_error(response)["msg"] == "Idempotency-Key must be given once"
    assert runs.count == 0


@pytest.mark.parametrize("call", CALLS)
async def test_the_same_key_header_twice_is_one_key(
    client: httpx.AsyncClient, key: str, runs: Runs, call: KeyedCall
) -> None:
    sandbox_id = await base.create_sandbox(client, key)

    response = await call(client, key, sandbox_id, [(HEADER, "same"), (HEADER, "same")])

    assert response.status_code < 300, response.text


def test_the_stored_hash_is_stable_across_key_order_and_defaults() -> None:
    first = ExecuteRequest.model_validate({"command": "x", "timeout_s": 60})
    second = ExecuteRequest.model_validate(
        json.loads('{"stdin":null,"env":{},"timeout_s":60.0,"command":"x"}')
    )

    assert model_body_hash("POST /a", first) == model_body_hash("POST /a", second)
    assert model_body_hash("POST /a", first) != model_body_hash("POST /b", first)
