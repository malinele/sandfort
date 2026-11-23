"""SDK r29: include_destroyed, get by name, delete_on_failure, snapshot export, status, API
keys and code contexts (sync, plus one async case for each surface)."""

import json
import sys
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    AmbiguousSandboxName,
    AsyncClient,
    Client,
    InternalError,
    InvalidState,
    NotFound,
    SandboxFailedError,
    TransportError,
)
from sandfort_sdk._transport import client_kwargs  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
OTHER_SID = "sbx_01HYYYYYYYYYYYYYYYYYYYYYYY"
THIRD_SID = "sbx_01HXXXXXXXXXXXXXXXXXXXXXXX"
SANDBOXES = "/v1/sandboxes"
SANDBOX = f"{SANDBOXES}/{SID}"
CONTEXTS = f"{SANDBOX}/toolbox/code-contexts"
CTX_ID = "ctx_0123456789abcdef"
CTX = f"{CONTEXTS}/{CTX_ID}"
SNAPSHOT_EXPORT = "/v1/snapshots/snap_1/export"
CREATED = "2026-11-06T10:00:00Z"
Answer = httpx.Response | Callable[[httpx.Request], httpx.Response]


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def failure(status: int, code: str, message: str = "boom") -> httpx.Response:
    error = {"code": code, "message": message, "details": {}, "request_id": "req_1"}
    body = {"success": False, "data": None, "error": error, "meta": None}
    return httpx.Response(status, json=body)


def reply(data: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=envelope(data))


def sandbox_json(
    state: str = "started", *, sandbox_id: str = SID, name: str = "demo"
) -> dict[str, Any]:
    return {
        "id": sandbox_id,
        "name": name,
        "state": state,
        "error_reason": "image pull failed" if state == "error" else None,
    }


class Api:
    """A MockTransport handler: answers by (method, path) and records every request."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], Answer] = {}
        self.requests: list[httpx.Request] = []

    def on(self, method: str, path: str, answer: Answer) -> "Api":
        self.routes[(method, path)] = answer
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.routes.get((request.method, request.url.path))
        if answer is None:
            raise AssertionError(f"unexpected {request.method} {request.url.path}")
        return answer(request) if callable(answer) else answer

    def calls(self) -> list[str]:
        return [f"{r.method} {r.url.path}" for r in self.requests]

    def body(self, index: int) -> Any:
        return json.loads(self.requests[index].content)


def sync_client(api: Api) -> Client:
    client = Client(BASE, KEY)
    client._transport._http.close()
    client._transport._http = httpx.Client(
        transport=httpx.MockTransport(api), **client_kwargs(BASE, KEY, 30.0)
    )
    return client


async def async_client(api: Api) -> AsyncClient:
    client = AsyncClient(BASE, KEY)
    await client._transport._http.aclose()
    client._transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(api), **client_kwargs(BASE, KEY, 30.0)
    )
    return client


# --- include_destroyed ------------------------------------------------------------------------


def test_include_destroyed_is_sent_only_when_true() -> None:
    api = Api().on("GET", SANDBOXES, reply([sandbox_json()]))
    client = sync_client(api)

    client.list_sandboxes()
    client.list_sandboxes(include_destroyed=True)
    list(client.iter_sandboxes(include_destroyed=True))
    list(client.iter_sandboxes())

    sent = ["include_destroyed" in r.url.params for r in api.requests]
    assert sent == [False, True, True, False]
    assert api.requests[1].url.params["include_destroyed"] == "true"


async def test_async_include_destroyed_is_sent_only_when_true() -> None:
    api = Api().on("GET", SANDBOXES, reply([sandbox_json()]))
    client = await async_client(api)

    await client.list_sandboxes()
    await client.list_sandboxes(include_destroyed=True)
    iterated = [item async for item in client.iter_sandboxes(include_destroyed=True)]
    await client.aclose()

    assert len(iterated) == 1
    assert ["include_destroyed" in r.url.params for r in api.requests] == [False, True, True]


# --- get by id or name ------------------------------------------------------------------------


def test_get_by_id_fetches_that_sandbox_only() -> None:
    api = Api().on("GET", SANDBOX, reply(sandbox_json()))

    assert sync_client(api).get(SID).id == SID
    assert api.calls() == [f"GET {SANDBOX}"]


def test_get_by_name_resolves_among_live_sandboxes() -> None:
    rows = [
        sandbox_json("destroyed", sandbox_id=THIRD_SID, name="work"),
        sandbox_json("error", sandbox_id=OTHER_SID, name="work"),
        sandbox_json("stopped", sandbox_id=SID, name="work"),
    ]
    api = Api().on("GET", SANDBOXES, reply(rows))

    sandbox = sync_client(api).get("work")

    assert (sandbox.id, sandbox.state) == (SID, "stopped")
    assert api.calls() == [f"GET {SANDBOXES}"]


def test_get_by_unknown_name_raises_not_found_naming_it() -> None:
    api = Api().on("GET", SANDBOXES, reply([sandbox_json(name="other")]))

    with pytest.raises(NotFound, match="no sandbox named 'ghost'"):
        sync_client(api).get("ghost")


def test_get_by_ambiguous_name_lists_the_candidate_ids() -> None:
    rows = [
        sandbox_json(sandbox_id=SID, name="twin"),
        sandbox_json("stopped", sandbox_id=OTHER_SID, name="twin"),
    ]
    api = Api().on("GET", SANDBOXES, reply(rows))

    with pytest.raises(AmbiguousSandboxName) as caught:
        sync_client(api).get("twin")

    assert caught.value.candidates == ((SID, "started"), (OTHER_SID, "stopped"))
    assert SID in str(caught.value)
    assert OTHER_SID in str(caught.value)


async def test_async_get_by_name_and_unknown_name() -> None:
    api = Api().on("GET", SANDBOXES, reply([sandbox_json(name="work")]))
    client = await async_client(api)

    found = await client.get("work")
    with pytest.raises(NotFound, match="ghost"):
        await client.get("ghost")
    await client.aclose()

    assert found.id == SID


# --- delete_on_failure ------------------------------------------------------------------------


def failing_create_api(delete_answer: Answer | None = None) -> Api:
    api = Api().on("POST", SANDBOXES, reply(sandbox_json("error"), 201))
    return api.on("DELETE", SANDBOX, delete_answer or reply(sandbox_json("destroying")))


def test_failed_create_deletes_the_sandbox_then_raises() -> None:
    api = failing_create_api()

    with pytest.raises(SandboxFailedError) as caught:
        sync_client(api).create_sandbox()

    assert api.calls() == [f"POST {SANDBOXES}", f"DELETE {SANDBOX}"]
    assert caught.value.deleted is True
    assert "was deleted" in str(caught.value)
    assert (caught.value.sandbox_id, caught.value.state) == (SID, "error")
    assert caught.value.error_reason == "image pull failed"


def test_delete_on_failure_false_keeps_the_sandbox() -> None:
    api = failing_create_api()

    with pytest.raises(SandboxFailedError) as caught:
        sync_client(api).create_sandbox(delete_on_failure=False)

    assert api.calls() == [f"POST {SANDBOXES}"]
    assert caught.value.deleted is False
    assert "was deleted" not in str(caught.value)


def test_a_failing_delete_leaves_the_original_error() -> None:
    api = failing_create_api(failure(500, "INTERNAL"))

    with pytest.raises(SandboxFailedError) as caught:
        sync_client(api).create_sandbox()

    assert caught.value.deleted is False
    assert api.calls() == [f"POST {SANDBOXES}", f"DELETE {SANDBOX}"]


async def test_async_failed_create_deletes_then_raises_and_false_keeps() -> None:
    api = failing_create_api()
    client = await async_client(api)

    with pytest.raises(SandboxFailedError) as deleted:
        await client.create_sandbox()
    with pytest.raises(SandboxFailedError) as kept:
        await client.create_sandbox(delete_on_failure=False)
    await client.aclose()

    assert api.calls() == [f"POST {SANDBOXES}", f"DELETE {SANDBOX}", f"POST {SANDBOXES}"]
    assert (deleted.value.deleted, kept.value.deleted) == (True, False)


# --- snapshot export --------------------------------------------------------------------------


class BrokenStream(httpx.SyncByteStream):
    def __iter__(self) -> Iterator[bytes]:
        yield b"partial"
        raise httpx.ReadError("connection lost")


def tar_response(chunks: list[bytes]) -> httpx.Response:
    headers = {"Content-Type": "application/x-tar"}
    return httpx.Response(200, content=iter(chunks), headers=headers)


def test_export_writes_the_streamed_bytes_and_returns_the_count(tmp_path: Path) -> None:
    chunks = [b"a" * 1000, b"b" * 500, b"c"]
    api = Api().on("GET", SNAPSHOT_EXPORT, tar_response(chunks))
    target = tmp_path / "image.tar"

    written = sync_client(api).export_snapshot("snap_1", target)

    assert written == 1501
    assert target.read_bytes() == b"".join(chunks)
    assert api.requests[0].headers["Accept"] == "application/x-tar"


def test_export_of_a_snapshot_not_ready_raises_and_writes_nothing(tmp_path: Path) -> None:
    api = Api().on("GET", SNAPSHOT_EXPORT, failure(409, "INVALID_STATE", "not ready"))
    target = tmp_path / "image.tar"

    with pytest.raises(InvalidState):
        sync_client(api).snapshots.export("snap_1", str(target))

    assert not target.exists()


def test_export_cut_off_mid_stream_removes_the_partial_file(tmp_path: Path) -> None:
    response = httpx.Response(200, stream=BrokenStream())
    api = Api().on("GET", SNAPSHOT_EXPORT, response)
    target = tmp_path / "image.tar"

    with pytest.raises(TransportError):
        sync_client(api).export_snapshot("snap_1", target)

    assert not target.exists()


async def test_async_export_writes_the_streamed_bytes(tmp_path: Path) -> None:
    api = Api().on("GET", SNAPSHOT_EXPORT, httpx.Response(200, content=b"tar-bytes" * 10))
    client = await async_client(api)
    target = tmp_path / "image.tar"

    written = await client.export_snapshot("snap_1", target)
    await client.aclose()

    assert written == 90
    assert target.read_bytes() == b"tar-bytes" * 10


# --- status -----------------------------------------------------------------------------------

STATUS = {
    "status": "degraded",
    "version": "0.1.0",
    "build_sha": "4871ea2",
    "started_at": "2026-11-06T08:00:00+00:00",
    "notice": {"message": "maintenance at 22:00", "updated_at": "2026-11-06T09:30:00+00:00"},
}


def test_status_parses_the_notice() -> None:
    api = Api().on("GET", "/v1/status", reply(STATUS))

    info = sync_client(api).status()

    assert (info.status, info.version, info.build_sha) == ("degraded", "0.1.0", "4871ea2")
    assert info.started_at == datetime(2026, 11, 6, 8, 0, tzinfo=UTC)
    assert info.notice is not None
    assert info.notice.message == "maintenance at 22:00"
    assert info.notice.updated_at == datetime(2026, 11, 6, 9, 30, tzinfo=UTC)


async def test_async_status_without_notice_or_build_sha() -> None:
    data = {**STATUS, "status": "ok", "build_sha": None, "notice": None}
    api = Api().on("GET", "/v1/status", reply(data))
    client = await async_client(api)

    info = await client.status()
    await client.aclose()

    assert (info.status, info.build_sha, info.notice) == ("ok", None, None)


# --- API keys ---------------------------------------------------------------------------------


def key_json(**extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "key_1",
        "name": "ci",
        "prefix": "sf_ab12",
        "scopes": ["sandboxes:read", "toolbox"],
        "sandbox_labels": None,
        "max_sandboxes": None,
        "created_at": CREATED,
        "last_used_at": None,
        "expires_at": None,
        "revoked_at": None,
        "created_by": "key_0",
    }
    return {**base, **extra}


def test_create_api_key_sends_the_body_and_returns_the_plaintext_once() -> None:
    expires = datetime(2027, 1, 1, tzinfo=UTC)
    created = key_json(sandbox_labels={"team": "a"}, max_sandboxes=5, key="sf_secret")
    api = Api().on("POST", "/v1/api-keys", reply(created, 201))

    result = sync_client(api).create_api_key(
        "ci",
        ["sandboxes:read", "toolbox"],
        sandbox_labels={"team": "a"},
        max_sandboxes=5,
        expires_at=expires,
    )

    assert api.body(0) == {
        "name": "ci",
        "scopes": ["sandboxes:read", "toolbox"],
        "sandbox_labels": {"team": "a"},
        "max_sandboxes": 5,
        "expires_at": "2027-01-01T00:00:00+00:00",
    }
    assert (result.key, result.id, result.max_sandboxes) == ("sf_secret", "key_1", 5)
    assert result.scopes == ("sandboxes:read", "toolbox")
    assert "sf_secret" not in repr(result)


def test_create_api_key_without_optional_fields_sends_only_name_and_scopes() -> None:
    api = Api().on("POST", "/v1/api-keys", reply(key_json(key="sf_secret"), 201))

    sync_client(api).create_api_key("ci", ["toolbox"])

    assert api.body(0) == {"name": "ci", "scopes": ["toolbox"]}


def test_create_api_key_checks_its_arguments_before_sending() -> None:
    api = Api()
    client = sync_client(api)

    with pytest.raises(ValueError, match="sandbox_labels"):
        client.create_api_key("ci", ["toolbox"], max_sandboxes=3)
    with pytest.raises(ValueError, match="timezone-aware"):
        client.create_api_key("ci", ["toolbox"], expires_at=datetime(2027, 1, 1))
    with pytest.raises(ValueError, match="scopes"):
        client.create_api_key("ci", [])

    assert api.requests == []


def test_list_and_revoke_api_keys() -> None:
    revoked = key_json(revoked_at="2026-11-06T11:00:00Z")
    api = Api().on("GET", "/v1/api-keys", reply([key_json(), revoked]))
    api.on("DELETE", "/v1/api-keys/key_1", reply(revoked))
    client = sync_client(api)

    keys = client.list_api_keys()
    result = client.revoke_api_key("key_1")

    assert [key.revoked_at is None for key in keys] == [True, False]
    assert result.revoked_at == datetime(2026, 11, 6, 11, 0, tzinfo=UTC)
    assert api.calls() == ["GET /v1/api-keys", "DELETE /v1/api-keys/key_1"]


async def test_async_api_key_create_list_revoke() -> None:
    api = Api().on("POST", "/v1/api-keys", reply(key_json(key="sf_secret"), 201))
    api.on("GET", "/v1/api-keys", reply([key_json()]))
    api.on("DELETE", "/v1/api-keys/key_1", reply(key_json(revoked_at=CREATED)))
    client = await async_client(api)

    created = await client.create_api_key("ci", ["toolbox"])
    listed = await client.list_api_keys()
    revoked = await client.revoke_api_key("key_1")
    await client.aclose()

    assert (created.key, len(listed), revoked.revoked_at is not None) == ("sf_secret", 1, True)


# --- code contexts ----------------------------------------------------------------------------


def exec_json(stdout: str = "", exit_code: int = 0) -> dict[str, Any]:
    return {
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": "",
        "timed_out": False,
        "truncated": False,
        "duration_ms": 3,
    }


def contexts_api() -> Api:
    context = {"id": CTX_ID, "language": "python", "cwd": "/work"}
    api = Api().on("POST", CONTEXTS, reply(context, 201))
    api.on("GET", CONTEXTS, reply([context]))
    api.on("POST", f"{CTX}/run", reply(exec_json("2\n")))
    api.on("DELETE", CTX, reply({"id": CTX_ID, "deleted": True}))
    api.on("GET", SANDBOX, reply(sandbox_json()))
    return api


def test_code_contexts_create_run_list_delete_use_the_right_paths() -> None:
    api = contexts_api()
    sandbox = sync_client(api).get(SID)

    context = sandbox.code_contexts.create(cwd="/work")
    result = context.run("print(1 + 1)", timeout_s=20)
    listed = sandbox.code_contexts.list()
    context.delete()

    assert (context.id, context.cwd, context.language) == (CTX_ID, "/work", "python")
    assert (result.stdout, result.ok) == ("2\n", True)
    assert [c.id for c in listed] == [CTX_ID]
    assert api.calls()[1:] == [
        f"POST {CONTEXTS}",
        f"POST {CTX}/run",
        f"GET {CONTEXTS}",
        f"DELETE {CTX}",
    ]
    assert api.body(1) == {"language": "python", "cwd": "/work"}
    assert api.body(2) == {"language": "python", "code": "print(1 + 1)", "timeout_s": 20}


def test_code_context_create_without_cwd_leaves_it_out_and_run_defaults_to_60s() -> None:
    api = contexts_api()
    sandbox = sync_client(api).get(SID)

    sandbox.code_contexts.create().run("x = 1")

    assert api.body(1) == {"language": "python"}
    assert api.body(2)["timeout_s"] == 60


def test_code_context_run_error_is_typed() -> None:
    api = contexts_api()
    api.on("POST", f"{CTX}/run", failure(500, "INTERNAL"))
    context = sync_client(api).get(SID).code_contexts.create()

    with pytest.raises(InternalError):
        context.run("1/0")


async def test_async_code_contexts_create_run_list_delete() -> None:
    api = contexts_api()
    client = await async_client(api)
    sandbox = await client.get(SID)

    context = await sandbox.code_contexts.create(cwd="/work")
    result = await context.run("print(1 + 1)")
    listed = await sandbox.code_contexts.list()
    await context.delete()
    await client.aclose()

    assert (result.stdout, len(listed)) == ("2\n", 1)
    assert api.calls()[-1] == f"DELETE {CTX}"
