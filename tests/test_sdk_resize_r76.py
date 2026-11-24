"""SDK ``Sandbox.resize`` / ``AsyncSandbox.resize`` against respx-mocked endpoints (daemon-free)."""

import inspect
import json
import sys
from pathlib import Path

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    AsyncClient,
    CapacityExceeded,
    Client,
    InvalidState,
    QuotaExceeded,
    ValidationFailed,
)

BASE = "http://sandfort.test"
KEY = "sf_test_key"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOX_URL = f"/v1/sandboxes/{SID}"
RESIZE_URL = f"{SANDBOX_URL}/resize"
NOTHING_TO_RESIZE = "nothing to resize: pass cpu_millicores, memory_mib or disk_gib"


def sandbox_json(state: str = "stopped", **resources: int) -> dict[str, object]:
    return {
        "id": SID,
        "name": "demo",
        "state": state,
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3, **resources},
        "env": {},
        "labels": {},
        "network": {"block_all": False},
        "public": False,
        "auto_stop_minutes": 15,
        "auto_delete_minutes": -1,
        "error_reason": None,
        "job_id": None,
    }


def envelope(data: object) -> dict[str, object]:
    return {"success": True, "data": data, "error": None, "meta": None}


def error_envelope(code: str, message: str = "boom") -> dict[str, object]:
    error = {"code": code, "message": message, "details": {}, "request_id": "req_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


async def call(fn, *args, **kwargs):  # type: ignore[no-untyped-def]
    """Invoke a sync or async SDK callable and return its result."""
    result = fn(*args, **kwargs)
    return await result if inspect.isawaitable(result) else result


@pytest.fixture
def api():  # type: ignore[no-untyped-def]
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router
        for recorded in router.calls:
            assert recorded.request.headers["authorization"] == f"Bearer {KEY}"


@pytest.fixture(params=["sync", "async"])
def kind(request) -> str:  # type: ignore[no-untyped-def]
    return request.param


@pytest.fixture
async def client(kind):  # type: ignore[no-untyped-def]
    instance = (Client if kind == "sync" else AsyncClient)(BASE, KEY, max_retries=0)
    yield instance
    await call(instance.close if isinstance(instance, Client) else instance.aclose)


async def stopped_sandbox(api, client):  # type: ignore[no-untyped-def]
    api.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json()))
    return await call(client.get, SID)


def sent_body(route) -> dict[str, object]:  # type: ignore[no-untyped-def]
    return json.loads(route.calls.last.request.content)


# --- request body ----------------------------------------------------------------------


async def test_resize_posts_only_the_given_field(api, client):
    sandbox = await stopped_sandbox(api, client)
    route = api.post(RESIZE_URL).respond(200, json=envelope(sandbox_json(memory_mib=1024)))

    await call(sandbox.resize, memory_mib=1024)

    assert sent_body(route) == {"memory_mib": 1024}
    assert route.call_count == 1


async def test_resize_posts_all_three_fields(api, client):
    sandbox = await stopped_sandbox(api, client)
    route = api.post(RESIZE_URL).respond(
        200, json=envelope(sandbox_json(cpu_millicores=2000, memory_mib=2048, disk_gib=8))
    )

    await call(sandbox.resize, cpu_millicores=2000, memory_mib=2048, disk_gib=8)

    assert sent_body(route) == {"cpu_millicores": 2000, "memory_mib": 2048, "disk_gib": 8}


async def test_resize_does_not_send_omitted_fields(api, client):
    sandbox = await stopped_sandbox(api, client)
    route = api.post(RESIZE_URL).respond(200, json=envelope(sandbox_json(cpu_millicores=500)))

    await call(sandbox.resize, cpu_millicores=500, disk_gib=None)

    assert sent_body(route) == {"cpu_millicores": 500}


async def test_resize_accepts_the_bounds(api, client):
    sandbox = await stopped_sandbox(api, client)
    route = api.post(RESIZE_URL).respond(200, json=envelope(sandbox_json()))

    await call(sandbox.resize, cpu_millicores=100, memory_mib=64, disk_gib=1)
    assert sent_body(route) == {"cpu_millicores": 100, "memory_mib": 64, "disk_gib": 1}

    await call(sandbox.resize, cpu_millicores=1_000_000, memory_mib=16_777_216, disk_gib=1_048_576)
    assert sent_body(route) == {
        "cpu_millicores": 1_000_000,
        "memory_mib": 16_777_216,
        "disk_gib": 1_048_576,
    }


# --- result ----------------------------------------------------------------------------


async def test_resize_returns_the_same_handle_with_the_reply_resources(api, client):
    sandbox = await stopped_sandbox(api, client)
    api.post(RESIZE_URL).respond(
        200, json=envelope(sandbox_json(cpu_millicores=2000, memory_mib=1024, disk_gib=5))
    )

    result = await call(sandbox.resize, memory_mib=1024)

    assert result is sandbox
    assert sandbox.info.resources.memory_mib == 1024
    assert sandbox.info.resources.cpu_millicores == 2000
    assert sandbox.resources.disk_gib == 5
    assert sandbox.state == "stopped"


# --- nothing to send -------------------------------------------------------------------


async def test_resize_without_arguments_raises_and_sends_nothing(api, client):
    sandbox = await stopped_sandbox(api, client)
    route = api.post(RESIZE_URL).respond(200, json=envelope(sandbox_json()))

    with pytest.raises(ValueError, match=NOTHING_TO_RESIZE):
        await call(sandbox.resize)

    assert route.call_count == 0
    assert api.calls.call_count == 1  # the get that built the handle


@pytest.mark.parametrize(
    "kwargs",
    [
        {"memory_mib": True},
        {"cpu_millicores": False},
        {"disk_gib": True},
        {"memory_mib": 1024.0},
        {"cpu_millicores": 500.5},
        {"disk_gib": 2.0},
        {"memory_mib": "1024"},
        {"cpu_millicores": 99},
        {"cpu_millicores": 1_000_001},
        {"memory_mib": 63},
        {"memory_mib": 16_777_217},
        {"disk_gib": 0},
        {"disk_gib": 1_048_577},
        {"memory_mib": -1},
        {"memory_mib": 1024, "disk_gib": 0},
    ],
    ids=repr,
)
async def test_resize_rejects_unusable_values_before_any_request(api, client, kwargs):
    sandbox = await stopped_sandbox(api, client)
    route = api.post(RESIZE_URL).respond(200, json=envelope(sandbox_json()))

    with pytest.raises(ValueError):
        await call(sandbox.resize, **kwargs)

    assert route.call_count == 0
    assert api.calls.call_count == 1


# --- server errors ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "code", "exc_type"),
    [
        (409, "INVALID_STATE", InvalidState),
        (429, "QUOTA_EXCEEDED", QuotaExceeded),
        (503, "CAPACITY", CapacityExceeded),
        (422, "VALIDATION_ERROR", ValidationFailed),
    ],
)
async def test_resize_maps_server_errors_and_keeps_the_handle(
    api, client, status, code, exc_type
):
    sandbox = await stopped_sandbox(api, client)
    before = sandbox.info
    route = api.post(RESIZE_URL).respond(status, json=error_envelope(code))

    with pytest.raises(exc_type) as raised:
        await call(sandbox.resize, memory_mib=1024)

    assert type(raised.value) is exc_type
    assert route.call_count == 1
    assert sandbox.info is before
    assert sandbox.resources.memory_mib == 512
