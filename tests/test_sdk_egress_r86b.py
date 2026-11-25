"""SDK ``set_egress_allowlist`` and egress fields of ``SandboxInfo`` (respx-mocked, daemon-free)."""

import dataclasses
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
    Client,
    Forbidden,
    InvalidResponseError,
    InvalidState,
    NotFound,
    SandboxInfo,
    Unprocessable,
    ValidationFailed,
)

BASE = "http://sandfort.test"
KEY = "sf_test_key"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOX_URL = f"/v1/sandboxes/{SID}"


def sandbox_json(**extra: object) -> dict[str, object]:
    return {
        "id": SID,
        "name": "demo",
        "state": "started",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "env": {},
        "labels": {},
        "network": {"block_all": False},
        "public": False,
        "auto_stop_minutes": 15,
        "auto_delete_minutes": -1,
        "error_reason": None,
        "job_id": None,
        **extra,
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


def sent_body(route) -> dict[str, object]:  # type: ignore[no-untyped-def]
    return json.loads(route.calls.last.request.content)


# --- request ---------------------------------------------------------------------------


async def test_set_egress_allowlist_patches_the_list(api, client):
    route = api.patch(SANDBOX_URL).respond(
        200, json=envelope(sandbox_json(egress_allowlist=["pypi.org"], egress_policy_generation=2))
    )

    sandbox = await call(client.set_egress_allowlist, SID, ["pypi.org", "10.0.0.0/8"])

    assert route.call_count == 1
    assert sent_body(route) == {"egress_allowlist": ["pypi.org", "10.0.0.0/8"]}
    assert sandbox.info.id == SID
    assert sandbox.info.egress_policy_generation == 2
    assert sandbox.info.egress_allowlist == ("pypi.org",)


async def test_empty_list_is_sent_as_an_empty_list(api, client):
    route = api.patch(SANDBOX_URL).respond(
        200, json=envelope(sandbox_json(egress_allowlist=[], egress_policy_generation=3))
    )

    sandbox = await call(client.set_egress_allowlist, SID, [])

    assert sent_body(route) == {"egress_allowlist": []}
    assert sandbox.info.egress_allowlist == ()


async def test_entries_are_sent_as_given_without_local_validation(api, client):
    route = api.patch(SANDBOX_URL).respond(200, json=envelope(sandbox_json()))
    odd = ["UPPER.example", "host:8080", "https://x", "1.2.3.4/8", ""]

    await call(client.set_egress_allowlist, SID, tuple(odd))

    assert sent_body(route) == {"egress_allowlist": odd}


async def test_sandbox_id_is_percent_encoded_in_the_path(api, client):
    route = api.patch("/v1/sandboxes/a%2Fb").respond(200, json=envelope(sandbox_json()))

    await call(client.set_egress_allowlist, "a/b", ["pypi.org"])

    assert route.call_count == 1


async def test_a_bare_string_is_refused_before_any_request(api, client):
    route = api.patch(SANDBOX_URL).respond(200, json=envelope(sandbox_json()))

    with pytest.raises(TypeError):
        await call(client.set_egress_allowlist, SID, "pypi.org")

    assert route.call_count == 0


async def test_none_is_refused_before_any_request(api, client):
    route = api.patch(SANDBOX_URL).respond(200, json=envelope(sandbox_json()))

    with pytest.raises(TypeError):
        await call(client.set_egress_allowlist, SID, None)

    assert route.call_count == 0


# --- errors surface through the existing mapping ---------------------------------------


@pytest.mark.parametrize(
    ("status", "code", "expected"),
    [
        (403, "FORBIDDEN", Forbidden),
        (404, "NOT_FOUND", NotFound),
        (409, "INVALID_STATE", InvalidState),
        (422, "VALIDATION_ERROR", ValidationFailed),
        (422, "UNPROCESSABLE", Unprocessable),
    ],
)
async def test_error_statuses_map_to_existing_exceptions(api, client, status, code, expected):
    api.patch(SANDBOX_URL).respond(
        status, json=error_envelope(code, "network egress is disabled by operator policy")
    )

    with pytest.raises(expected) as caught:
        await call(client.set_egress_allowlist, SID, ["pypi.org"])

    assert caught.value.status_code == status
    assert "operator policy" in str(caught.value)


# --- parsing (case K4) -----------------------------------------------------------------


def test_k4_parses_generation_and_ignores_unknown_fields():
    payload = sandbox_json(
        egress_allowlist=["pypi.org"],
        egress_policy_generation=4,
        future_field={"nested": [1, 2]},
        another_unknown="x",
    )

    info = SandboxInfo.from_payload(payload)

    assert info.egress_policy_generation == 4
    assert info.egress_allowlist == ("pypi.org",)


def test_older_server_without_egress_fields_defaults_generation_to_zero():
    info = SandboxInfo.from_payload(sandbox_json())

    assert info.egress_policy_generation == 0
    assert info.egress_allowlist is None


def test_null_generation_and_allowlist_parse_as_default_and_none():
    info = SandboxInfo.from_payload(
        sandbox_json(egress_allowlist=None, egress_policy_generation=None)
    )

    assert info.egress_policy_generation == 0
    assert info.egress_allowlist is None


@pytest.mark.parametrize("bad", ["", False, [], {}, "3"])
def test_a_wrong_typed_generation_is_refused_not_coerced_to_zero(bad):
    with pytest.raises(InvalidResponseError):
        SandboxInfo.from_payload(sandbox_json(egress_policy_generation=bad))


def test_new_fields_do_not_move_existing_positional_fields():
    names = [field.name for field in dataclasses.fields(SandboxInfo)]

    assert names.index("image_mounts") < names.index("egress_policy_generation")
    assert names.index("egress_policy_generation") < names.index("egress_allowlist")
