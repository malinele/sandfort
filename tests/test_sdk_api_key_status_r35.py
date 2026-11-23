"""Round 35: the SDK ``ApiKeyInfo`` carries the server's key ``status``.

The REST answers compute ``status`` (``active``, ``expired`` or ``revoked``) at answer time.
The SDK keeps the value as sent; a server that omits it loads as ``active``.
"""

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, get_args

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sandfort_sdk import ApiKeyInfo, AsyncClient, Client  # noqa: E402
from sandfort_sdk._transport import client_kwargs  # noqa: E402
from sandfort_sdk.api_keys import ApiKeyStatus, CreatedApiKey  # noqa: E402
from sandfort_sdk.exceptions import InvalidResponseError  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
CREATED = "2026-11-06T10:00:00Z"
STATUSES: tuple[ApiKeyStatus, ...] = ("active", "expired", "revoked")

Handler = Callable[[httpx.Request], httpx.Response]


def key_json(key_id: str = "key_1", **extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": key_id,
        "name": "ci",
        "prefix": "sf_ab12",
        "scopes": ["sandboxes:read"],
        "sandbox_labels": None,
        "max_sandboxes": None,
        "created_at": CREATED,
        "last_used_at": None,
        "expires_at": None,
        "revoked_at": None,
        "created_by": "key_0",
    }
    return {**base, **extra}


def reply(data: Any, status: int = 200) -> httpx.Response:
    body = {"success": True, "data": data, "error": None, "meta": None}
    return httpx.Response(status, json=body)


def keys_handler(rows: list[dict[str, Any]]) -> Handler:
    """GET answers every row, POST the first row, DELETE the row of the path id."""

    def handle(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return reply(rows)
        if request.method == "POST":
            return reply({**rows[0], "key": "sf_secret"}, 201)
        key_id = request.url.path.rsplit("/", 1)[-1]
        return reply(next(row for row in rows if row["id"] == key_id))

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


def status_rows() -> list[dict[str, Any]]:
    return [key_json(f"key_{status}", status=status) for status in STATUSES]


def test_package_root_exports_the_status_alias_with_exactly_the_known_values() -> None:
    import sandfort_sdk

    assert "ApiKeyStatus" in sandfort_sdk.__all__
    assert sandfort_sdk.ApiKeyStatus is ApiKeyStatus
    assert set(get_args(sandfort_sdk.ApiKeyStatus)) == {"active", "expired", "revoked"}
    assert len(get_args(sandfort_sdk.ApiKeyStatus)) == 3


@pytest.mark.parametrize("status", STATUSES)
def test_from_payload_keeps_the_status_of_the_payload(status: str) -> None:
    info = ApiKeyInfo.from_payload(key_json(status=status))

    assert info.status == status


def test_from_payload_without_status_loads_as_active() -> None:
    info = ApiKeyInfo.from_payload(key_json())

    assert info.status == "active"


def test_a_revoked_payload_without_status_is_not_second_guessed() -> None:
    info = ApiKeyInfo.from_payload(key_json(revoked_at=CREATED))

    assert (info.status, info.revoked_at is not None) == ("active", True)


def test_a_status_that_is_not_a_string_is_an_invalid_response() -> None:
    with pytest.raises(InvalidResponseError):
        ApiKeyInfo.from_payload(key_json(status=3))


@pytest.mark.parametrize("status", STATUSES)
def test_created_api_key_inherits_the_status(status: str) -> None:
    created = CreatedApiKey.from_payload(key_json(status=status, key="sf_secret"))

    assert (created.status, created.key) == (status, "sf_secret")
    assert "sf_secret" not in repr(created)


def test_created_api_key_without_status_loads_as_active() -> None:
    created = CreatedApiKey.from_payload(key_json(key="sf_secret"))

    assert created.status == "active"


def test_status_does_not_disturb_positional_construction() -> None:
    info = ApiKeyInfo.from_payload(key_json())
    again = ApiKeyInfo(
        info.id,
        info.name,
        info.prefix,
        info.scopes,
        info.sandbox_labels,
        info.max_sandboxes,
        info.created_at,
        info.last_used_at,
        info.expires_at,
        info.revoked_at,
        info.created_by,
    )

    assert again == info


def test_sync_list_passes_the_status_through() -> None:
    client = sync_client(keys_handler(status_rows()))

    listed = client.list_api_keys()

    assert [key.status for key in listed] == list(STATUSES)


def test_sync_revoke_and_create_pass_the_status_through() -> None:
    client = sync_client(keys_handler(status_rows()))

    revoked = client.revoke_api_key("key_revoked")
    created = client.create_api_key("ci", ["sandboxes:read"])

    assert (revoked.status, created.status) == ("revoked", "active")


async def test_async_list_passes_the_status_through() -> None:
    client = await async_client(keys_handler(status_rows()))

    listed = await client.list_api_keys()
    await client.aclose()

    assert [key.status for key in listed] == list(STATUSES)


async def test_async_revoke_and_create_pass_the_status_through() -> None:
    client = await async_client(keys_handler(status_rows()))

    revoked = await client.revoke_api_key("key_expired")
    created = await client.create_api_key("ci", ["sandboxes:read"])
    await client.aclose()

    assert (revoked.status, created.status) == ("expired", "active")


def test_list_of_an_older_server_without_status_loads_every_key_as_active() -> None:
    rows = [key_json("key_1"), key_json("key_2", revoked_at=CREATED)]
    client = sync_client(keys_handler(rows))

    listed = client.list_api_keys()

    assert [key.status for key in listed] == ["active", "active"]
