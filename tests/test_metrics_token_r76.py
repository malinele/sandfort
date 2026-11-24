"""R76: optional bearer token for ``GET /metrics`` (empty token = open, as before).

Config cases need no database. HTTP cases copy the fixture pattern of ``test_observability``:
FakeDriver, temp SQLite database, httpx AsyncClient over the ASGI app.
"""

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api import app as app_module
from sandfort.api.app import create_app
from sandfort.config import METRICS_TOKEN_ENV, MIN_SESSION_SECRET_CHARS, Settings
from sandfort.observability import metrics

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "scrape-token-0123456789abcdef-XYZ"
UNAUTHORIZED_STATUS = 401


# --- config -----------------------------------------------------------------------


def test_metrics_token_env_name() -> None:
    assert METRICS_TOKEN_ENV == "SANDFORT_METRICS_TOKEN"


def test_default_settings_leave_metrics_open() -> None:
    assert Settings().metrics_token == ""


def test_from_env_without_the_variable_leaves_metrics_open() -> None:
    assert Settings.from_env({}).metrics_token == ""


def test_from_env_loads_a_long_enough_token_stripped() -> None:
    settings = Settings.from_env({METRICS_TOKEN_ENV: f"  {TOKEN}\n"})

    assert settings.metrics_token == TOKEN


def test_from_env_blank_value_counts_as_unset() -> None:
    assert Settings.from_env({METRICS_TOKEN_ENV: "   "}).metrics_token == ""


def test_from_env_accepts_exactly_the_minimum_length() -> None:
    token = "a" * MIN_SESSION_SECRET_CHARS

    assert Settings.from_env({METRICS_TOKEN_ENV: token}).metrics_token == token


@pytest.mark.parametrize(
    "short", ["s3cr3t-short-" + "k" * 10, "k" * (MIN_SESSION_SECRET_CHARS - 1)]
)
def test_from_env_rejects_a_short_token_without_echoing_it(short: str) -> None:
    with pytest.raises(ValueError) as raised:
        Settings.from_env({METRICS_TOKEN_ENV: short})

    assert METRICS_TOKEN_ENV in str(raised.value)
    assert short not in str(raised.value)


@pytest.mark.parametrize(
    "bad",
    [
        "a" * 20 + " " + "b" * 20,  # whitespace inside
        "a" * 20 + "\t" + "b" * 20,
        "a" * 40 + "\x01",  # non-printable
        "a" * 40 + "\x7f",
        "a" * 31 + "é",  # non-ASCII
        "a" * 40 + "€",
    ],
)
def test_from_env_rejects_an_unusable_token_without_echoing_it(bad: str) -> None:
    with pytest.raises(ValueError) as raised:
        Settings.from_env({METRICS_TOKEN_ENV: bad})

    assert METRICS_TOKEN_ENV in str(raised.value)
    assert bad not in str(raised.value)


def test_repr_does_not_leak_the_token() -> None:
    assert TOKEN not in repr(Settings(metrics_token=TOKEN))


# --- HTTP -------------------------------------------------------------------------


def _settings(url: str, token: str) -> Settings:
    return Settings(
        driver="fake",
        database_url=url,
        api_key_pepper="test-pepper",
        sandbox_jobs_enabled=True,
        metrics_token=token,
    )


async def _serve(tmp_path: Path, token: str) -> AsyncIterator[httpx.AsyncClient]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'metrics_token.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application: FastAPI = create_app(_settings(url, token))
    try:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            yield http
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    async for http in _serve(tmp_path, TOKEN):
        yield http


@pytest.fixture
async def open_client(tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    async for http in _serve(tmp_path, ""):
        yield http


def _anonymous(response: httpx.Response) -> dict[str, Any]:
    """The 401 envelope without the per-request id, for comparing bodies."""
    body: dict[str, Any] = json.loads(response.text)
    body["error"].pop("request_id", None)
    return body


async def test_missing_header_is_401_in_the_error_envelope(client: httpx.AsyncClient) -> None:
    response = await client.get("/metrics")

    assert response.status_code == UNAUTHORIZED_STATUS
    assert response.json()["error"]["code"] == "UNAUTHORIZED"
    assert TOKEN not in response.text


async def test_wrong_token_is_401(client: httpx.AsyncClient) -> None:
    response = await client.get("/metrics", headers={"Authorization": "Bearer not-the-token"})

    assert response.status_code == UNAUTHORIZED_STATUS
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


async def test_basic_scheme_with_the_right_token_is_401(client: httpx.AsyncClient) -> None:
    response = await client.get("/metrics", headers={"Authorization": f"Basic {TOKEN}"})

    assert response.status_code == UNAUTHORIZED_STATUS


async def test_bare_token_without_a_scheme_is_401(client: httpx.AsyncClient) -> None:
    response = await client.get("/metrics", headers={"Authorization": TOKEN})

    assert response.status_code == UNAUTHORIZED_STATUS


async def test_scheme_is_case_insensitive(client: httpx.AsyncClient) -> None:
    response = await client.get("/metrics", headers={"Authorization": f"bearer {TOKEN}"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    for name in metrics.METRIC_NAMES:
        assert name in response.text


async def test_correct_bearer_token_is_200(client: httpx.AsyncClient) -> None:
    response = await client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")


async def test_every_401_body_is_identical_and_carries_no_challenge(
    client: httpx.AsyncClient,
) -> None:
    attempts: list[dict[str, str]] = [
        {},
        {"Authorization": "Bearer not-the-token"},
        {"Authorization": f"Basic {TOKEN}"},
        {"Authorization": TOKEN},
        {"Authorization": "Bearer "},
    ]

    responses = [await client.get("/metrics", headers=headers) for headers in attempts]

    assert {r.status_code for r in responses} == {UNAUTHORIZED_STATUS}
    assert len({json.dumps(_anonymous(r), sort_keys=True) for r in responses}) == 1
    assert all("www-authenticate" not in r.headers for r in responses)


async def test_unauthenticated_scrape_does_no_database_work(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def explode(_app: FastAPI) -> None:
        raise AssertionError("the queue depth was read before the token was checked")

    monkeypatch.setattr(app_module, "_refresh_queue_depth", explode)

    response = await client.get("/metrics")

    assert response.status_code == UNAUTHORIZED_STATUS


async def test_metrics_stay_open_without_a_token(open_client: httpx.AsyncClient) -> None:
    response = await open_client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
