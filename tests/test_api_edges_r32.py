"""API edges: pinned docs assets with a CSP, HEAD on status, empty ``from_id``, output-limit exit.

The docs and status tests use the full ``create_app`` with the fake driver (neither route
touches the database); the ``from_id`` test needs a migrated database and an ``audit:read`` key.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.schemas.toolbox_process import KILLED_EXIT_CODE, context_run_response
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.drivers.base import ExecResult
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
CSP = "content-security-policy"
JSON_CSP = "default-src 'none'; frame-ancestors 'none'"
SWAGGER_JS = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"
SWAGGER_CSS = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui.css"
REDOC_JS = "https://cdn.jsdelivr.net/npm/redoc@2.2.0/bundles/redoc.standalone.js"
DATA_FAVICON = 'href="data:image/'
THIRD_PARTY_HOST = "fastapi.tiangolo.com"


@pytest.fixture
async def app() -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    settings = Settings(
        driver="fake", database_url="sqlite+aiosqlite:///:memory:", api_key_pepper=PEPPER
    )
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


# --- 1. the docs pages ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "pinned"),
    [("/docs", (SWAGGER_JS, SWAGGER_CSS)), ("/redoc", (REDOC_JS,))],
)
async def test_the_docs_pages_load_pinned_assets_under_their_own_csp(
    client: httpx.AsyncClient, path: str, pinned: tuple[str, ...]
) -> None:
    response = await client.get(path)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    for url in pinned:
        assert url in response.text
    assert THIRD_PARTY_HOST not in response.text
    assert DATA_FAVICON in response.text
    policy = response.headers[CSP]
    assert "frame-ancestors 'none'" in policy
    assert "base-uri 'none'" in policy and "form-action 'none'" in policy
    assert "connect-src 'self'" in policy and "worker-src blob:" in policy
    assert "script-src 'self' https://cdn.jsdelivr.net;" in policy


async def test_the_docs_policy_allows_inline_styles_only(client: httpx.AsyncClient) -> None:
    docs = await client.get("/docs")
    spec = await client.get("/openapi.json")

    assert "style-src https://cdn.jsdelivr.net 'unsafe-inline'" in docs.headers[CSP]
    assert "script-src 'self' https://cdn.jsdelivr.net;" in docs.headers[CSP]
    assert spec.status_code == 200
    assert spec.headers[CSP] == JSON_CSP


async def test_the_docs_pages_stay_out_of_the_schema(client: httpx.AsyncClient) -> None:
    paths = (await client.get("/openapi.json")).json()["paths"]

    assert "/docs" not in paths and "/redoc" not in paths


# --- 2. HEAD on status ---------------------------------------------------------------------


async def test_head_status_answers_200_with_the_get_headers_and_no_body(
    client: httpx.AsyncClient,
) -> None:
    got = await client.get("/v1/status")
    head = await client.head("/v1/status")

    assert head.status_code == 200
    assert head.content == b""
    assert head.headers["content-type"] == got.headers["content-type"]
    assert head.headers["x-content-type-options"] == "nosniff"
    assert head.headers[CSP] == JSON_CSP
    assert int(head.headers["content-length"]) == len(got.content)


# --- 3. an empty from_id -------------------------------------------------------------------


async def test_an_empty_from_id_is_a_validation_error(tmp_path: Path) -> None:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'edges.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        org = Org(id=new_org_id(), name="Edges", slug="edges", created_at=NOW)
        generated = generate_api_key(PEPPER)
        stored = ApiKey(
            id=new_api_key_id(),
            org_id=org.id,
            name="ci",
            prefix=generated.prefix,
            secret_hash=generated.secret_hash,
            scopes=frozenset({Scope.AUDIT_READ}),
            created_at=NOW,
        )
        async with UnitOfWork(application.state.session_factory) as uow:
            await uow.orgs.add(org)
            await uow.api_keys.add(stored)
            await uow.commit()
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            response = await http.get(
                "/v1/audit-events/verify",
                params={"from_id": ""},
                headers={"Authorization": f"Bearer {generated.key}"},
            )
    finally:
        await application.state.engine.dispose()

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


# --- 4. one exit code for an output-limit stop ---------------------------------------------


@pytest.mark.parametrize(
    "result",
    [
        ExecResult(exit_code=137, stdout=b"x" * 10, truncated=True),
        ExecResult(exit_code=0, stderr=b"x" * 10, truncated=True),
        ExecResult(exit_code=1, stdout=b"a", stderr=b"b", truncated=True),
    ],
)
def test_an_output_limit_stop_reports_the_killed_exit_code(result: ExecResult) -> None:
    response = context_run_response(result)

    assert response.stop_reason == "output_limit"
    assert response.exit_code == KILLED_EXIT_CODE == 137


def test_a_run_that_was_not_stopped_at_the_limit_keeps_its_exit_code() -> None:
    response = context_run_response(ExecResult(exit_code=1, stderr=b"boom\n"))

    assert response.stop_reason is None
    assert response.exit_code == 1
