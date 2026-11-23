"""R65 spec-contract findings: 405 Allow, 415 and 422 documentation, servers, descriptions."""

from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.openapi import (
    HTTP_METHODS,
    RAW_BODY_OPERATIONS,
    UPLOAD_OPERATION,
    build_app,
    build_document,
)
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"


@pytest.fixture(scope="module")
def document() -> dict[str, Any]:
    return build_document(build_app())


def _operations(document: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    for path, item in document["paths"].items():
        for method, operation in item.items():
            if method in HTTP_METHODS:
                yield path, method, operation


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'r65d.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def auth(app: FastAPI) -> dict[str, str]:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=frozenset(Scope),
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}"}


def _allow(response: httpx.Response) -> list[str]:
    return [method.strip() for method in response.headers["allow"].split(",")]


# --- 1. 405 Allow lists every method of the path --------------------------------------------


async def test_a_405_on_a_volume_lists_get_and_delete(
    client: httpx.AsyncClient, auth: dict[str, str]
) -> None:
    response = await client.patch("/v1/volumes/vol_x", headers=auth, json={})

    assert response.status_code == 405
    assert response.json()["error"]["code"] == "METHOD_NOT_ALLOWED"
    assert _allow(response) == ["DELETE", "GET"]


async def test_a_405_on_the_download_path_lists_get_and_head(
    client: httpx.AsyncClient, auth: dict[str, str]
) -> None:
    response = await client.post("/v1/sandboxes/sbx_x/toolbox/fs/download", headers=auth)

    assert response.status_code == 405
    assert _allow(response) == ["GET", "HEAD"]


async def test_a_405_on_a_collection_lists_its_methods(
    client: httpx.AsyncClient, auth: dict[str, str]
) -> None:
    response = await client.delete("/v1/volumes", headers=auth)

    assert response.status_code == 405
    assert _allow(response) == ["GET", "POST"]


# --- 2 and 3. 415 and 422 are documented -----------------------------------------------------


def test_json_body_operations_declare_415(document: dict[str, Any]) -> None:
    upload_path, upload_method = UPLOAD_OPERATION
    bodies = [
        (path, method, op)
        for path, method, op in _operations(document)
        if "requestBody" in op and (path, method) not in RAW_BODY_OPERATIONS
    ]

    assert bodies
    for path, method, operation in bodies:
        response = operation["responses"].get("415")
        assert response == {"$ref": "#/components/responses/UnsupportedMediaType"}, (path, method)
    for raw_path, raw_method in RAW_BODY_OPERATIONS:  # raw bytes bodies (upload, restore)
        assert "415" not in document["paths"][raw_path][raw_method]["responses"]
    assert (upload_path, upload_method) in RAW_BODY_OPERATIONS


def test_the_415_component_names_the_code_and_the_media_type(document: dict[str, Any]) -> None:
    description = document["components"]["responses"]["UnsupportedMediaType"]["description"]

    assert "UNSUPPORTED_MEDIA_TYPE" in description
    assert "application/json" in description


def test_the_shared_422_names_both_codes_and_when_each_occurs(document: dict[str, Any]) -> None:
    component = document["components"]["responses"]["ValidationFailed"]
    description = component["description"]

    assert "VALIDATION_ERROR" in description
    assert "UNPROCESSABLE" in description
    validated = [op for _, _, op in _operations(document) if "422" in op["responses"]]
    assert validated
    assert all(
        op["responses"]["422"] == {"$ref": "#/components/responses/ValidationFailed"}
        for op in validated
    )


# --- 4. no internal audit text in the public descriptions -------------------------------------


def test_no_description_leaks_the_audit_trade_off(document: dict[str, Any]) -> None:
    rendered = (ROOT / "openapi" / "sandfort.v1.json").read_text()

    assert "Audit trade-off" not in rendered
    assert "intent-then-act" not in rendered
    assert "supersedes" not in rendered
    path, method = UPLOAD_OPERATION
    assert document["paths"][path][method]["description"]


# --- 5. servers -------------------------------------------------------------------------------


def test_the_spec_declares_servers(document: dict[str, Any]) -> None:
    assert document["servers"] == [
        {"url": "https://api.sandfort.dev", "description": "hosted beta"},
        {"url": "http://localhost:8000", "description": "local dev"},
    ]


# --- 6. every operation has a description -----------------------------------------------------


def test_every_operation_has_a_plain_description(document: dict[str, Any]) -> None:
    for path, method, operation in _operations(document):
        description = operation.get("description", "")
        assert len(description) >= 30, f"{method} {path} lacks a description"
        assert "—" not in description, f"{method} {path} uses an em-dash"


# --- 7. the api-key list is documented as unpaginated ------------------------------------------


def test_the_api_key_list_says_it_is_unpaginated(document: dict[str, Any]) -> None:
    description = document["paths"]["/v1/api-keys"]["get"]["description"]

    assert "unpaginated" in description
    assert "every key" in description
