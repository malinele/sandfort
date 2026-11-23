"""R63 persona findings on the OpenAPI export: 3.1 nullability, header scope and bounds,
inline download schema, 409 reasons, state enums, response headers and 413 (daemon-free)."""

import json
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort import errors
from sandfort.api.app import create_app
from sandfort.api.openapi import (
    DOWNLOAD_OPERATION,
    EXEC_OPERATION,
    EXPORT_OPERATION,
    HTTP_METHODS,
    IDEMPOTENT_OPERATIONS,
    UPLOAD_OPERATION,
    build_app,
    build_document,
    takes_idempotency_key,
)
from sandfort.api.routes.toolbox.process import IdempotencyResultUnavailable
from sandfort.api.schemas.toolbox_fs import MAX_INLINE_READ_BYTES
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
HEADER = "Idempotency-Key"
MAX_KEY = 255
SANDBOX = "/v1/sandboxes/{sandbox_id}"


@pytest.fixture(scope="module")
def document() -> dict[str, Any]:
    return build_document(build_app())


def _operations(document: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    for path, item in document["paths"].items():
        for method, operation in item.items():
            if method in HTTP_METHODS:
                yield path, method, operation


def _walk(node: Any) -> Iterator[tuple[str, Any]]:
    """Every (key, value) pair of a JSON document, depth first."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield key, value
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


# --- 1. OpenAPI 3.1 nullability ------------------------------------------------------------


def test_the_exported_spec_has_no_nullable_keyword(document: dict[str, Any]) -> None:
    assert document["openapi"].startswith("3.1")
    assert [key for key, _ in _walk(document) if key == "nullable"] == []


def test_the_committed_spec_has_no_nullable_keyword() -> None:
    committed = json.loads((ROOT / "openapi" / "sandfort.v1.json").read_text())

    assert [key for key, _ in _walk(committed) if key == "nullable"] == []


def test_node_id_is_a_string_or_null_type_union(document: dict[str, Any]) -> None:
    node_id = document["components"]["schemas"]["SandboxResponse"]["properties"]["node_id"]

    assert node_id["type"] == ["string", "null"]


# --- 2 and 3. Idempotency-Key bounds and scope ---------------------------------------------


def _header(operation: dict[str, Any]) -> dict[str, Any]:
    (parameter,) = [p for p in operation["parameters"] if p["name"] == HEADER]
    return parameter


def test_the_header_schema_declares_the_live_bounds(document: dict[str, Any]) -> None:
    for path, method, _ in IDEMPOTENT_OPERATIONS:
        schema = _header(document["paths"][path][method])["schema"]
        text = [branch for branch in schema["anyOf"] if branch.get("type") == "string"]

        assert text == [{"type": "string", "minLength": 1, "maxLength": MAX_KEY}], path


def test_exactly_the_named_operations_take_the_header(document: dict[str, Any]) -> None:
    declared = {
        (path, method) for path, method, op in _operations(document) if takes_idempotency_key(op)
    }

    assert declared == {(path, method) for path, method, _ in IDEMPOTENT_OPERATIONS}
    assert EXEC_OPERATION in declared


def test_the_description_names_each_operation_and_says_others_ignore_it(
    document: dict[str, Any],
) -> None:
    description = document["info"]["description"]

    for path, method, name in IDEMPOTENT_OPERATIONS:
        assert f"{name} (`{method.upper()} {path}`)" in description
    assert "Every other POST ignores the header" in description
    assert "Creates accept" not in description


def test_the_description_documents_unknown_query_parameters_and_405(
    document: dict[str, Any],
) -> None:
    description = document["info"]["description"]

    assert "extra_forbidden" in description
    assert "405" in description
    assert "METHOD_NOT_ALLOWED" in description


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'r63.db'}"
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


BAD_KEYS = ("", "k" * (MAX_KEY + 1))
CREATE_BODIES = (
    ("/v1/sandboxes", {}),
    ("/v1/volumes", {"name": "vol-a"}),
    ("/v1/snapshots", {"image": "alpine:3"}),
    ("/v1/snapshots/from-sandbox", {"sandbox_id": "sbx_x", "name": "snap-a"}),
    ("/v1/sandboxes/sbx_x/toolbox/process/execute", {"command": "true"}),
)


@pytest.mark.parametrize("key", BAD_KEYS, ids=["empty", "too-long"])
@pytest.mark.parametrize(("path", "body"), CREATE_BODIES)
async def test_an_out_of_range_key_answers_422_validation_error(
    client: httpx.AsyncClient, auth: dict[str, str], path: str, body: dict[str, Any], key: str
) -> None:
    response = await client.post(path, headers={**auth, HEADER: key}, json=body)

    assert response.status_code == 422, response.text
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert error["details"]["errors"][0]["loc"] == ["header", HEADER]


async def test_a_key_at_the_bounds_is_accepted(
    client: httpx.AsyncClient, auth: dict[str, str]
) -> None:
    for key in ("k", "k" * MAX_KEY):
        body = {"name": f"v-{len(key)}"}
        response = await client.post("/v1/volumes", headers={**auth, HEADER: key}, json=body)

        assert response.status_code == 201, response.text


# --- 4. fs download ------------------------------------------------------------------------


def test_the_inline_download_answer_has_a_schema(document: dict[str, Any]) -> None:
    path, method = DOWNLOAD_OPERATION
    content = document["paths"][path][method]["responses"]["200"]["content"]
    schemas = document["components"]["schemas"]

    assert content["application/json"]["schema"] == {
        "$ref": "#/components/schemas/Envelope_FsDownloadResponse_"
    }
    inline = schemas["FsDownloadResponse"]
    assert set(inline["properties"]) == {"path", "size_bytes", "content", "truncated"}
    envelope = schemas["Envelope_FsDownloadResponse_"]
    assert envelope["properties"]["data"]["anyOf"][0] == {
        "$ref": "#/components/schemas/FsDownloadResponse"
    }
    assert {"application/octet-stream", "application/x-tar"} <= set(content)


def test_max_bytes_is_documented_with_its_bounds(document: dict[str, Any]) -> None:
    path, method = DOWNLOAD_OPERATION
    parameters = {p["name"]: p for p in document["paths"][path][method]["parameters"]}
    max_bytes = parameters["max_bytes"]
    integer = [b for b in max_bytes["schema"]["anyOf"] if b.get("type") == "integer"]

    assert integer == [{"type": "integer", "minimum": 1, "maximum": MAX_INLINE_READ_BYTES}]
    assert MAX_INLINE_READ_BYTES == 2097152
    assert "inline=true" in max_bytes["description"]
    assert "ignored otherwise" in max_bytes["description"]
    assert parameters["inline"]["description"]


# --- 5. 409 reasons and state enums --------------------------------------------------------


def test_result_unavailable_is_a_409_reason() -> None:
    error = IdempotencyResultUnavailable("the answer was not kept")

    assert error.status == 409
    assert error.code == "IDEMPOTENCY_RESULT_UNAVAILABLE"
    assert error.details["reason"] == errors.RESULT_UNAVAILABLE == "result_unavailable"


def test_the_description_lists_result_unavailable_and_shared_name_taken(
    document: dict[str, Any],
) -> None:
    description = document["info"]["description"]

    assert "`result_unavailable`" in description
    assert "a sandbox, volume or snapshot with that name already exists" in description


def _state_values(document: dict[str, Any], schema: str) -> list[str]:
    schemas = document["components"]["schemas"]
    reference = schemas[schema]["properties"]["state"]["$ref"]
    values: list[str] = schemas[reference.rsplit("/", 1)[-1]]["enum"]
    return values


def test_volume_and_snapshot_states_are_enums(document: dict[str, Any]) -> None:
    assert _state_values(document, "VolumeResponse") == ["ready", "deleting"]
    assert _state_values(document, "SnapshotResponse") == [
        "pending",
        "ready",
        "error",
        "deleting",
    ]


# --- 6. internal notes never reach the spec ------------------------------------------------


def test_no_description_leaks_an_internal_note(document: dict[str, Any]) -> None:
    texts = [value for key, value in _walk(document) if key == "description"]

    assert texts
    assert [t for t in texts if isinstance(t, str) and "form feed" in t.lower()] == []
    assert all(isinstance(t, str) and "\f" not in t for t in texts)


def test_the_sandbox_list_description_starts_with_its_summary(document: dict[str, Any]) -> None:
    description = document["paths"]["/v1/sandboxes"]["get"]["description"]

    assert description.startswith("List sandboxes.")


# --- 7. 413 --------------------------------------------------------------------------------


def test_413_is_listed_on_every_operation_that_can_answer_it(document: dict[str, Any]) -> None:
    expected = {
        (path, method) for path, method, op in _operations(document) if "requestBody" in op
    } | {
        (SANDBOX + "/toolbox/fs/list", "get"),
        (SANDBOX + "/toolbox/fs/stat", "get"),
        DOWNLOAD_OPERATION,
    }
    listed = {(p, m) for p, m, op in _operations(document) if "413" in op["responses"]}

    assert listed == expected
    assert UPLOAD_OPERATION in listed
    assert ("/v1/sandboxes", "post") in listed
    assert ("/v1/sandboxes", "get") not in listed


# --- 9. response headers -------------------------------------------------------------------


def _header_names(response: dict[str, Any], document: dict[str, Any]) -> set[str]:
    if "$ref" in response:
        response = document["components"]["responses"][response["$ref"].rsplit("/", 1)[-1]]
    return set(response.get("headers", {}))


def test_every_response_declares_x_request_id(document: dict[str, Any]) -> None:
    for path, method, operation in _operations(document):
        for status, response in operation["responses"].items():
            names = _header_names(response, document)
            assert "x-request-id" in names, f"{method} {path} {status}"
    assert "x-request-id" in document["components"]["headers"]


def test_retry_after_is_on_429_and_503_only(document: dict[str, Any]) -> None:
    for path, method, operation in _operations(document):
        for status, response in operation["responses"].items():
            has = "Retry-After" in _header_names(response, document)
            assert has == (status in {"429", "503"}), f"{method} {path} {status}"


def test_idempotent_replayed_is_on_the_keyed_operations_success_answers(
    document: dict[str, Any],
) -> None:
    for path, method, operation in _operations(document):
        keyed = takes_idempotency_key(operation)
        for status, response in operation["responses"].items():
            has = "Idempotent-Replayed" in _header_names(response, document)
            assert has == (keyed and status.startswith("2")), f"{method} {path} {status}"


def test_downloads_declare_their_headers(document: dict[str, Any]) -> None:
    path, method = DOWNLOAD_OPERATION
    download = document["paths"][path][method]["responses"]["200"]
    export_path, export_method = EXPORT_OPERATION
    export = document["paths"][export_path][export_method]["responses"]["200"]

    assert {"ETag", "Content-Length", "Content-Disposition"} <= set(download["headers"])
    assert "Content-Disposition" in export["headers"]
    declared = document["components"]["headers"]
    assert {"ETag", "Content-Length", "Content-Disposition", "Retry-After"} <= set(declared)
    assert declared["Idempotent-Replayed"]["schema"]["enum"] == ["true"]
