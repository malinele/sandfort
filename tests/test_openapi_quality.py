"""The exported OpenAPI document is usable by client generators.

Every operation declares the error envelope (no 401/403 where no key is taken) and nothing
points at FastAPI's ``HTTPValidationError``; the raw-body upload, the binary download and the
server-sent-event streams carry their real media types; operationIds are the route function
names; the live ``/openapi.json`` serves the export; ``SandboxResponse`` documents its state
enum, ``node_id`` and ``egress_allowlist``.
"""

import json
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute, RouteContext, iter_route_contexts

from sandfort.api.app import PREFIXED_OPERATIONS
from sandfort.api.openapi import (
    AUTH_STATUSES,
    BUILD_LOGS_OPERATION,
    COMMAND_LOGS_FOLLOW_OPERATION,
    CONTEXT_RUN_STREAM_OPERATION,
    DOWNLOAD_OPERATION,
    ERROR_STATUSES,
    HTTP_METHODS,
    SANDBOX_LOGS_OPERATION,
    SSE_DESCRIPTIONS,
    UNAUTHENTICATED_PATHS,
    UPLOAD_OPERATION,
    VALIDATION_REF,
    VALIDATION_STATUS,
    build_app,
    build_document,
    error_ref,
    render_spec,
)
from sandfort.api.schemas.sandboxes import SandboxResponse
from sandfort.domain.sandbox import SandboxState

_TOOLBOX = "/v1/sandboxes/{sandbox_id}/toolbox/process"
PROCESS_EXECUTE_PATH = _TOOLBOX + "/execute"
SESSION_COMMANDS_PATH = _TOOLBOX + "/sessions/{session_id}/commands"
SSE_EVENT_NAMES = {
    SANDBOX_LOGS_OPERATION: ("`stdout`", "`stderr`", "`error`", "`?since=<id>`"),
    COMMAND_LOGS_FOLLOW_OPERATION: ("`stdout`", "`stderr`", "`exit`", "`Last-Event-ID"),
    BUILD_LOGS_OPERATION: ("`log`", "`state`", "zero-based line index"),
    CONTEXT_RUN_STREAM_OPERATION: ("`stdout`", "`stderr`", "`result`", "`error`"),
}
BINARY = {"type": "string", "format": "binary"}


@pytest.fixture(scope="module")
def app() -> FastAPI:
    return build_app()


@pytest.fixture(scope="module")
def document(app: FastAPI) -> dict[str, Any]:
    return build_document(app)


def operations(document: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    for path, item in document["paths"].items():
        for method, operation in item.items():
            if method in HTTP_METHODS:
                yield path, method, operation


def schema_routes(app: FastAPI) -> list[RouteContext]:
    """The exported routes; included routers are flattened into their effective routes."""
    return [
        context
        for context in iter_route_contexts(app.routes)
        if isinstance(context.original_route, APIRoute) and context.include_in_schema
    ]


def route_methods(context: RouteContext) -> set[str]:
    return context.methods or set()


def operation_at(document: dict[str, Any], key: tuple[str, str]) -> dict[str, Any]:
    path, method = key
    result: dict[str, Any] = document["paths"][path][method]
    return result


def resolve(document: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    ref = schema.get("$ref")
    if ref is None:
        return schema
    resolved: dict[str, Any] = document["components"]["schemas"][ref.rsplit("/", 1)[-1]]
    return resolved


# --- error responses ----------------------------------------------------------------------


def test_every_operation_declares_the_error_envelope(document: dict[str, Any]) -> None:
    for path, method, operation in operations(document):
        responses = operation["responses"]
        for status in ERROR_STATUSES:
            if path in UNAUTHENTICATED_PATHS and status in AUTH_STATUSES:
                assert status not in responses, f"{method} {path} declares {status}"
            else:
                assert responses.get(status) == error_ref(status), f"{method} {path} lacks {status}"


def test_the_generated_422_points_at_the_validation_response(document: dict[str, Any]) -> None:
    validated = [op for _, _, op in operations(document) if VALIDATION_STATUS in op["responses"]]

    assert validated
    assert all(op["responses"][VALIDATION_STATUS] == VALIDATION_REF for op in validated)


def test_unauthenticated_operations_have_no_auth_errors(document: dict[str, Any]) -> None:
    open_paths = [path for path in document["paths"] if path in UNAUTHENTICATED_PATHS]

    assert sorted(open_paths) == ["/healthz", "/readyz", "/v1/auth/sso/exchange", "/v1/status"]
    for path in open_paths:
        for operation in document["paths"][path].values():
            assert operation["security"] == []
            assert not AUTH_STATUSES & set(operation["responses"])


def test_no_http_validation_error_remains(document: dict[str, Any]) -> None:
    rendered = json.dumps(document)
    schemas = document["components"]["schemas"]

    assert "HTTPValidationError" not in rendered
    assert "ValidationError" not in schemas
    assert "Error" in document["components"]["responses"]


# --- media types ----------------------------------------------------------------------------


def test_upload_takes_a_required_octet_stream_body(document: dict[str, Any]) -> None:
    body = operation_at(document, UPLOAD_OPERATION)["requestBody"]

    assert body["required"] is True
    assert body["content"] == {"application/octet-stream": {"schema": BINARY}}


def test_download_answers_binary(document: dict[str, Any]) -> None:
    ok = operation_at(document, DOWNLOAD_OPERATION)["responses"]["200"]

    assert ok["content"]["application/octet-stream"]["schema"] == BINARY
    inline = ok["content"]["application/json"]["schema"]
    assert inline == {"$ref": "#/components/schemas/Envelope_FsDownloadResponse_"}


@pytest.mark.parametrize("key", sorted(SSE_DESCRIPTIONS))
def test_streaming_operations_are_event_streams(
    document: dict[str, Any], key: tuple[str, str]
) -> None:
    ok = operation_at(document, key)["responses"]["200"]

    assert ok["content"] == {"text/event-stream": {"schema": {"type": "string"}}}
    assert "`id`" in ok["description"]
    for name in SSE_EVENT_NAMES[key]:
        assert name in ok["description"], f"{key} does not describe {name}"


def test_only_the_named_operations_stream(document: dict[str, Any]) -> None:
    streaming = {
        (path, method)
        for path, method, op in operations(document)
        if "text/event-stream" in op["responses"].get("200", {}).get("content", {})
    }

    assert streaming == set(SSE_DESCRIPTIONS)


# --- operationIds ---------------------------------------------------------------------------


def module_of(context: RouteContext) -> str:
    endpoint = context.endpoint
    assert endpoint is not None
    return endpoint.__module__


def expected_operation_id(context: RouteContext) -> str:
    module, name = module_of(context), context.name
    assert name is not None
    if (module, name) in PREFIXED_OPERATIONS:
        return f"{module.rsplit('.', 1)[-1]}_{name}"
    return name


def test_operation_ids_are_unique(document: dict[str, Any]) -> None:
    ids = [op["operationId"] for _, _, op in operations(document)]

    assert len(ids) == len(set(ids))


def test_operation_ids_are_the_function_names(app: FastAPI, document: dict[str, Any]) -> None:
    routes = schema_routes(app)

    assert routes
    for route in routes:
        for method in route_methods(route):
            operation = document["paths"][route.path_format][method.lower()]
            assert operation["operationId"] == expected_operation_id(route)
    assert len(list(operations(document))) == sum(len(route_methods(r)) for r in routes)


def test_a_shared_name_gets_the_module_prefix(document: dict[str, Any]) -> None:
    process_execute = document["paths"][PROCESS_EXECUTE_PATH]["post"]
    session_command = document["paths"][SESSION_COMMANDS_PATH]["post"]

    assert process_execute["operationId"] == "execute_command"
    assert session_command["operationId"] == "sessions_execute_command"


def test_prefixed_operations_name_real_routes(app: FastAPI) -> None:
    pairs = {(module_of(route), route.name) for route in schema_routes(app)}

    assert pairs >= PREFIXED_OPERATIONS


# --- the live route -------------------------------------------------------------------------


async def test_the_live_route_serves_the_export() -> None:
    app = build_app()
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            response = await http.get("/openapi.json")
    finally:
        await app.state.engine.dispose()

    assert response.status_code == 200
    assert response.json() == json.loads(render_spec(build_document()))


def test_the_live_document_is_built_once() -> None:
    app = build_app()

    first = app.openapi()

    assert app.openapi() is first
    assert first == build_document(app)


# --- SandboxResponse ------------------------------------------------------------------------


def test_sandbox_response_documents_state_and_hidden_fields(document: dict[str, Any]) -> None:
    properties = document["components"]["schemas"]["SandboxResponse"]["properties"]
    state = resolve(document, properties["state"])

    assert set(state["enum"]) == {item.value for item in SandboxState}
    assert properties["node_id"]["type"] == ["string", "null"]
    assert "egress_allowlist" in properties


def test_sandbox_response_serialises_the_state_value() -> None:
    response = SandboxResponse.model_validate(
        {
            "id": "sbx_1",
            "name": "one",
            "state": "stopped",
            "resources": {},
            "env": {},
            "labels": {},
            "network": {},
            "public": False,
            "auto_stop_minutes": 15,
            "auto_delete_minutes": -1,
            "isolation": "container",
            "node_id": "node_1",
        }
    )

    dumped = response.model_dump(mode="json")

    assert response.state is SandboxState.STOPPED
    assert dumped["state"] == "stopped"
    assert dumped["node_id"] == "node_1"
    assert dumped["egress_allowlist"] is None
