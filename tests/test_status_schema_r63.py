"""Round 63: ``GET /v1/status`` is typed in the OpenAPI spec (``StatusResponse``)."""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from sandfort.api import openapi
from sandfort.api.app import create_app
from sandfort.config import Settings

STATUS = "/v1/status"
OLD_KEYS = {
    "status",
    "version",
    "build_sha",
    "image_sha",
    "build_matches_image",
    "started_at",
    "notice",
    "audit_public_key",
    "audit_key_fingerprint",
}
NEW_PROPERTIES = {
    "image_sha",
    "build_matches_image",
    "audit_public_key",
    "audit_key_fingerprint",
    "started_at",
    "notice",
    "version",
}
NULLABLE = {
    "build_sha",
    "image_sha",
    "build_matches_image",
    "notice",
    "audit_public_key",
    "audit_key_fingerprint",
}


JSON_TYPES: dict[str, type | tuple[type, ...]] = {
    "string": str,
    "boolean": bool,
    "null": type(None),
    "object": dict,
}


def conforms(value: Any, schema: dict[str, Any], components: dict[str, Any]) -> bool:
    """Whether ``value`` fits the subset of JSON Schema the status model uses."""
    if "$ref" in schema:
        target = components[schema["$ref"].rsplit("/", 1)[1]]
        return conforms(value, target, components)
    if "anyOf" in schema:
        return any(conforms(value, item, components) for item in schema["anyOf"])
    if "enum" in schema and value not in schema["enum"]:
        return False
    if "type" in schema and not isinstance(value, JSON_TYPES[schema["type"]]):
        return False
    if schema.get("type") != "object":
        return True
    props = schema.get("properties", {})
    if not set(schema.get("required", [])) <= set(value):
        return False
    return all(conforms(value[key], props[key], components) for key in value if key in props)


def status_schema() -> tuple[dict[str, Any], dict[str, Any]]:
    spec = openapi.build_document()
    ref = spec["paths"][STATUS]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    envelope_name = ref["$ref"].rsplit("/", 1)[1]
    envelope = spec["components"]["schemas"][envelope_name]
    data = next(item for item in envelope["properties"]["data"]["anyOf"] if "$ref" in item)
    name = data["$ref"].rsplit("/", 1)[1]
    assert name == "StatusResponse"
    return spec, spec["components"]["schemas"][name]


def test_spec_types_the_status_route() -> None:
    _, schema = status_schema()

    assert NEW_PROPERTIES <= set(schema["properties"])
    assert set(schema["properties"]) == OLD_KEYS
    assert set(schema["required"]) == OLD_KEYS
    for name, prop in schema["properties"].items():
        assert prop.get("description"), f"{name} has no description"
    for name in NULLABLE:
        prop = schema["properties"][name]
        assert {"type": "null"} in prop["anyOf"], f"{name} is not nullable"
    for name in ("audit_public_key", "audit_key_fingerprint"):
        assert "published only while heads are signed" in schema["properties"][name]["description"]


@pytest.fixture
async def body(tmp_path: Path) -> AsyncIterator[dict[str, Any]]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    notice = tmp_path / "notice"
    notice.write_text("degraded: maintenance\n")
    settings = Settings(
        driver="fake",
        database_url="sqlite+aiosqlite:///:memory:",
        api_key_pepper="test-pepper",
        build_sha="abc123",
        status_notice_file=str(notice),
    )
    app = create_app(settings)
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            response = await http.get(STATUS)
        assert response.status_code == 200
        yield response.json()
    finally:
        await app.state.engine.dispose()


async def test_live_answer_validates_and_keeps_its_keys(body: dict[str, Any]) -> None:
    spec, schema = status_schema()

    assert conforms(body["data"], schema, spec["components"]["schemas"])
    assert not conforms({**body["data"], "notice": 5}, schema, spec["components"]["schemas"])

    assert set(body["data"]) == OLD_KEYS
    assert body["data"]["status"] == "degraded"
    assert set(body["data"]["notice"]) == {"message", "updated_at"}
    assert set(schema["properties"]) == set(body["data"])
