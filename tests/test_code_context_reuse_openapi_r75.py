"""The code-context create operation documents the 200 reuse response (round 75, TS round)."""

from typing import Any

import pytest

from sandfort.api.openapi import build_document

PREFIX = "/v1/sandboxes/{sandbox_id}/toolbox/code-contexts"


@pytest.fixture(scope="module")
def create_responses() -> dict[str, Any]:
    operation: dict[str, Any] = build_document()["paths"][PREFIX]["post"]
    responses: dict[str, Any] = operation["responses"]
    return responses


def test_create_declares_the_200_reuse_response(create_responses: dict[str, Any]) -> None:
    assert "200" in create_responses


def test_the_200_reuse_response_describes_the_existing_named_context(
    create_responses: dict[str, Any],
) -> None:
    description = str(create_responses["200"].get("description", ""))

    assert "name" in description
    assert "existing" in description or "live" in description


def test_the_200_reuse_response_carries_the_create_payload_schema(
    create_responses: dict[str, Any],
) -> None:
    schema_of = {
        status: response.get("content", {}).get("application/json", {}).get("schema")
        for status, response in create_responses.items()
    }

    assert schema_of["200"] is not None
    assert schema_of["200"] == schema_of["201"]
