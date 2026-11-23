"""Round 68 (SF74-003): the OpenAPI spec describes the volume transfer contract.

Export answers a gzipped tar (``application/gzip``, binary), not JSON. Restore takes that same
archive as a required raw body (not JSON, so no 415) and documents its 413.
"""

import json
from typing import Any

import pytest

from sandfort.api.openapi import OPENAPI_PATH, build_document

EXPORT = "/v1/volumes/{volume_id}/export"
RESTORE = "/v1/volumes/{volume_id}/restore"
GZIP = "application/gzip"
BINARY = {"format": "binary", "type": "string"}


@pytest.fixture(scope="module")
def document() -> dict[str, Any]:
    return build_document()


def test_export_200_is_binary_gzip_and_not_json(document: dict[str, Any]) -> None:
    ok = document["paths"][EXPORT]["get"]["responses"]["200"]

    assert ok["content"] == {GZIP: {"schema": BINARY}}
    assert "Content-Disposition" in ok["headers"]
    assert "gzip" in ok["description"].lower()


def test_restore_has_a_required_binary_gzip_request_body(document: dict[str, Any]) -> None:
    body = document["paths"][RESTORE]["post"]["requestBody"]

    assert body["required"] is True
    assert body["content"] == {GZIP: {"schema": BINARY}}
    assert "256 MiB" in body["description"]


def test_restore_documents_413_with_its_causes(document: dict[str, Any]) -> None:
    responses = document["paths"][RESTORE]["post"]["responses"]
    too_large = responses["413"]

    assert "PAYLOAD_TOO_LARGE" in too_large["description"]
    assert "max_expansion_ratio" in too_large["description"]
    assert "application/json" in too_large["content"]


def test_restore_still_documents_the_conflict_and_validation_answers(
    document: dict[str, Any],
) -> None:
    responses = document["paths"][RESTORE]["post"]["responses"]

    assert {"200", "403", "404", "409", "413", "422"} <= set(responses)
    assert "415" not in responses  # the body is gzip, never JSON


def test_restore_success_stays_a_json_envelope(document: dict[str, Any]) -> None:
    ok = document["paths"][RESTORE]["post"]["responses"]["200"]

    assert set(ok["content"]) == {"application/json"}


def test_the_committed_spec_carries_the_same_declarations() -> None:
    committed = json.loads(OPENAPI_PATH.read_text(encoding="utf-8"))
    export = committed["paths"][EXPORT]["get"]["responses"]["200"]
    restore = committed["paths"][RESTORE]["post"]

    assert set(export["content"]) == {GZIP}
    assert set(restore["requestBody"]["content"]) == {GZIP}
    assert "413" in restore["responses"]
