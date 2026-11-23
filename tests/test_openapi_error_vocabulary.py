"""The OpenAPI description publishes the error and stop-reason vocabulary (daemon-free)."""

from typing import Any

import pytest

from sandfort import errors
from sandfort.api.openapi import RETRY_ERROR_REF, build_app, build_document
from sandfort.api.schemas import toolbox_process

STOP_REASON_PREFIX = "STOP_REASON_"


def _string_constants(module: Any, *, prefix: str = "") -> dict[str, str]:
    """Module-level upper-case string constants, so a new one is picked up without an edit."""
    return {
        name: value
        for name, value in vars(module).items()
        if name.isupper() and name.startswith(prefix) and isinstance(value, str)
    }


CONFLICT_REASONS = _string_constants(errors)
STOP_REASONS = _string_constants(toolbox_process, prefix=STOP_REASON_PREFIX)


@pytest.fixture(scope="module")
def description() -> str:
    text = build_document(build_app())["info"]["description"]
    assert isinstance(text, str)
    return text


def test_the_constants_are_found() -> None:
    assert errors.NAME_TAKEN in CONFLICT_REASONS.values()
    assert errors.CONFLICT_REASON in CONFLICT_REASONS.values()
    assert toolbox_process.STOP_REASON_KILLED in STOP_REASONS.values()
    assert len(STOP_REASONS) == 7


@pytest.mark.parametrize("reason", sorted(CONFLICT_REASONS.values()))
def test_description_lists_every_conflict_reason(description: str, reason: str) -> None:
    assert f"`{reason}`" in description


@pytest.mark.parametrize("stop_reason", sorted(STOP_REASONS.values()))
def test_description_lists_every_stop_reason(description: str, stop_reason: str) -> None:
    assert f"`{stop_reason}`" in description


def test_description_names_the_conflict_and_state_details(description: str) -> None:
    assert "error.details.reason" in description
    assert errors.Conflict.code in description
    assert errors.InvalidState.code in description
    assert "error.details.state" in description


def test_description_explains_idempotency_errors(description: str) -> None:
    assert errors.IdempotencyMismatch.code in description
    assert "422" in description
    assert "Idempotency-Key" in description
    assert f"reason `{errors.IN_PROGRESS}`" in description


def test_description_names_the_request_id_header_and_field(description: str) -> None:
    assert "x-request-id" in description
    assert "error.request_id" in description


def test_sandbox_create_documents_the_503_answer() -> None:
    operation = build_document(build_app())["paths"]["/v1/sandboxes"]["post"]

    assert operation["responses"]["503"] == RETRY_ERROR_REF


def test_description_names_the_open_status_path(description: str) -> None:
    assert "`/v1/status`" in description


def test_the_rest_of_the_description_is_kept(description: str) -> None:
    assert "## Authentication" in description
    assert "## Errors" in description
    assert "see `Retry-After`" in description
