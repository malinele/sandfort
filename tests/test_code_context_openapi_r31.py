"""The code-context operations carry a summary and a description in the generated OpenAPI."""

from typing import Any

import pytest

from sandfort.api.openapi import build_document

PREFIX = "/v1/sandboxes/{sandbox_id}/toolbox/code-contexts"
HTTP_METHODS = ("get", "post", "put", "patch", "delete")
EXPECTED_OPERATIONS = {
    ("post", PREFIX),
    ("get", PREFIX),
    ("delete", f"{PREFIX}/{{context_id}}"),
    ("post", f"{PREFIX}/{{context_id}}/run"),
    ("post", f"{PREFIX}/{{context_id}}/run/stream"),
    ("post", f"{PREFIX}/{{context_id}}/interrupt"),
}


@pytest.fixture(scope="module")
def operations() -> dict[tuple[str, str], dict[str, Any]]:
    paths: dict[str, Any] = build_document()["paths"]
    return {
        (method, path): operation
        for path, item in paths.items()
        if path.startswith(PREFIX)
        for method, operation in item.items()
        if method in HTTP_METHODS
    }


def test_all_code_context_operations_are_in_the_document(
    operations: dict[tuple[str, str], dict[str, Any]],
) -> None:
    assert set(operations) == EXPECTED_OPERATIONS


@pytest.mark.parametrize("key", sorted(EXPECTED_OPERATIONS))
def test_operation_has_a_summary_and_a_description(
    operations: dict[tuple[str, str], dict[str, Any]], key: tuple[str, str]
) -> None:
    operation = operations[key]

    assert str(operation.get("summary", "")).strip()
    assert str(operation.get("description", "")).strip()


def test_run_description_names_queue_timeout_and_context_lost(
    operations: dict[tuple[str, str], dict[str, Any]],
) -> None:
    description = operations[("post", f"{PREFIX}/{{context_id}}/run")]["description"]

    assert "queue_timeout" in description
    assert "context_lost" in description


def test_run_description_says_which_outcome_gives_which_stop_reason(
    operations: dict[tuple[str, str], dict[str, Any]],
) -> None:
    description = operations[("post", f"{PREFIX}/{{context_id}}/run")]["description"]

    assert "the kernel answered, state kept) is a plain `timeout`" in description
    assert "that run ends with `stop_reason` `context_lost`, `exit_code` 124" in description


def test_interrupt_description_names_native_code(
    operations: dict[tuple[str, str], dict[str, Any]],
) -> None:
    description = operations[("post", f"{PREFIX}/{{context_id}}/interrupt")]["description"]

    assert "native code" in description


@pytest.mark.parametrize("action", ["run", "interrupt"])
def test_run_and_interrupt_tell_one_sequence(
    operations: dict[tuple[str, str], dict[str, Any]], action: str
) -> None:
    description = operations[("post", f"{PREFIX}/{{context_id}}/{action}")]["description"]

    assert "queue_timeout" in description
    assert "only after that 2 s grace" in description
    assert "removed" in description
