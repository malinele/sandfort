"""SDK r35: typed sandbox error codes and ``error_code`` on the sandbox handle."""

import asyncio
import sys
from pathlib import Path
from typing import assert_never, get_args

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import pytest  # noqa: E402
import sandfort_sdk  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    ERROR_CODE_CONTAINER_EXITED,
    ERROR_CODE_CONTAINER_MISSING,
    ERROR_CODE_EGRESS_UNAVAILABLE,
    ERROR_CODE_IMAGE_NOT_FOUND,
    ERROR_CODE_INTERNAL,
    ERROR_CODE_NODE_LOST,
    ERROR_CODE_RESET_FAILED,
    ERROR_CODE_START_FAILED,
    ERROR_CODE_TIMEOUT,
    AsyncSandbox,
    ErrorCode,
    Sandbox,
    SandboxInfo,
    is_known_error_code,
)
from sandfort_sdk._transport import AsyncTransport, SyncTransport  # noqa: E402
from sandfort_sdk.error_codes import (  # noqa: E402
    ERROR_CODE_IMAGE_ACCESS_DENIED,
    ERROR_CODE_INVALID_IMAGE_REFERENCE,
    ERROR_CODE_REGISTRY_TLS_ERROR,
    ERROR_CODE_REGISTRY_UNREACHABLE,
    KNOWN_ERROR_CODES,
)

from sandfort.domain import sandbox as server_domain  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"

CONSTANTS = (
    ERROR_CODE_IMAGE_NOT_FOUND,
    ERROR_CODE_REGISTRY_UNREACHABLE,
    ERROR_CODE_REGISTRY_TLS_ERROR,
    ERROR_CODE_IMAGE_ACCESS_DENIED,
    ERROR_CODE_INVALID_IMAGE_REFERENCE,
    ERROR_CODE_START_FAILED,
    ERROR_CODE_TIMEOUT,
    ERROR_CODE_RESET_FAILED,
    ERROR_CODE_CONTAINER_MISSING,
    ERROR_CODE_CONTAINER_EXITED,
    ERROR_CODE_NODE_LOST,
    ERROR_CODE_EGRESS_UNAVAILABLE,
    ERROR_CODE_INTERNAL,
)


def describe(code: ErrorCode) -> str:
    """An exhaustive branch over the Literal; mypy rejects it if a member is unhandled."""
    match code:
        case (
            "image_not_found"
            | "image_access_denied"
            | "invalid_image_reference"
            | "registry_tls_error"
        ):
            return "fix the image or the registry configuration"
        case "registry_unreachable" | "start_failed" | "timeout" | "reset_failed":
            return "retry"
        case "container_missing" | "container_exited" | "node_lost":
            return "start again"
        case "egress_unavailable":
            return "fix the node's egress proxy settings, then create again"
        case "internal":
            return "report"
        case _:
            assert_never(code)


def info(error_code: str | None) -> SandboxInfo:
    return SandboxInfo.from_payload(
        {
            "id": SID,
            "name": "demo",
            "state": "error" if error_code else "started",
            "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
            "network": {"block_all": False},
            "error_code": error_code,
        }
    )


def test_constants_equal_the_literal_args() -> None:
    assert CONSTANTS == get_args(ErrorCode)
    assert frozenset(CONSTANTS) == KNOWN_ERROR_CODES
    assert len(set(CONSTANTS)) == len(CONSTANTS)


def test_literal_matches_the_server_codes() -> None:
    assert get_args(ErrorCode) == server_domain.ERROR_CODES
    assert set(get_args(ErrorCode)) == set(KNOWN_ERROR_CODES)
    assert set(server_domain.IMAGE_PULL_ERROR_CODES) <= KNOWN_ERROR_CODES


@pytest.mark.parametrize("value", sorted(KNOWN_ERROR_CODES))
def test_type_guard_narrows_known_codes(value: str) -> None:
    raw: str | None = value
    assert is_known_error_code(raw)
    narrowed: ErrorCode = raw  # accepted by mypy only after the TypeGuard
    assert describe(narrowed)


@pytest.mark.parametrize("value", [None, "", "Timeout", "time_out", "future_code", " internal"])
def test_type_guard_rejects_unknown_values(value: str | None) -> None:
    assert not is_known_error_code(value)


def test_root_exports() -> None:
    names = {"ErrorCode", "is_known_error_code", *(f"ERROR_CODE_{c.upper()}" for c in CONSTANTS)}
    assert names <= set(sandfort_sdk.__all__)
    for code in CONSTANTS:
        assert getattr(sandfort_sdk, f"ERROR_CODE_{code.upper()}") == code


@pytest.mark.parametrize("error_code", [None, ERROR_CODE_IMAGE_NOT_FOUND, "future_code"])
def test_sync_handle_mirrors_info_error_code(error_code: str | None) -> None:
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    try:
        handle = Sandbox(info(error_code), transport)
        assert handle.error_code == handle.info.error_code == error_code
        with pytest.raises(AttributeError):
            handle.error_code = "internal"  # type: ignore[misc]
    finally:
        transport.close()


def test_async_handle_mirrors_info_error_code() -> None:
    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    try:
        handle = AsyncSandbox(info(ERROR_CODE_CONTAINER_EXITED), transport)
        assert handle.error_code == ERROR_CODE_CONTAINER_EXITED
    finally:
        asyncio.run(transport.aclose())


_EXHAUSTIVE = '''
from typing import assert_never
from sandfort_sdk import ErrorCode, is_known_error_code

def handle(code: ErrorCode) -> int:
    match code:
        case "image_not_found" | "registry_unreachable" | "registry_tls_error":
            return 1
        case "image_access_denied" | "invalid_image_reference" | "start_failed":
            return 1
        case "timeout" | "reset_failed":
            return 1
        case "container_missing" | "container_exited" | "node_lost" | "internal":
            return 2
        case "egress_unavailable":
            return 3
        case _:
            assert_never(code)

def narrow(raw: str | None) -> int:
    return handle(raw) if is_known_error_code(raw) else 0
'''

_MISSING_CASE = '''
from typing import assert_never
from sandfort_sdk import ErrorCode

def handle(code: ErrorCode) -> int:
    match code:
        case "image_not_found" | "registry_unreachable" | "registry_tls_error":
            return 1
        case "image_access_denied" | "invalid_image_reference" | "start_failed":
            return 1
        case "timeout" | "reset_failed":
            return 1
        case "container_missing" | "container_exited" | "node_lost":
            return 2
        case _:
            assert_never(code)
'''


def test_mypy_exhaustiveness_over_the_literal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = pytest.importorskip("mypy.api")
    (tmp_path / "exhaustive.py").write_text(_EXHAUSTIVE)
    (tmp_path / "missing.py").write_text(_MISSING_CASE)
    monkeypatch.setenv("MYPYPATH", str(SDK_SRC))
    stdout, _, status = api.run(
        [
            "--strict",
            "--no-incremental",
            "--cache-dir",
            str(tmp_path / ".mypy_cache"),
            str(tmp_path / "exhaustive.py"),
            str(tmp_path / "missing.py"),
        ]
    )
    errors = [line for line in stdout.splitlines() if ": error:" in line]
    assert status == 1, stdout
    assert errors, stdout
    assert all("missing.py" in line for line in errors), stdout
    assert any("assert_never" in line and "internal" in line for line in errors), stdout
