"""Synchronous exec with timeout and output caps.

The caps are enforced here as well as in the driver: whatever the caller asked for,
a request never exceeds ``MAX_TIMEOUT_S`` or ``MAX_OUTPUT_BYTES`` per stream.
"""

import re
from collections.abc import Mapping
from dataclasses import replace

from sandfort.config import ENV_PREFIX, is_reserved_env_name
from sandfort.domain.sandbox import Sandbox, visible_stop_cause
from sandfort.drivers.base import ExecRequest, ExecResult, SandboxDriver
from sandfort.errors import Unprocessable, no_container_conflict

MAX_TIMEOUT_S = 3600.0
MAX_OUTPUT_BYTES = 1024 * 1024

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def validate_env(env: Mapping[str, str]) -> None:
    """Reject names that are malformed or reserved for the platform."""
    reserved = sorted(name for name in env if is_reserved_env_name(name))
    if reserved:
        raise Unprocessable(
            f"environment variable names starting with {ENV_PREFIX} are reserved",
            details={"names": reserved},
        )
    malformed = sorted(name for name in env if not _ENV_NAME.fullmatch(name))
    if malformed:
        raise Unprocessable("invalid environment variable names", details={"names": malformed})


async def execute(driver: SandboxDriver, sandbox: Sandbox, request: ExecRequest) -> ExecResult:
    if sandbox.driver_ref is None:
        raise no_container_conflict(sandbox.state.value, visible_stop_cause(sandbox))
    validate_env(request.env)
    bounded = replace(
        request,
        timeout_s=min(request.timeout_s, MAX_TIMEOUT_S),
        max_output_bytes=min(request.max_output_bytes, MAX_OUTPUT_BYTES),
    )
    return await driver.exec(sandbox.driver_ref, bounded)
