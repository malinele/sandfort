"""Standalone stdio MCP server exposing Sandfort sandboxes as tools.

Run: SANDFORT_BASE_URL=http://127.0.0.1:8000 SANDFORT_API_KEY=sf_... \
    .venv/bin/python mcp_server/sandfort_mcp.py

stdout belongs to the MCP protocol; every diagnostic in this module goes to stderr.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "sdk" / "python" / "src"))

from mcp.server.mcpserver import MCPServer  # noqa: E402
from sandfort_sdk import Client, SandfortSDKError  # noqa: E402

URL_ENV = "SANDFORT_BASE_URL"
KEY_ENV = "SANDFORT_API_KEY"
MAX_DOWNLOAD_BYTES = 1024 * 1024
DEFAULT_TIMEOUT_S = 60
HIDDEN_STATES = frozenset({"destroyed", "deleting"})


class ConfigError(RuntimeError):
    """Required environment configuration is missing."""


def load_config(env: Mapping[str, str] | None = None) -> tuple[str, str]:
    """Return ``(server_url, api_key)`` from the environment or raise ``ConfigError``."""
    source = os.environ if env is None else env
    missing = [name for name in (URL_ENV, KEY_ENV) if not source.get(name)]
    if missing:
        raise ConfigError("missing required environment variable(s): " + ", ".join(missing))
    return source[URL_ENV], source[KEY_ENV]


class ClientHolder:
    """Builds the SDK client on first use; tests replace the module-level holder."""

    def __init__(self) -> None:
        self._client: Client | None = None

    def get(self) -> Any:
        if self._client is None:
            url, key = load_config()
            self._client = Client(url, key)
        return self._client


HOLDER: Any = ClientHolder()

mcp = MCPServer("sandfort")


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _error(exc: Exception) -> str:
    _log(f"tool error: {exc}")
    return f"error: {exc}"


def _exec_json(result: Any) -> str:
    return json.dumps(
        {
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": result.timed_out,
        }
    )


@mcp.tool()
def create_sandbox(name: str | None = None, snapshot: str | None = None) -> str:
    """Create a sandbox and wait until it is started. Returns JSON with its id and state."""
    try:
        sandbox = HOLDER.get().create_sandbox(name=name, snapshot=snapshot)
        return json.dumps({"id": sandbox.id, "state": sandbox.state})
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)


@mcp.tool()
def run_code(
    sandbox_id: str, language: str, code: str, timeout_seconds: int = DEFAULT_TIMEOUT_S
) -> str:
    """Run a code snippet in a sandbox. Returns JSON with exit_code, stdout and stderr."""
    try:
        sandbox = HOLDER.get().get(sandbox_id)
        result = sandbox.code_run(language, code, timeout_s=timeout_seconds)
        return _exec_json(result)
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)


@mcp.tool()
def run_command(
    sandbox_id: str,
    command: str,
    cwd: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_S,
) -> str:
    """Run a shell command in a sandbox. Returns JSON with exit_code, stdout and stderr."""
    try:
        sandbox = HOLDER.get().get(sandbox_id)
        result = sandbox.process_exec(command, cwd=cwd, timeout_s=timeout_seconds)
        return _exec_json(result)
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)


@mcp.tool()
def upload_text_file(sandbox_id: str, path: str, content: str) -> str:
    """Write text content (UTF-8) to a file path inside a sandbox, replacing any existing file."""
    try:
        sandbox = HOLDER.get().get(sandbox_id)
        data = content.encode("utf-8")
        sandbox.fs.upload_file(path, data)
        return f"uploaded {len(data)} bytes to {path}"
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)


@mcp.tool()
def download_text_file(sandbox_id: str, path: str) -> str:
    """Read a UTF-8 text file from a sandbox. Files over 1 MiB are refused."""
    try:
        sandbox = HOLDER.get().get(sandbox_id)
        data = sandbox.fs.read_bytes(path)
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)
    if len(data) > MAX_DOWNLOAD_BYTES:
        return f"error: {path} is {len(data)} bytes, over the 1 MiB limit; not returned"
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return f"error: {path} is not valid UTF-8 text"


@mcp.tool()
def list_sandboxes() -> str:
    """List sandboxes. Returns a JSON array of rows with id, name and state.

    Returns live sandboxes only: destroyed and deleting sandboxes are left out.
    """
    try:
        page = HOLDER.get().list_sandboxes()
        rows = [
            {"id": s.id, "name": s.info.name, "state": s.state}
            for s in page.items
            if s.state not in HIDDEN_STATES
        ]
        return json.dumps(rows)
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)


@mcp.tool()
def delete_sandbox(sandbox_id: str) -> str:
    """Delete a sandbox by id."""
    try:
        HOLDER.get().delete(sandbox_id)
        return f"deleted {sandbox_id}"
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)


@mcp.tool()
def create_snapshot(sandbox_id: str, name: str) -> str:
    """Create a named snapshot from a sandbox. Returns JSON with the snapshot id and state."""
    try:
        info = HOLDER.get().snapshots.create_from_sandbox(sandbox_id, name)
        return json.dumps({"id": info.id, "state": info.state})
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)


def main() -> None:
    try:
        load_config()
    except ConfigError as exc:
        _log(f"sandfort-mcp: {exc}")
        raise SystemExit(2) from exc
    mcp.run("stdio")


if __name__ == "__main__":
    main()
