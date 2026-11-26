"""Standalone stdio MCP server exposing Sandfort sandboxes as tools.

Run: SANDFORT_BASE_URL=http://127.0.0.1:8000 SANDFORT_API_KEY=sf_... \
    .venv/bin/python mcp_server/sandfort_mcp.py

stdout belongs to the MCP protocol; every diagnostic in this module goes to stderr.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "sdk" / "python" / "src"))

from mcp.server.mcpserver import MCPServer  # noqa: E402
from pydantic import Strict  # noqa: E402
from sandfort_sdk import Client, SandfortSDKError  # noqa: E402

# A JSON true must stay a type error, not become the integer 1 (a one minute delete timer).
StrictInt = Annotated[int, Strict()]

URL_ENV = "SANDFORT_BASE_URL"
KEY_ENV = "SANDFORT_API_KEY"
MAX_DOWNLOAD_BYTES = 1024 * 1024
MAX_BINARY_BYTES = MAX_DOWNLOAD_BYTES
MAX_BASE64_CHARS = 4 * ((MAX_BINARY_BYTES + 2) // 3)
MAX_LIST_ENTRIES = 1000
DEFAULT_TIMEOUT_S = 60
START_WAIT_TIMEOUT_S = 60
MAX_START_WAIT_S = 600
HIDDEN_STATES = frozenset({"destroyed", "deleting"})
UPLOAD_TOO_LARGE = "error: content is over the 1 MiB limit; not uploaded"


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


def _entry_json(entry: Any) -> dict[str, Any]:
    modified = entry.modified_at
    return {
        "name": entry.name,
        "path": entry.path,
        "kind": entry.kind,
        "size_bytes": entry.size_bytes,
        "mode": entry.mode,
        "modified_at": modified.isoformat() if modified is not None else None,
    }


def _state_json(sandbox: Any) -> str:
    return json.dumps({"id": sandbox.id, "state": sandbox.state})


@mcp.tool()
def create_sandbox(
    name: str | None = None,
    snapshot: str | None = None,
    auto_stop_minutes: StrictInt | None = None,
    auto_delete_minutes: StrictInt | None = None,
    labels: dict[str, str] | None = None,
    block_network: bool | None = None,
    egress_allowlist: list[str] | None = None,
    isolation: str | None = None,
) -> str:
    """Create a sandbox and wait until it is started. Returns JSON with its id and state.

    Without snapshot the default image is python:3.12-slim (Python and pip, no git). An
    option left as None is not sent and the server decides.
    auto_stop_minutes: idle minutes before the sandbox is stopped (default 15).
    auto_delete_minutes: minutes after a stop before the sandbox is deleted (default -1).
    Both timers take -1 to 525600 and -1 turns a timer off. auto_stop_minutes 0 also
    turns it off. auto_delete_minutes 0 deletes the sandbox at the next scan after any
    stop, stop_sandbox included.
    labels: string keys and values, at most 32. Keys starting with sandfort. are reserved.
    block_network: true blocks all network access.
    egress_allowlist: lowercase host names, leading-dot domains or CIDR ranges the
    sandbox may reach through the egress proxy. An empty list allows no host. A
    non-empty list cannot be combined with block_network true.
    isolation: container, gvisor or microvm. The server refuses a tier it does not offer.
    None uses the tier recorded on the snapshot, else the server default.
    """
    options: dict[str, Any] = {
        "auto_stop_minutes": auto_stop_minutes,
        "auto_delete_minutes": auto_delete_minutes,
        "labels": labels,
        "block_network": block_network,
        "egress_allowlist": egress_allowlist,
        "isolation": isolation,
    }
    extra = {key: value for key, value in options.items() if value is not None}
    try:
        sandbox = HOLDER.get().create_sandbox(name=name, snapshot=snapshot, **extra)
        return _state_json(sandbox)
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)


@mcp.tool()
def start_sandbox(
    sandbox_id: str, wait_timeout_seconds: StrictInt = START_WAIT_TIMEOUT_S
) -> str:
    """Start a stopped sandbox and wait until it is started. Returns JSON with id and state.

    wait_timeout_seconds bounds the whole call, from 1 to 600 seconds. When the wait runs
    out an error is returned and the start may still finish later.
    """
    if wait_timeout_seconds <= 0:
        return "error: wait_timeout_seconds must be greater than 0"
    if wait_timeout_seconds > MAX_START_WAIT_S:
        return f"error: wait_timeout_seconds must be at most {MAX_START_WAIT_S}"
    try:
        client = HOLDER.get()
        sandbox = client.start(sandbox_id, wait=True, wait_timeout_s=wait_timeout_seconds)
        return _state_json(sandbox)
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)


@mcp.tool()
def stop_sandbox(sandbox_id: str) -> str:
    """Stop a sandbox. Returns JSON with its id and state.

    The call does not wait for the stop to finish, so the state may still be stopping.
    list_sandboxes shows when it is stopped.
    """
    try:
        return _state_json(HOLDER.get().stop(sandbox_id))
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
    """Write text content (UTF-8) to a file path inside a sandbox, replacing any existing file.

    Content over 1 MiB of UTF-8 bytes (not characters) is refused before any request.
    """
    data = content.encode("utf-8")
    if len(data) > MAX_BINARY_BYTES:
        return UPLOAD_TOO_LARGE
    try:
        sandbox = HOLDER.get().get(sandbox_id)
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
def list_directory(sandbox_id: str, path: str = "/") -> str:
    """List a directory in a sandbox. Returns JSON with path, entries and truncated.

    Each entry has name, path, kind, size_bytes, mode and modified_at. At most 1000
    entries are returned; when truncated is true the rest is left out.
    """
    try:
        sandbox = HOLDER.get().get(sandbox_id)
        listing = sandbox.fs.list_dir(path)
        entries = [_entry_json(e) for e in listing.entries[:MAX_LIST_ENTRIES]]
        truncated = len(listing.entries) > MAX_LIST_ENTRIES
        return json.dumps({"path": listing.path, "entries": entries, "truncated": truncated})
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)


@mcp.tool()
def stat_path(sandbox_id: str, path: str) -> str:
    """Describe one file, directory or symlink in a sandbox. Returns a JSON entry."""
    try:
        sandbox = HOLDER.get().get(sandbox_id)
        return json.dumps(_entry_json(sandbox.fs.stat(path)))
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)


@mcp.tool()
def make_directory(sandbox_id: str, path: str, parents: bool = True) -> str:
    """Create a directory in a sandbox, with missing parents by default.

    Returns JSON with path and created.
    """
    try:
        sandbox = HOLDER.get().get(sandbox_id)
        result = sandbox.fs.mkdir(path, parents=parents)
        return json.dumps({"path": result.path, "created": result.created})
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)


@mcp.tool()
def delete_path(sandbox_id: str, path: str, recursive: bool = False) -> str:
    """Delete a file or directory in a sandbox. Returns JSON with path and deleted.

    recursive=True removes a whole directory tree; use it with care.
    """
    try:
        sandbox = HOLDER.get().get(sandbox_id)
        result = sandbox.fs.delete(path, recursive=recursive)
        return json.dumps({"path": result.path, "deleted": result.deleted})
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)


@mcp.tool()
def upload_binary_file(
    sandbox_id: str, path: str, content_base64: str, overwrite: bool = True
) -> str:
    """Write base64-encoded bytes to a file path inside a sandbox.

    Content over 1 MiB (decoded) is refused. An existing file is replaced unless
    overwrite is false.
    """
    if len(content_base64) > MAX_BASE64_CHARS:
        return UPLOAD_TOO_LARGE
    try:
        data = base64.b64decode(content_base64, validate=True)
    except binascii.Error:
        return "error: content_base64 is not valid base64"
    if len(data) > MAX_BINARY_BYTES:
        return UPLOAD_TOO_LARGE
    try:
        sandbox = HOLDER.get().get(sandbox_id)
        sandbox.fs.upload_file(path, data, overwrite=overwrite)
        return f"uploaded {len(data)} bytes to {path}"
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)


@mcp.tool()
def download_binary_file(sandbox_id: str, path: str) -> str:
    """Read a file from a sandbox as base64. Files over 1 MiB are refused.

    Returns JSON with path, size_bytes and content_base64; base64 inflates the
    output by about a third.
    """
    try:
        sandbox = HOLDER.get().get(sandbox_id)
        data = sandbox.fs.read_bytes(path)
    except (SandfortSDKError, ConfigError) as exc:
        return _error(exc)
    if len(data) > MAX_DOWNLOAD_BYTES:
        return f"error: {path} is {len(data)} bytes, over the 1 MiB limit; not returned"
    encoded = base64.b64encode(data).decode("ascii")
    return json.dumps({"path": path, "size_bytes": len(data), "content_base64": encoded})


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
