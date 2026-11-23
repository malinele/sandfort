"""Deterministic OpenAPI export (WP 4.6) and the post-processing the live route serves too.

Run ``python -m sandfort.api.openapi [OUTPUT]`` to regenerate the committed spec; the drift
test compares that file byte for byte with ``render_spec(build_document())``. Bump
``EXPORT_VERSION`` when the export format changes: the marker travels in ``info`` so a spec
written by an older export is recognised as stale instead of reported as drift.

``build_document`` starts from ``fastapi.openapi.utils.get_openapi`` (never ``app.openapi``,
which ``create_app`` points back at this module) and then adds the bearer scheme, declares the
error envelope for 400/401/403/404/409/422/429/500 on every operation (no 401/403 where no key
is taken) in place of FastAPI's ``HTTPValidationError`` (the server never sends it), declares
415 where a JSON body can be refused, adds the ``servers`` list and the operation descriptions
that the routes do not carry (``openapi_descriptions``), and gives
the raw-body upload, the binary download and the server-sent-event streams their media types.
"""

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from pydantic import TypeAdapter

from sandfort import errors
from sandfort.api import openapi_fs, openapi_volumes
from sandfort.api.app import METRICS_PATH, create_app
from sandfort.api.envelope import Envelope
from sandfort.api.openapi_descriptions import describe
from sandfort.api.schemas.toolbox_fs import MAX_INLINE_READ_BYTES, FsDownloadResponse
from sandfort.api.schemas.toolbox_process import (
    STOP_REASON_KILLED,
    STOP_REASON_OOM_KILLED,
    STOP_REASON_OUTPUT_LIMIT,
    STOP_REASON_SANDBOX_DELETED,
    STOP_REASON_SANDBOX_RESET,
    STOP_REASON_SANDBOX_STOPPED,
    STOP_REASON_TIMEOUT,
)
from sandfort.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[3]
OPENAPI_PATH = REPO_ROOT / "openapi" / "sandfort.v1.json"
EXPORT_VERSION = 3
EXPORT_VERSION_KEY = "x-export-version"
_EXPORT_PEPPER = "openapi-export"  # the app refuses to build without a pepper; never used


def build_app() -> FastAPI:
    """The real application on the fake driver and an in-memory database (nothing connects)."""
    settings = Settings(
        driver="fake",
        database_url="sqlite+aiosqlite:///:memory:",
        api_key_pepper=_EXPORT_PEPPER,
    )
    return create_app(settings)


API_KEY_SCHEME = "ApiKeyBearer"
ERROR_RESPONSE = "Error"
ERROR_REF = {"$ref": "#/components/responses/" + ERROR_RESPONSE}
RETRY_ERROR_RESPONSE = "ErrorRetryAfter"  # the 429 and 503 answers, which carry Retry-After
RETRY_ERROR_REF = {"$ref": "#/components/responses/" + RETRY_ERROR_RESPONSE}
RETRY_STATUSES = frozenset({"429", "503"})
HEADER_REF_PREFIX = "#/components/headers/"
REQUEST_ID_HEADER = "x-request-id"
RETRY_AFTER_HEADER = "Retry-After"
REPLAYED_HEADER = "Idempotent-Replayed"
IDEMPOTENCY_HEADER = "Idempotency-Key"
SCHEMA_REF_PREFIX = "#/components/schemas/"
UNAUTHENTICATED_PATHS = frozenset(
    {"/healthz", "/readyz", "/v1/status", METRICS_PATH, "/v1/auth/sso/exchange"}
)
VALIDATION_STATUS = "422"  # FastAPI declares it wherever a request has inputs
# 503 is on every operation: any node-routed call can answer it (no capacity, node unavailable).
ERROR_STATUSES = ("400", "401", "403", "404", "409", "429", "500", "503")
AUTH_STATUSES = frozenset({"401", "403"})
BODY_TOO_LARGE_STATUS = "413"
UNSUPPORTED_MEDIA_STATUS = "415"
UNSUPPORTED_MEDIA_RESPONSE = "UnsupportedMediaType"
UNSUPPORTED_MEDIA_REF = {"$ref": "#/components/responses/" + UNSUPPORTED_MEDIA_RESPONSE}
VALIDATION_RESPONSE = "ValidationFailed"
VALIDATION_REF = {"$ref": "#/components/responses/" + VALIDATION_RESPONSE}
SERVERS: list[dict[str, str]] = [
    {"url": "https://api.sandfort.dev", "description": "hosted beta"},
    {"url": "http://localhost:8000", "description": "local dev"},
]
# FastAPI's request-validation schemas, unused once the 422s point at the error envelope; the
# first references the second, so they are checked in this order.
GENERATED_VALIDATION_SCHEMAS = ("HTTPValidationError", "ValidationError")
HTTP_METHODS = frozenset({"get", "put", "post", "delete", "patch", "options", "head", "trace"})

# (path, method) of the operations whose bodies are not JSON, as the route modules declare them.
_SANDBOX = "/v1/sandboxes/{sandbox_id}"
_SESSION_COMMAND = _SANDBOX + "/toolbox/process/sessions/{session_id}/commands/{command_id}"
UPLOAD_OPERATION = (_SANDBOX + "/toolbox/fs/upload", "put")  # routes/toolbox/fs.py upload_file
DOWNLOAD_OPERATION = (_SANDBOX + "/toolbox/fs/download", "get")  # fs.py download_path
DOWNLOAD_HEAD_OPERATION = (DOWNLOAD_OPERATION[0], "head")  # fs.py head_download
EXPORT_OPERATION = ("/v1/snapshots/{snapshot_id}/export", "get")  # routes/snapshots.py
# Operations whose request body is raw bytes, so a JSON content type is never the problem (no 415).
RAW_BODY_OPERATIONS = (UPLOAD_OPERATION, openapi_volumes.RESTORE_OPERATION)
SANDBOX_LOGS_OPERATION = (_SANDBOX + "/logs", "get")  # routes/sandbox_logs.py
COMMAND_LOGS_FOLLOW_OPERATION = (_SESSION_COMMAND + "/logs/follow", "get")  # toolbox/sessions.py
BUILD_LOGS_OPERATION = ("/v1/images/builds/{snapshot_id}/logs", "get")  # routes/image_builds.py
CONTEXT_RUN_STREAM_OPERATION = (  # routes/toolbox/code_contexts.py stream_code_context_run
    _SANDBOX + "/toolbox/code-contexts/{context_id}/run/stream",
    "post",
)

EXEC_OPERATION = (_SANDBOX + "/toolbox/process/execute", "post")  # toolbox/process.py
# (path, method, name) of the operations that take the Idempotency-Key header; the drift test
# compares this list with the operations that really declare the parameter.
IDEMPOTENT_OPERATIONS: tuple[tuple[str, str, str], ...] = (
    ("/v1/sandboxes", "post", "create sandbox"),
    (EXEC_OPERATION[0], EXEC_OPERATION[1], "synchronous exec"),
    (_SANDBOX + "/toolbox/process/code-run", "post", "code run"),
    (_SANDBOX + "/toolbox/process/sessions", "post", "create session"),
    ("/v1/snapshots", "post", "register snapshot"),
    ("/v1/snapshots/from-sandbox", "post", "snapshot from sandbox"),
    ("/v1/volumes", "post", "create volume"),
)
# Operations that answer 413 without a request body: the fs probes refuse a listing that is too
# large, and an inline read refuses a file above the inline cap.
FS_LIST_OPERATION = (_SANDBOX + "/toolbox/fs/list", "get")
FS_STAT_OPERATION = (_SANDBOX + "/toolbox/fs/stat", "get")
TOO_LARGE_WITHOUT_BODY = (FS_LIST_OPERATION, FS_STAT_OPERATION, DOWNLOAD_OPERATION)
INLINE_ENVELOPE = "Envelope_FsDownloadResponse_"
_INLINE_DESCRIPTION = (
    "With `inline=true` the answer is the JSON envelope `{success, data: {path, size_bytes, "
    "content, truncated}}` instead: the file's text (UTF-8, invalid bytes replaced), cut at "
    "`max_bytes` with `truncated` true. A directory answers 422; a file above the inline limit "
    "answers 413."
)
_MAX_BYTES_DESCRIPTION = (
    "Inline reads only (`inline=true`; ignored otherwise): the most bytes of the file to "
    "return, 1 to " + str(MAX_INLINE_READ_BYTES) + ". Default: the maximum. A larger value "
    "answers 422."
)
_INLINE_PARAMETER_DESCRIPTION = (
    "Answer a JSON envelope with the file's text instead of streaming the bytes."
)

_BINARY_SCHEMA: dict[str, Any] = {"type": "string", "format": "binary"}
_KEEPALIVE = (
    " While idle the server sends a `: keepalive` comment line about every 15 seconds; "
    "each `data:` line is one JSON object."
)
SSE_DESCRIPTIONS: dict[tuple[str, str], str] = {
    SANDBOX_LOGS_OPERATION: (
        "Server-sent events (no envelope). One `stdout` or `stderr` event per container log "
        'line, `data: {"timestamp": <unix seconds>, "stream": "stdout"|"stderr", "line": '
        "<text>}`. The event `id` is the line's timestamp in unix seconds (six decimals): pass "
        "it as `?since=<id>` to resume. Without `follow` the stream ends after the tail; a "
        'driver failure mid-stream sends one `error` event, `data: {"message": <text>}`, '
        "and ends the stream." + _KEEPALIVE
    ),
    COMMAND_LOGS_FOLLOW_OPERATION: (
        "Server-sent events (no envelope). One `stdout` or `stderr` event per output line, "
        '`data: {"stream": "stdout"|"stderr", "offset": <line start byte>, "line": <text>}`; '
        "`line` keeps its terminator (`\\n` or `\\r\\n`), and an unterminated tail is held until "
        "its line completes, the other stream writes or the command ends. The event `id` is "
        "the byte offset where the next line starts: reconnect with `Last-Event-ID: <id>` (or "
        "`?offset=<id>`) to resume exactly after the last delivered line. A final "
        '`exit` event, `data: {"exit_code": <int|null>, "state": <command state>, '
        '"truncated": <bool>}`, whose `id` is the final offset, ends the stream.' + _KEEPALIVE
    ),
    BUILD_LOGS_OPERATION: (
        "Server-sent events (no envelope). One `log` event per build log line, "
        '`data: {"line": <text>}`, replayed from the first line for a late subscriber; the '
        "event `id` is the zero-based line index. A final `state` event without an `id`, "
        '`data: {"state": <snapshot state>, "snapshot_id": <id>, "digest": <string|null>, '
        '"reason": <string|null>}`, carries the terminal state and ends the stream.' + _KEEPALIVE
    ),
    CONTEXT_RUN_STREAM_OPERATION: (
        "Server-sent events (no envelope). One `stdout` or `stderr` event per output chunk of "
        'the cell, `data: {"data": <text>}`; `stdout` is sent by whole lines, so the last line '
        "arrives with its newline or at the end, and the outcome line of the client is never "
        "sent. One final `result` event, whose data is the object the run operation answers in "
        "`data`, ends the stream. A failure after the stream started sends one `error` event, "
        '`data: {"code": <error code>, "message": <text>}`, instead of `result`. The events '
        "carry no `id`, so a dropped stream cannot be resumed: a new request is a new run."
        + _KEEPALIVE
    ),
}
_DOWNLOAD_DESCRIPTION = (
    "The file as raw bytes (`application/octet-stream`), or a directory as a tar archive "
    "(`application/x-tar`), with a `Content-Disposition: attachment` file name. A file also "
    "answers `Accept-Ranges: bytes` (a directory tar answers `none`). " + _INLINE_DESCRIPTION
)
_EXPORT_DESCRIPTION = (
    "The snapshot image as a tar archive (`application/x-tar`), the format `docker save` "
    "produces, streamed with a `Content-Disposition: attachment` file name taken from the "
    "snapshot name. Load it on any Docker host with `docker load`. Only a `ready` snapshot "
    "can be exported (409 `INVALID_STATE`); a driver without image export answers 409 "
    "`CONFLICT` with reason `unsupported_mode`."
)
UPLOAD_REQUEST_BODY: dict[str, Any] = {
    "required": True,
    "description": (
        "The file content as raw bytes, streamed. The target path is the `path` query "
        "parameter; send `Content-Length`, or `size_bytes` when the length is not known."
    ),
    "content": {"application/octet-stream": {"schema": _BINARY_SCHEMA}},
}

_API_KEY_SECURITY_SCHEME: dict[str, Any] = {
    "type": "http",
    "scheme": "bearer",
    "description": (
        "API key sent as `Authorization: Bearer <key>`. Keys are created through the "
        "`/v1/api-keys` endpoints, start with `sf_` and are shown once, at creation."
    ),
}


def _header_refs(*names: str) -> dict[str, Any]:
    """``headers`` entries that point at the shared ``components.headers`` definitions."""
    return {name: {"$ref": HEADER_REF_PREFIX + name} for name in names}


# Mirrors ``Envelope`` and ``ErrorBody`` (api/envelope.py, api/schemas/common.py) for a failure.
_ERROR_RESPONSE: dict[str, Any] = {
    "description": (
        "Standard error envelope: `success` is false, `data` is null and `error` carries "
        "the failure."
    ),
    "headers": _header_refs(REQUEST_ID_HEADER),
    "content": {
        "application/json": {
            "schema": {
                "type": "object",
                "required": ["success", "error"],
                "properties": {
                    "success": {"type": "boolean", "const": False},
                    "data": {"type": "null"},
                    "error": {
                        "type": "object",
                        "required": ["code", "message"],
                        "properties": {
                            "code": {"type": "string", "description": "Machine-readable code."},
                            "message": {"type": "string", "description": "Human-readable text."},
                            "details": {
                                "type": "object",
                                "additionalProperties": True,
                                "description": "Extra context; empty when there is none.",
                            },
                            "request_id": {
                                "anyOf": [{"type": "string"}, {"type": "null"}],
                                "description": "Request id, also sent in the response header.",
                            },
                        },
                    },
                },
            }
        }
    },
}

_RETRY_ERROR_RESPONSE: dict[str, Any] = {
    **_ERROR_RESPONSE,
    "description": _ERROR_RESPONSE["description"]
    + " Sent with 429 and 503, which also carry `Retry-After`.",
    "headers": {**_header_refs(REQUEST_ID_HEADER, RETRY_AFTER_HEADER)},
}

_UNSUPPORTED_MEDIA_RESPONSE: dict[str, Any] = {
    **_ERROR_RESPONSE,
    "description": (
        "The request body is not JSON: its `Content-Type` is neither `application/json` nor "
        "`application/*+json`. Error code `UNSUPPORTED_MEDIA_TYPE`, with "
        '`error.details.supported` listing `["application/json"]`. Declared on every '
        "operation that takes a JSON body; the file upload takes raw bytes and never answers "
        "it."
    ),
}

_VALIDATION_RESPONSE: dict[str, Any] = {
    **_ERROR_RESPONSE,
    "description": (
        "The request was refused with 422. Two error codes are used, and a client should "
        "treat both as a refused request. `VALIDATION_ERROR`: the request did not pass "
        "validation (a wrong type or range, a missing or unknown field, an unknown or "
        "repeated query parameter, a body that is not valid JSON or holds text the API "
        "refuses, an out-of-range header, a write under /proc, /sys or /dev); "
        "`error.details.errors` lists each problem as `{loc, msg, type}`. `UNPROCESSABLE`: "
        "the request is well formed but the service refuses its content (an image reference "
        "the policy forbids, a git argument that starts with `-`, a move of a path onto "
        "itself, a relative session `cwd`, an inverted time range); read `error.message`, "
        "`details.errors` is absent. A third code, `IDEMPOTENCY_MISMATCH`, answers a reused "
        "`Idempotency-Key` with a different body."
    ),
}

# Response headers the server sends, declared once in ``components.headers`` and referenced.
_COMPONENT_HEADERS: dict[str, Any] = {
    REQUEST_ID_HEADER: {
        "description": (
            "Request id: the well-formed client-supplied `X-Request-Id` (1 to 64 characters of "
            "`A-Za-z0-9._-`), else a generated one. Sent on every response."
        ),
        "schema": {"type": "string"},
    },
    RETRY_AFTER_HEADER: {
        "description": "Whole seconds to wait before retrying. Sent with 429 and 503.",
        "schema": {"type": "integer", "minimum": 0},
    },
    REPLAYED_HEADER: {
        "description": (
            "`true` when the answer is the stored answer of an earlier request with the same "
            "`Idempotency-Key`; absent on the first answer."
        ),
        "schema": {"type": "string", "enum": ["true"]},
    },
    "ETag": {
        "description": (
            "Weak validator of a file download; sent only when the file has a known size and "
            "modification time."
        ),
        "schema": {"type": "string"},
    },
    "Content-Length": {
        "description": "Size of the file in bytes; sent only for a non-empty file of known size.",
        "schema": {"type": "integer", "minimum": 1},
    },
    "Content-Disposition": {
        "description": "`attachment` with the file name (`filename*=UTF-8''<name>`).",
        "schema": {"type": "string"},
    },
    **openapi_fs.COMPONENT_HEADERS,
}

# The reason and stop-reason values come from the constants the server uses, so the text cannot
# drift from the code; tests/test_openapi_error_vocabulary.py checks that none is missing.
_CONFLICT_REASONS: tuple[tuple[str, str], ...] = (
    (
        errors.NAME_TAKEN,
        "a sandbox, volume or snapshot with that name already exists in the org",
    ),
    (errors.ALREADY_EXISTS, "the object (member, external id, file, row id) already exists"),
    (errors.CONCURRENT_UPDATE, "another writer changed the row first; retry"),
    (errors.NO_CONTAINER, "the sandbox has no running container for the call"),
    (errors.IN_PROGRESS, "the same work (idempotency key, snapshot) has not finished yet"),
    (errors.IN_USE, "the object is still used by a sandbox"),
    (errors.CLOSED, "the PTY or session is closed or does not accept the call"),
    (errors.OPERATION_FAILED, "a git or fs command in the sandbox failed"),
    (errors.CHANGED_DURING_RESET, "the sandbox changed state while a reset replaced it"),
    (errors.UNSUPPORTED_MODE, "the operation is not supported in the configured run mode"),
    (errors.DISK_FULL, "the runtime reported that the sandbox disk is full"),
    (errors.RUNTIME_CONFLICT, "the runtime refused the operation for another reason"),
    (
        errors.RESULT_UNAVAILABLE,
        "a keyed exec already ran, but its answer was not kept for replay (error code "
        "`IDEMPOTENCY_RESULT_UNAVAILABLE`); the command does not run again",
    ),
    (errors.CONFLICT_REASON, "fallback when none of the above applies"),
)
_STOP_REASONS: tuple[tuple[str, str], ...] = (
    (STOP_REASON_TIMEOUT, "the command reached `timeout_s`"),
    (STOP_REASON_OUTPUT_LIMIT, "the output limit was reached and the output is truncated"),
    (
        STOP_REASON_SANDBOX_STOPPED,
        "the sandbox stopped under the command: it was stopped (by a caller or by auto-stop), "
        "or it died (a resource limit was hit or its main process ended); stderr says which",
    ),
    (STOP_REASON_SANDBOX_DELETED, "the sandbox was deleted while the command ran"),
    (STOP_REASON_SANDBOX_RESET, "the sandbox was reset while the command ran"),
    (
        STOP_REASON_OOM_KILLED,
        "the sandbox ran out of memory and the server could see it: the container died of it "
        "(`sandbox_stopped` is true) or the kernel killed the process (the sandbox keeps "
        "running); the container isolation tier only, the gVisor and microVM tiers still "
        "answer `killed` or `sandbox_stopped`",
    ),
    (STOP_REASON_KILLED, "the process got SIGKILL (exit code 137) without any other reason"),
)


def _bullets(pairs: Sequence[tuple[str, str]]) -> str:
    return "".join(f"\n- `{value}`: {meaning}" for value, meaning in pairs)


def _idempotent_list() -> str:
    return ", ".join(
        f"{name} (`{method.upper()} {path}`)" for path, method, name in IDEMPOTENT_OPERATIONS
    )


_ERROR_VOCABULARY = (
    "\n\nEvery 409 `" + errors.Conflict.code + "` carries `error.details.reason`, a stable "
    "string to switch on instead of parsing the message. The values:"
    + _bullets(_CONFLICT_REASONS)
    + "\n\nA 409 `"
    + errors.InvalidState.code
    + "` (an operation the current state does not allow) carries `error.details.state`.\n\n"
    "The `Idempotency-Key` header (1 to 255 characters; an empty or longer key answers 422 `"
    + errors.ValidationFailed.code
    + "`) is accepted by exactly these operations: "
    + _idempotent_list()
    + ". Every other POST ignores the header. Reusing a key with a different request body "
    "answers 422 `" + errors.IdempotencyMismatch.code + "`; a request whose key is still in "
    "progress answers 409 with reason `" + errors.IN_PROGRESS + "`. A replay of a stored answer "
    "carries the `" + REPLAYED_HEADER + ": true` response header.\n\n"
    "A query parameter an operation does not declare is refused with 422 `"
    + errors.ValidationFailed.code
    + "`, one `details.errors` entry of type `extra_forbidden` per unknown name (`loc` is "
    '`["query", <name>]`). A method a path does not support answers 405 `METHOD_NOT_ALLOWED` '
    "with an `Allow` header.\n\n"
    "Every response carries the `x-request-id` header (a well-formed client-supplied value is "
    "kept), and error bodies repeat it as `error.request_id`; quote it when reporting a failure."
    "\n\nThe exec and code-run results (`/toolbox/process/execute` and `/toolbox/process/"
    "code-run`) carry `stop_reason`, null for a normal exit. The values:" + _bullets(_STOP_REASONS)
)

_DESCRIPTION_SUFFIX = (
    "\n\n## Authentication\n\n"
    "Operations require `Authorization: Bearer <api key>`; see the `" + API_KEY_SCHEME + "` "
    "security scheme. `/healthz`, `/readyz`, `/v1/status` and `/v1/auth/sso/exchange` take no "
    "API key.\n\n"
    "## Errors\n\n"
    "Failures use the envelope described by `#/components/responses/" + ERROR_RESPONSE + "`: "
    '`{"success": false, "data": null, "error": {"code", "message", "details", '
    '"request_id"}}`. Common status codes: 400 (invalid input), 401 (missing or invalid key), '
    "403 (key lacks the scope), 404 (not found), 409 (conflict with the current state), 413 "
    "(request body too large), 415 (a body that is not JSON), 416 (a download `Range` "
    "outside the file), 422 (request validation failed: `VALIDATION_ERROR` for a request "
    "that fails validation, `UNPROCESSABLE` for well-formed content the service refuses), "
    "429 (rate limit or quota), "
    "500 (internal error), 503 (node unavailable or no capacity; see `Retry-After`)."
    + _ERROR_VOCABULARY
)


def error_ref(status: str) -> dict[str, Any]:
    """The component reference for an error ``status``: 429 and 503 also carry Retry-After."""
    return RETRY_ERROR_REF if status in RETRY_STATUSES else ERROR_REF


def _with_error_responses(path: str, responses: dict[str, Any]) -> dict[str, Any]:
    """``responses`` with the error envelope for 422 (when declared) and every error status.

    A status the route declares itself is kept, except the generated 422 which is replaced.
    """
    statuses = [
        status
        for status in ERROR_STATUSES
        if not (path in UNAUTHENTICATED_PATHS and status in AUTH_STATUSES)
    ]
    added = {status: error_ref(status) for status in statuses if status not in responses}
    validation = {VALIDATION_STATUS: VALIDATION_REF} if VALIDATION_STATUS in responses else {}
    return {**responses, **added, **validation}


def _sse_response(description: str) -> dict[str, Any]:
    content = {"text/event-stream": {"schema": {"type": "string"}}}
    return {"description": description, "content": content}


def _download_response() -> dict[str, Any]:
    return {
        "description": _DOWNLOAD_DESCRIPTION,
        "headers": _header_refs(
            "Content-Disposition", "Content-Length", "ETag", openapi_fs.ACCEPT_RANGES_HEADER
        ),
        "content": {
            "application/octet-stream": {"schema": _BINARY_SCHEMA},
            "application/x-tar": {"schema": _BINARY_SCHEMA},
            "application/json": {"schema": {"$ref": SCHEMA_REF_PREFIX + INLINE_ENVELOPE}},
        },
    }


def _download_head_response() -> dict[str, Any]:
    """The HEAD 200: the headers of the GET answer, with the media types it would carry."""
    response = _download_response()
    return {
        **response,
        "description": "The headers of the download; no body.",
        "content": {
            media: body for media, body in response["content"].items() if "json" not in media
        },
    }


_ERROR_CONTENT: dict[str, Any] = _ERROR_RESPONSE["content"]


def _download_get(operation: dict[str, Any]) -> dict[str, Any]:
    parameters = [_download_parameter(p) for p in operation.get("parameters", [])]
    responses = operation.get("responses", {})
    description = " ".join(
        part
        for part in (
            operation.get("description"),
            openapi_fs.SYMLINK_NOTE,
            openapi_fs.IF_RANGE_NOTE,
        )
        if part
    )
    return {
        **operation,
        "description": description,
        "parameters": [*parameters, openapi_fs.RANGE_PARAMETER],
        "responses": {
            **responses,
            "200": _download_response(),
            "206": openapi_fs.partial_response(head=False),
            "416": openapi_fs.range_refused_response(_ERROR_CONTENT, head=False),
        },
    }


def _download_head(operation: dict[str, Any]) -> dict[str, Any]:
    responses = operation.get("responses", {})
    return {
        **operation,
        "summary": openapi_fs.HEAD_SUMMARY,
        "description": openapi_fs.HEAD_DESCRIPTION,
        "parameters": [*operation.get("parameters", []), openapi_fs.RANGE_PARAMETER],
        "responses": {
            **responses,
            "200": _download_head_response(),
            "206": openapi_fs.partial_response(head=True),
            "416": openapi_fs.range_refused_response(_ERROR_CONTENT, head=True),
        },
    }


def _export_response() -> dict[str, Any]:
    return {
        "description": _EXPORT_DESCRIPTION,
        "headers": _header_refs("Content-Disposition"),
        "content": {"application/x-tar": {"schema": _BINARY_SCHEMA}},
    }


def _download_parameter(parameter: dict[str, Any]) -> dict[str, Any]:
    """The download's ``inline`` and ``max_bytes`` query parameters with their documentation."""
    name = parameter.get("name")
    if name == "inline":
        return {**parameter, "description": _INLINE_PARAMETER_DESCRIPTION}
    if name != "max_bytes":
        return parameter
    schema = parameter.get("schema", {})
    branches = [
        {**branch, "maximum": MAX_INLINE_READ_BYTES} if branch.get("type") == "integer" else branch
        for branch in schema.get("anyOf", [])
    ]
    patched = {**schema, "anyOf": branches} if branches else schema
    return {**parameter, "description": _MAX_BYTES_DESCRIPTION, "schema": patched}


def _with_media(path: str, method: str, operation: dict[str, Any]) -> dict[str, Any]:
    """``operation`` with the non-JSON request or 200 body the route really uses, if any."""
    key = (path, method)
    responses = operation.get("responses", {})
    if key == UPLOAD_OPERATION:
        too_large = openapi_fs.upload_too_large_response(_ERROR_CONTENT)
        return {
            **operation,
            "requestBody": UPLOAD_REQUEST_BODY,
            "responses": {**responses, BODY_TOO_LARGE_STATUS: too_large},
        }
    if key == DOWNLOAD_OPERATION:
        return _download_get(operation)
    if key == DOWNLOAD_HEAD_OPERATION:
        return _download_head(operation)
    if key == EXPORT_OPERATION:
        return {**operation, "responses": {**responses, "200": _export_response()}}
    if key == openapi_volumes.EXPORT_OPERATION:
        archive = openapi_volumes.export_response(_header_refs("Content-Disposition"))
        return {**operation, "responses": {**responses, "200": archive}}
    if key == openapi_volumes.RESTORE_OPERATION:
        too_large = openapi_volumes.restore_too_large_response(_ERROR_CONTENT)
        return {
            **operation,
            "requestBody": openapi_volumes.RESTORE_REQUEST_BODY,
            "responses": {**responses, BODY_TOO_LARGE_STATUS: too_large},
        }
    if key in SSE_DESCRIPTIONS:
        stream = _sse_response(SSE_DESCRIPTIONS[key])
        return {**operation, "responses": {**responses, "200": stream}}
    return operation


def takes_idempotency_key(operation: dict[str, Any]) -> bool:
    """True when ``operation`` declares the ``Idempotency-Key`` header parameter."""
    return any(
        parameter.get("in") == "header" and parameter.get("name") == IDEMPOTENCY_HEADER
        for parameter in operation.get("parameters", [])
    )


def _with_response_headers(operation: dict[str, Any]) -> dict[str, Any]:
    """Every inline response with ``x-request-id``; replays of a keyed create also say so.

    A response that is a ``$ref`` (the error components) carries its headers itself.
    """
    replayable = takes_idempotency_key(operation)
    patched: dict[str, Any] = {}
    for status, response in operation.get("responses", {}).items():
        if "$ref" in response:
            patched[status] = response
            continue
        names = [REQUEST_ID_HEADER]
        if replayable and status.startswith("2"):
            names.append(REPLAYED_HEADER)
        headers = {**_header_refs(*names), **response.get("headers", {})}
        patched[status] = {**response, "headers": headers}
    return {**operation, "responses": patched}


def _with_body_too_large(path: str, method: str, operation: dict[str, Any]) -> dict[str, Any]:
    """``operation`` with 413 when it takes a request body or reads a size-limited file."""
    responses = operation.get("responses", {})
    limited = "requestBody" in operation or (path, method) in TOO_LARGE_WITHOUT_BODY
    if not limited or BODY_TOO_LARGE_STATUS in responses:
        return operation
    return {**operation, "responses": {**responses, BODY_TOO_LARGE_STATUS: ERROR_REF}}


def _with_unsupported_media(path: str, method: str, operation: dict[str, Any]) -> dict[str, Any]:
    """``operation`` with 415 when it takes a JSON body (the upload and restore take raw bytes)."""
    responses = operation.get("responses", {})
    if "requestBody" not in operation or (path, method) in RAW_BODY_OPERATIONS:
        return operation
    if UNSUPPORTED_MEDIA_STATUS in responses:
        return operation
    return {
        **operation,
        "responses": {**responses, UNSUPPORTED_MEDIA_STATUS: UNSUPPORTED_MEDIA_REF},
    }


def _operation(path: str, method: str, operation: dict[str, Any]) -> dict[str, Any]:
    patched = _with_body_too_large(path, method, _with_media(path, method, operation))
    patched = _with_unsupported_media(path, method, patched)
    patched = describe(method, path, patched)
    patched = _with_response_headers(patched)
    responses = _with_error_responses(path, patched.get("responses", {}))
    security: dict[str, Any] = {"security": []} if path in UNAUTHENTICATED_PATHS else {}
    return {**patched, "responses": responses, **security}


def _patched_paths(paths: dict[str, Any]) -> dict[str, Any]:
    """Every operation patched; non-operation keys of a path item (``parameters``) are kept."""
    return {
        path: {
            key: _operation(path, key, value) if key in HTTP_METHODS else value
            for key, value in item.items()
        }
        for path, item in paths.items()
    }


def _without_unreferenced(document: dict[str, Any], names: Sequence[str]) -> dict[str, Any]:
    """``document`` without each named schema that nothing else references (checked in order)."""
    for name in names:
        components = document.get("components", {})
        schemas = components.get("schemas", {})
        if name not in schemas:
            continue
        rest = {key: value for key, value in schemas.items() if key != name}
        candidate = {**document, "components": {**components, "schemas": rest}}
        if json.dumps(SCHEMA_REF_PREFIX + name) not in json.dumps(candidate):
            document = candidate
    return document


def _with_inline_download(schemas: dict[str, Any]) -> dict[str, Any]:
    """``schemas`` plus the inline download envelope (the route answers it without a model)."""
    adapter = TypeAdapter(Envelope[FsDownloadResponse])
    schema = adapter.json_schema(ref_template=SCHEMA_REF_PREFIX + "{model}", mode="serialization")
    definitions: dict[str, Any] = schema.pop("$defs", {})
    added = {**definitions, INLINE_ENVELOPE: schema}
    return {**schemas, **{name: added[name] for name in added if name not in schemas}}


def _with_security_and_errors(document: dict[str, Any]) -> dict[str, Any]:
    """Copy of ``document`` with the bearer scheme, error component and description added."""
    components = document.get("components", {})
    info = document["info"]
    patched = {
        **document,
        "paths": _patched_paths(document["paths"]),
        "info": {**info, "description": (info.get("description") or "") + _DESCRIPTION_SUFFIX},
        "components": {
            **components,
            "securitySchemes": {
                **components.get("securitySchemes", {}),
                API_KEY_SCHEME: _API_KEY_SECURITY_SCHEME,
            },
            "headers": {**components.get("headers", {}), **_COMPONENT_HEADERS},
            "responses": {
                **components.get("responses", {}),
                ERROR_RESPONSE: _ERROR_RESPONSE,
                RETRY_ERROR_RESPONSE: _RETRY_ERROR_RESPONSE,
                UNSUPPORTED_MEDIA_RESPONSE: _UNSUPPORTED_MEDIA_RESPONSE,
                VALIDATION_RESPONSE: _VALIDATION_RESPONSE,
            },
            "schemas": _with_inline_download(components.get("schemas", {})),
        },
        "security": [{API_KEY_SCHEME: []}],
    }
    return _without_unreferenced(patched, GENERATED_VALIDATION_SCHEMAS)


def generated_document(app: FastAPI) -> dict[str, Any]:
    """FastAPI's own document for ``app``, built from its routes, never through ``app.openapi``."""
    return get_openapi(
        title=app.title,
        version=app.version,
        openapi_version=app.openapi_version,
        summary=app.summary,
        description=app.description,
        terms_of_service=app.terms_of_service,
        contact=app.contact,
        license_info=app.license_info,
        routes=app.routes,
        webhooks=app.webhooks.routes,
        tags=app.openapi_tags,
        servers=app.servers,
        separate_input_output_schemas=app.separate_input_output_schemas,
        external_docs=app.openapi_external_docs,
    )


def build_document(app: FastAPI | None = None) -> dict[str, Any]:
    """The application's OpenAPI document with the export version marker in ``info``."""
    document = _with_security_and_errors(generated_document(app or build_app()))
    info = {**document["info"], EXPORT_VERSION_KEY: EXPORT_VERSION}
    return {**document, "info": info, "servers": SERVERS}


def render_spec(document: dict[str, Any]) -> str:
    """Sorted keys, two-space indent, trailing newline."""
    return json.dumps(document, sort_keys=True, indent=2) + "\n"


def export_spec(path: Path = OPENAPI_PATH, app: FastAPI | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(render_spec(build_document(app)).encode("utf-8"))
    return path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export the Sandfort OpenAPI document.")
    parser.add_argument("output", nargs="?", type=Path, default=OPENAPI_PATH)
    args = parser.parse_args(argv)
    written = export_spec(args.output)
    print(f"wrote {written}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
