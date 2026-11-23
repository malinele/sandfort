"""The OpenAPI declarations of the volume transfer routes (export and restore).

Both move a gzipped tar as the raw HTTP body (``application/gzip``), never JSON. The export 200
is a binary download; restore takes the archive as a required raw request body, so it takes no
JSON content type (no 415) and documents its own 413 (``routes/volumes.py``,
``services/volume_transfer.py``).
"""

from typing import Any

from sandfort.api.openapi_fs import PAYLOAD_TOO_LARGE
from sandfort.api.schemas.toolbox_fs import MAX_UPLOAD_BYTES
from sandfort.toolbox.fs_range import MIB

EXPORT_OPERATION = ("/v1/volumes/{volume_id}/export", "get")
RESTORE_OPERATION = ("/v1/volumes/{volume_id}/restore", "post")
ARCHIVE_MEDIA_TYPE = "application/gzip"
_BINARY_SCHEMA: dict[str, Any] = {"type": "string", "format": "binary"}
_LIMIT_TEXT = f"{MAX_UPLOAD_BYTES // MIB} MiB"

EXPORT_RESPONSE_DESCRIPTION = (
    "The volume as a gzipped tar (`application/gzip`, binary), streamed with a "
    "`Content-Disposition: attachment` file name `<volume name>.tar.gz`."
)
RESTORE_REQUEST_BODY: dict[str, Any] = {
    "required": True,
    "description": (
        "A gzipped tar (`application/gzip`, binary) as the raw request body, at most "
        f"{_LIMIT_TEXT} compressed. It replaces the volume's contents; a JSON body is not accepted."
    ),
    "content": {ARCHIVE_MEDIA_TYPE: {"schema": _BINARY_SCHEMA}},
}


def export_response(headers: dict[str, Any]) -> dict[str, Any]:
    """The export 200: a binary gzip body, with the shared ``Content-Disposition`` header."""
    return {
        "description": EXPORT_RESPONSE_DESCRIPTION,
        "headers": headers,
        "content": {ARCHIVE_MEDIA_TYPE: {"schema": _BINARY_SCHEMA}},
    }


def restore_too_large_response(error_content: dict[str, Any]) -> dict[str, Any]:
    """The restore 413, in its three forms."""
    return {
        "description": (
            f"Error code `{PAYLOAD_TOO_LARGE}`. Three causes: a `Content-Length` over "
            f"{_LIMIT_TEXT} (refused before the body is read, nothing changes; `error.details` "
            "is `{limit_bytes, size_bytes}`); more bytes sent than that without a declared "
            "length; or the extracted data over the volume size limit (`details.limit_bytes`) "
            "or over 64 times the compressed size (`details.max_expansion_ratio`), which "
            "leaves the volume empty (`details.volume_emptied` is `true`)."
        ),
        "content": error_content,
    }
