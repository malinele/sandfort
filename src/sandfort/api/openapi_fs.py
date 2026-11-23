"""OpenAPI text for the fs transfer routes: ranged and HEAD downloads and the upload limit.

``openapi.py`` merges these pieces into the exported document. They live here so that module
stays focused on the shared envelope, and so the numbers (the upload limit) are read from the
constants the routes use, not copied.
"""

from typing import Any

from sandfort.api.schemas.toolbox_fs import MAX_UPLOAD_BYTES
from sandfort.toolbox.fs_range import MIB

HEADER_REF_PREFIX = "#/components/headers/"
ACCEPT_RANGES_HEADER = "Accept-Ranges"
CONTENT_RANGE_HEADER = "Content-Range"
RANGE_NOT_SATISFIABLE = "RANGE_NOT_SATISFIABLE"
PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
_LIMIT_TEXT = f"{MAX_UPLOAD_BYTES // MIB} MiB ({MAX_UPLOAD_BYTES} bytes)"

COMPONENT_HEADERS: dict[str, Any] = {
    ACCEPT_RANGES_HEADER: {
        "description": (
            "`bytes` on a file download: the server honours one `Range`. `none` on a directory "
            "tar, which cannot be ranged."
        ),
        "schema": {"type": "string", "enum": ["bytes", "none"]},
    },
    CONTENT_RANGE_HEADER: {
        "description": (
            "On 206, `bytes <first>-<last>/<size>`: the bytes sent and the size of the whole "
            "file. On 416, `bytes */<size>`."
        ),
        "schema": {"type": "string"},
    },
}

RANGE_PARAMETER: dict[str, Any] = {
    "in": "header",
    "name": "Range",
    "required": False,
    "description": (
        "Read part of a file: one byte range, `bytes=0-1023` (the first 1024 bytes), "
        "`bytes=1024-` (from byte 1024 to the end) or `bytes=-512` (the last 512 bytes). "
        "The unit is case-insensitive. Single byte ranges only: several ranges, another "
        "unit, a reversed range, spaces inside the range and a malformed value are ignored "
        "and the whole file is answered 200. A range that starts at or past the end of the "
        "file, any range on an empty file, and the empty suffix `bytes=-0` answer 416. With "
        "`If-Range`, the range is honoured only when it names the file's current ETag; "
        "otherwise the whole file is answered 200. A directory and an `inline=true` read "
        "ignore the header."
    ),
    "schema": {"type": "string", "examples": ["bytes=0-1023"]},
}

_RANGED_BODY = {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}
SYMLINK_NOTE = (
    "A path that is a symlink is not followed: it answers 409 `CONFLICT` "
    '("cannot download a symlink"); download the link target instead.'
)
IF_RANGE_NOTE = (
    "If-Range is compared to the weak ETag; this deviates from RFC 9110, which forbids weak "
    "validators there, so a changed file with an unchanged mtime could resume wrongly."
)
HEAD_SUMMARY = "Download headers"
HEAD_DESCRIPTION = (
    "The status and headers `GET` on the same path would answer, with no body: "
    "`Content-Length`, `ETag` and `Accept-Ranges` of a file, or `Accept-Ranges: none` of a "
    "directory tar. A `Range` header is answered as `GET` does (206 or 416 with "
    "`Content-Range`). `inline` and `max_bytes` are accepted and ignored: the headers are "
    "those of the plain download. HEAD reads the file's metadata only and never streams the "
    "file or builds a directory tar. A symlinked path answers 409 `CONFLICT`, as `GET` does. "
    "Needs the same scope as `GET`."
)


def _refs(*names: str) -> dict[str, Any]:
    return {name: {"$ref": HEADER_REF_PREFIX + name} for name in names}


def partial_response(*, head: bool) -> dict[str, Any]:
    """The 206 answer: one range of a file, with its own length and ``Content-Range``."""
    length = {
        "description": "Number of bytes of the range, not of the whole file.",
        "schema": {"type": "integer", "minimum": 1},
    }
    response: dict[str, Any] = {
        "description": (
            "The requested byte range of the file"
            + ("; no body on HEAD." if head else " (`application/octet-stream`).")
        ),
        "headers": {
            **_refs("Content-Disposition", CONTENT_RANGE_HEADER, ACCEPT_RANGES_HEADER, "ETag"),
            "Content-Length": length,
        },
    }
    return {**response, "content": _RANGED_BODY}


def range_refused_response(error_content: dict[str, Any], *, head: bool) -> dict[str, Any]:
    """The 416 answer: the range lies outside the file, ``Content-Range: bytes */<size>``."""
    body = "" if head else " The envelope carries `details.size_bytes`."
    response: dict[str, Any] = {
        "description": (
            f"Error code `{RANGE_NOT_SATISFIABLE}`: the range starts at or past the end of "
            "the file. `Content-Range: bytes */<size>` gives the size of the file." + body
        ),
        "headers": _refs(CONTENT_RANGE_HEADER, ACCEPT_RANGES_HEADER),
    }
    return response if head else {**response, "content": error_content}


def upload_too_large_response(error_content: dict[str, Any]) -> dict[str, Any]:
    """The 413 of an upload over the limit, answered before the body is read."""
    return {
        "description": (
            f"Error code `{PAYLOAD_TOO_LARGE}`: the upload is over the limit of {_LIMIT_TEXT}. "
            "It is refused before the body is read and nothing is written, whether the size "
            "comes from `size_bytes` or from `Content-Length`. The message reads `upload limit "
            f"is {_LIMIT_TEXT}; this upload is <N> bytes`, and `error.details` is "
            "`{limit_bytes, size_bytes}`."
        ),
        "content": error_content,
    }
