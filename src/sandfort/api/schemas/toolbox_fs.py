"""Request/response models for the ``/fs`` toolbox routes (stubs frozen by seed S2)."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from sandfort.api.schemas.common import NoBool, RequestModel

MAX_UPLOAD_BYTES = 256 * 1024 * 1024
MAX_INLINE_READ_BYTES = 2 * 1024 * 1024


class FileEntry(BaseModel):
    name: str
    path: str
    kind: Literal["file", "dir", "symlink"]
    size_bytes: int = Field(ge=0)
    mode: str
    modified_at: datetime | None = None


class FsListRequest(RequestModel):
    path: str = "/"


class FsListResponse(BaseModel):
    path: str
    entries: list[FileEntry]


class FsStatRequest(RequestModel):
    path: str


class FsStatResponse(BaseModel):
    entry: FileEntry


class FsMkdirRequest(RequestModel):
    path: str
    mode: str = "755"
    parents: bool = True


class FsMkdirResponse(BaseModel):
    path: str
    created: bool


class FsMoveRequest(RequestModel):
    source: str
    destination: str
    overwrite: bool = False


class FsMoveResponse(BaseModel):
    source: str
    destination: str


class FsDeleteRequest(RequestModel):
    path: str
    recursive: bool = False


class FsDeleteResponse(BaseModel):
    path: str
    deleted: bool


class FsUploadRequest(RequestModel):
    path: str
    size_bytes: NoBool[int] = Field(ge=0, le=MAX_UPLOAD_BYTES)
    overwrite: bool = True


class FsUploadResponse(BaseModel):
    path: str
    size_bytes: int = Field(ge=0)


class FsDownloadRequest(RequestModel):
    path: str
    inline: bool = False
    max_bytes: NoBool[int] = Field(default=MAX_INLINE_READ_BYTES, ge=1, le=MAX_INLINE_READ_BYTES)


class FsDownloadResponse(BaseModel):
    """Inline reads carry ``content`` (utf-8 text); larger files stream instead."""

    path: str
    size_bytes: int = Field(ge=0)
    content: str | None = None
    truncated: bool = False
