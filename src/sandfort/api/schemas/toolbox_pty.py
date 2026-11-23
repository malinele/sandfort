"""Request/response models for PTY sessions (stubs frozen by seed S2)."""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field

from sandfort.api.schemas.common import NoBool, RequestModel

MAX_PTY_DIMENSION = 1000


class PtyCreateRequest(RequestModel):
    rows: NoBool[int] = Field(default=24, ge=1, le=MAX_PTY_DIMENSION)
    cols: NoBool[int] = Field(default=80, ge=1, le=MAX_PTY_DIMENSION)
    # None runs the default shell: bash when the image has it, else /bin/sh.
    argv: Annotated[list[str], Field(min_length=1)] | None = None
    env: dict[str, str] = Field(default_factory=dict)


class PtyResizeRequest(RequestModel):
    rows: NoBool[int] = Field(ge=1, le=MAX_PTY_DIMENSION)
    cols: NoBool[int] = Field(ge=1, le=MAX_PTY_DIMENSION)


class PtyResponse(BaseModel):
    id: str
    sandbox_id: str
    state: str
    rows: int
    cols: int
    created_at: datetime


class PtyConnectTokenResponse(BaseModel):
    pty_id: str
    token: str = Field(repr=False)
    websocket_url: str
