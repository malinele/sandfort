"""Request/response models for exec sessions and their commands."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from sandfort.api.schemas.common import NoBool, RequestModel
from sandfort.api.schemas.text_checks import check_cwd, check_env
from sandfort.api.schemas.toolbox_process import MAX_TIMEOUT_S, ExecuteResponse
from sandfort.db.models.exec import ExecCommandState

StreamName = Literal["stdout", "stderr"]


class SessionCreateRequest(RequestModel):
    cwd: str | None = None
    env: dict[str, str] = Field(default_factory=dict)

    @field_validator("cwd")
    @classmethod
    def valid_cwd(cls, value: str | None) -> str | None:
        return check_cwd(value)

    @field_validator("env")
    @classmethod
    def valid_env(cls, value: dict[str, str]) -> dict[str, str]:
        check_env(value)
        return value


class SessionResponse(BaseModel):
    id: str
    sandbox_id: str
    cwd: str | None
    env: dict[str, str]
    state: str
    created_at: datetime


class SessionCommandRequest(RequestModel):
    command: str = Field(min_length=1)
    mode: Literal["sync", "async"] = "sync"
    timeout_s: NoBool[int] = Field(default=60, ge=1, le=MAX_TIMEOUT_S)


class CommandStatus(BaseModel):
    id: str
    session_id: str | None
    state: ExecCommandState
    exit_code: int | None = None
    stdout_bytes: int = Field(default=0, ge=0)
    stderr_bytes: int = Field(default=0, ge=0)
    created_at: datetime
    finished_at: datetime | None = None


class SessionExecResponse(BaseModel):
    """Sync calls carry ``result``; async calls carry the running ``command``."""

    mode: Literal["sync", "async"]
    cwd: str | None = None
    result: ExecuteResponse | None = None
    command: CommandStatus | None = None


class LogEvent(BaseModel):
    stream: StreamName
    offset: int = Field(ge=0)
    line: str


class LogPageResponse(BaseModel):
    """One page of a command's log; ``next_offset`` is where the next read starts."""

    events: list[LogEvent]
    next_offset: int = Field(ge=0)
    truncated: bool
    state: ExecCommandState | None = None
    exit_code: int | None = None
    complete: bool
