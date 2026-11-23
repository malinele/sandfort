"""Request/response models for the ``/git`` toolbox routes (stubs frozen by seed S2).

Credentials are ephemeral: accepted on a request, used for that one operation
and never echoed back (no response model contains a credential, and the token
field is excluded from serialization and ``repr``).
"""

from typing import Self

from pydantic import BaseModel, Field, model_validator

from sandfort.api.schemas.common import NoBool, RequestModel

# Upper bound for ``git clone --depth``: far past any useful shallow clone; omit ``depth``
# for the full history.
MAX_CLONE_DEPTH = 1_000_000


class GitCredential(RequestModel):
    username: str = Field(min_length=1)
    token: str = Field(min_length=1, repr=False, exclude=True)


class GitCloneRequest(RequestModel):
    url: str
    path: str
    branch: str | None = None
    depth: NoBool[int | None] = Field(
        default=None,
        ge=1,
        le=MAX_CLONE_DEPTH,
        description=(
            f"Shallow clone with this many commits (1 to {MAX_CLONE_DEPTH}); "
            "omit for the full history."
        ),
    )
    credential: GitCredential | None = None


class GitStatusRequest(RequestModel):
    path: str


class GitAddRequest(RequestModel):
    path: str
    files: list[str] = Field(default_factory=lambda: ["."], min_length=1)


class GitCommitRequest(RequestModel):
    path: str
    message: str = Field(min_length=1)
    author_name: str | None = None
    author_email: str | None = None


REMOTE_URL_DESCRIPTION = (
    "http(s) url of the remote, supplied by the caller. Required with a credential. The "
    "repository's remote must name the same scheme and host (422 otherwise), and git is "
    "run against this url instead of the remote name, so sandbox config cannot redirect "
    "the credential."
)


class _GitSyncRequest(RequestModel):
    path: str
    remote: str = "origin"
    branch: str | None = None
    credential: GitCredential | None = None
    remote_url: str | None = Field(default=None, min_length=1, description=REMOTE_URL_DESCRIPTION)

    @model_validator(mode="after")
    def credential_needs_remote_url(self) -> Self:
        if self.credential is not None and self.remote_url is None:
            raise ValueError("remote_url is required when a credential is given")
        return self


class GitPushRequest(_GitSyncRequest):
    pass


class GitPullRequest(_GitSyncRequest):
    pass


class GitFileStatus(BaseModel):
    path: str
    index: str
    worktree: str


class GitStatusResponse(BaseModel):
    branch: str | None
    ahead: int = 0
    behind: int = 0
    files: list[GitFileStatus] = Field(default_factory=list)


class GitCommitResponse(BaseModel):
    sha: str


class GitOperationResponse(BaseModel):
    """Result of clone, add, push and pull; ``output`` is credential-scrubbed."""

    path: str
    output: str = ""
