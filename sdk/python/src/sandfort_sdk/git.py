"""Git toolbox facade (``sandbox.git``): clone, status, add, commit, push and pull.

A :class:`GitCredential` is passed per call and only ever serialized into that request's
JSON body: the facade keeps no reference to it and its token is excluded from ``repr``.
A credentialed ``push`` or ``pull`` also needs ``remote_url``: the server refuses (422)
when the repository's remote names another host and runs git against that url, so code
inside the sandbox cannot redirect the token by rewriting the remote.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from sandfort_sdk._requests import area_path
from sandfort_sdk._transport import AsyncTransport, SyncTransport
from sandfort_sdk.models import _as_dict, _as_list, _required

# Server-side budgets (``toolbox.git``): local commands vs. network operations.
LOCAL_WAIT_S = 60.0
REMOTE_WAIT_S = 600.0
DEFAULT_REMOTE = "origin"


@dataclass(frozen=True, slots=True)
class GitCredential:
    """HTTPS credential for one git call; the token never appears in ``repr`` or ``str``."""

    username: str
    token: str = field(repr=False)

    def __post_init__(self) -> None:
        if not self.username or not self.token:
            raise ValueError("git credential username and token must not be empty")

    def to_payload(self) -> dict[str, str]:
        return {"username": self.username, "token": self.token}


@dataclass(frozen=True, slots=True)
class GitFileStatus:
    path: str
    index: str
    worktree: str

    @classmethod
    def from_payload(cls, data: Any) -> "GitFileStatus":
        raw = _as_dict(data, "git file status")
        return cls(*_required(raw, "git file status", "path", "index", "worktree"))


@dataclass(frozen=True, slots=True)
class GitStatus:
    branch: str | None
    ahead: int = 0
    behind: int = 0
    files: tuple[GitFileStatus, ...] = ()

    @property
    def is_clean(self) -> bool:
        return not self.files

    @classmethod
    def from_payload(cls, data: Any) -> "GitStatus":
        raw = _as_dict(data, "git status")
        files = _as_list(raw.get("files") or [], "git status files")
        return cls(
            branch=raw.get("branch"),
            ahead=raw.get("ahead", 0),
            behind=raw.get("behind", 0),
            files=tuple(GitFileStatus.from_payload(item) for item in files),
        )


@dataclass(frozen=True, slots=True)
class GitResult:
    """Outcome of clone, add, push and pull; ``output`` is credential-scrubbed by the server."""

    path: str
    output: str = ""

    @classmethod
    def from_payload(cls, data: Any) -> "GitResult":
        raw = _as_dict(data, "git result")
        (path,) = _required(raw, "git result", "path")
        return cls(path, raw.get("output") or "")


@dataclass(frozen=True, slots=True)
class GitCommitResult:
    sha: str

    @classmethod
    def from_payload(cls, data: Any) -> "GitCommitResult":
        return cls(*_required(_as_dict(data, "git commit"), "git commit", "sha"))


def _git_path(sandbox_id: str, tail: str) -> str:
    return area_path(sandbox_id, "git", f"/{tail}")


def _body(fields: dict[str, Any], credential: GitCredential | None = None) -> dict[str, Any]:
    body = {key: value for key, value in fields.items() if value is not None}
    if credential is None:
        return body
    return {**body, "credential": credential.to_payload()}


def _add_body(path: str, files: str | Sequence[str]) -> dict[str, Any]:
    names = [files] if isinstance(files, str) else list(files)
    if not names:
        raise ValueError("files must not be empty")
    return {"path": path, "files": names}


def _commit_body(
    path: str, message: str, author_name: str | None, author_email: str | None
) -> dict[str, Any]:
    if not message.strip():
        raise ValueError("commit message must not be empty")
    fields = {
        "path": path,
        "message": message,
        "author_name": author_name,
        "author_email": author_email,
    }
    return _body(fields)


def _sync_body(
    path: str,
    remote: str,
    branch: str | None,
    credential: GitCredential | None,
    remote_url: str | None,
) -> dict[str, Any]:
    """Push/pull body; a credential is bound to the caller's ``remote_url`` (required)."""
    if credential is not None and not remote_url:
        raise ValueError("remote_url is required when a credential is given")
    fields = {"path": path, "remote": remote, "branch": branch, "remote_url": remote_url}
    return _body(fields, credential)


class Git:
    """Synchronous git toolbox of one sandbox."""

    def __init__(self, sandbox_id: str, transport: SyncTransport) -> None:
        self._sandbox_id = sandbox_id
        self._transport = transport

    def clone(
        self,
        url: str,
        path: str,
        *,
        branch: str | None = None,
        depth: int | None = None,
        credential: GitCredential | None = None,
    ) -> GitResult:
        body = _body({"url": url, "path": path, "branch": branch, "depth": depth}, credential)
        return GitResult.from_payload(self._post("clone", body, REMOTE_WAIT_S))

    def status(self, path: str) -> GitStatus:
        reply = self._transport.request(
            "GET", _git_path(self._sandbox_id, "status"), params={"path": path}
        )
        return GitStatus.from_payload(reply.data)

    def add(self, path: str, files: str | Sequence[str] = (".",)) -> GitResult:
        return GitResult.from_payload(self._post("add", _add_body(path, files), LOCAL_WAIT_S))

    def commit(
        self,
        path: str,
        message: str,
        *,
        author_name: str | None = None,
        author_email: str | None = None,
    ) -> GitCommitResult:
        body = _commit_body(path, message, author_name, author_email)
        return GitCommitResult.from_payload(self._post("commit", body, LOCAL_WAIT_S))

    def push(
        self,
        path: str,
        *,
        remote: str = DEFAULT_REMOTE,
        branch: str | None = None,
        credential: GitCredential | None = None,
        remote_url: str | None = None,
    ) -> GitResult:
        body = _sync_body(path, remote, branch, credential, remote_url)
        return GitResult.from_payload(self._post("push", body, REMOTE_WAIT_S))

    def pull(
        self,
        path: str,
        *,
        remote: str = DEFAULT_REMOTE,
        branch: str | None = None,
        credential: GitCredential | None = None,
        remote_url: str | None = None,
    ) -> GitResult:
        body = _sync_body(path, remote, branch, credential, remote_url)
        return GitResult.from_payload(self._post("pull", body, REMOTE_WAIT_S))

    def _post(self, tail: str, body: dict[str, Any], wait_s: float) -> Any:
        path = _git_path(self._sandbox_id, tail)
        return self._transport.request("POST", path, json=body, server_wait_s=wait_s).data


class AsyncGit:
    """Asynchronous git toolbox of one sandbox."""

    def __init__(self, sandbox_id: str, transport: AsyncTransport) -> None:
        self._sandbox_id = sandbox_id
        self._transport = transport

    async def clone(
        self,
        url: str,
        path: str,
        *,
        branch: str | None = None,
        depth: int | None = None,
        credential: GitCredential | None = None,
    ) -> GitResult:
        body = _body({"url": url, "path": path, "branch": branch, "depth": depth}, credential)
        return GitResult.from_payload(await self._post("clone", body, REMOTE_WAIT_S))

    async def status(self, path: str) -> GitStatus:
        reply = await self._transport.request(
            "GET", _git_path(self._sandbox_id, "status"), params={"path": path}
        )
        return GitStatus.from_payload(reply.data)

    async def add(self, path: str, files: str | Sequence[str] = (".",)) -> GitResult:
        body = _add_body(path, files)
        return GitResult.from_payload(await self._post("add", body, LOCAL_WAIT_S))

    async def commit(
        self,
        path: str,
        message: str,
        *,
        author_name: str | None = None,
        author_email: str | None = None,
    ) -> GitCommitResult:
        body = _commit_body(path, message, author_name, author_email)
        return GitCommitResult.from_payload(await self._post("commit", body, LOCAL_WAIT_S))

    async def push(
        self,
        path: str,
        *,
        remote: str = DEFAULT_REMOTE,
        branch: str | None = None,
        credential: GitCredential | None = None,
        remote_url: str | None = None,
    ) -> GitResult:
        body = _sync_body(path, remote, branch, credential, remote_url)
        return GitResult.from_payload(await self._post("push", body, REMOTE_WAIT_S))

    async def pull(
        self,
        path: str,
        *,
        remote: str = DEFAULT_REMOTE,
        branch: str | None = None,
        credential: GitCredential | None = None,
        remote_url: str | None = None,
    ) -> GitResult:
        body = _sync_body(path, remote, branch, credential, remote_url)
        return GitResult.from_payload(await self._post("pull", body, REMOTE_WAIT_S))

    async def _post(self, tail: str, body: dict[str, Any], wait_s: float) -> Any:
        path = _git_path(self._sandbox_id, tail)
        reply = await self._transport.request("POST", path, json=body, server_wait_s=wait_s)
        return reply.data
