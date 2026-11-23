"""Git toolbox facade used by the ``/git`` routes: clone, status, add, commit, push, pull.

Every operation runs ``git`` through the driver exec primitive as an argv list (never a
shell string). Repository paths are validated like fs toolbox paths and handed to git with
``-C`` (clone takes its target as the final argument). Each call guards the sandbox and
writes its audit row before the driver is touched (intent-then-act); audit details carry
the url or remote with any userinfo stripped and never a credential. Credentialed clone,
push and pull run inside ``ephemeral_askpass``: the helper exists only around that one git
exec, sandbox credential helpers are disabled for it, and surfaced text is ``redact``-ed.
Credentialed execs are also hardened against sandbox-written config: hooks, fsmonitor and
proxies are off, TLS verification is forced, url rewriting for the target is pinned, and
the global and system git config are replaced by a null file for that one exec. A
credentialed push or pull is bound to the caller's ``remote_url``: the repository's remote
must name the same host and git receives that url, not the remote name.
"""

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType
from sandfort.domain.sandbox import Sandbox, visible_stop_cause
from sandfort.drivers.base import ExecRequest, ExecResult, SandboxDriver
from sandfort.drivers.errors import DriverTimeout
from sandfort.errors import OPERATION_FAILED, Conflict, Unprocessable, no_container_conflict
from sandfort.toolbox.fs import Actor, AuditSink
from sandfort.toolbox.git_credentials import (
    Credential,
    ephemeral_askpass,
    redact,
    remote_base,
    require_same_target,
    strip_userinfo,
    validate_credential,
)
from sandfort.toolbox.guards import load_started_sandbox
from sandfort.toolbox.paths import normalize_path

GIT = "git"
LOCAL_TIMEOUT_S = 60.0
REMOTE_TIMEOUT_S = 600.0
OUTPUT_BYTES = 1024 * 1024
ERROR_EXCERPT_CHARS = 500
NO_CREDENTIAL_HELPER = ("-c", "credential.helper=")
NO_HOOKS_PATH = "/nonexistent/sandfort-no-hooks"
# Config overrides for every credentialed exec (before the target-specific ones below).
HARDENING_OVERRIDES = (
    *NO_CREDENTIAL_HELPER,
    "-c",
    f"core.hooksPath={NO_HOOKS_PATH}",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "http.sslVerify=true",
    "-c",
    "http.proxy=",
)
# Sandbox-written global config and the system config must not inject settings.
ISOLATED_CONFIG_ENV: Mapping[str, str] = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
}
# Remote operations never wait on a terminal prompt: without a credential they fail fast.
REMOTE_ENV: Mapping[str, str] = {"GIT_TERMINAL_PROMPT": "0"}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# Commit runs with untranslated messages so the English markers below always match.
COMMIT_LOCALE_ENV: Mapping[str, str] = {"LC_ALL": "C", "LANGUAGE": "C"}
# Lowercase fragments of git's "who are you" failures (stderr text, never echoed back).
IDENTITY_MARKERS = (
    "author identity unknown",
    "committer identity unknown",
    "unable to auto-detect email address",
    "empty ident name",
    "no name was given and auto-detection is disabled",  # user.useConfigOnly
    "no email was given and auto-detection is disabled",  # user.useConfigOnly
)
MISSING_IDENTITY_MESSAGE = (
    "git needs an author for this commit: pass author_name and author_email, "
    "or set user.name and user.email in the sandbox"
)

GIT_MISSING = "git_missing"
GIT_MISSING_MESSAGE = (
    "git is not installed in this sandbox's image (the default python:3.12-slim has no git); "
    "create the sandbox from an image that has git, for example snapshot python:3.12"
)
COMMAND_NOT_FOUND_EXIT_CODE = 127
# The runner's own line, or a shell's ("sh: 1: git: not found", "bash: git: command not found").
_GIT_NOT_FOUND = re.compile(
    r"^(?:command not found: git|(?:[^:\n]+: )*git: (?:command )?not found)$", re.MULTILINE
)


@dataclass(frozen=True, slots=True)
class FileStatus:
    path: str
    index: str
    worktree: str


@dataclass(frozen=True, slots=True)
class RepoStatus:
    branch: str | None
    ahead: int
    behind: int
    files: tuple[FileStatus, ...]


@dataclass(frozen=True, slots=True)
class GitOutput:
    """Path the operation ran on and its scrubbed stdout."""

    path: str
    output: str


# -- validation ----------------------------------------------------------------------


def _check_arg(value: str | None, field: str) -> None:
    """A value git could parse as an option: non-empty, no leading ``-``, no control chars."""
    if value is None:
        return
    if not value or value.startswith("-") or _CONTROL.search(value):
        raise Unprocessable(
            f"{field} must be non-empty, must not start with '-' and must not contain "
            "control characters",
            details={"field": field},
        )


def _check_text(value: str | None, field: str) -> None:
    if value is not None and _CONTROL.search(value):
        message = f"{field} must not contain control characters"
        raise Unprocessable(message, details={"field": field})


def _check_files(files: Sequence[str]) -> list[str]:
    if not files or any(not name or "\x00" in name for name in files):
        raise Unprocessable("files must be non-empty names without NUL bytes")
    return list(files)


# -- argv builders -------------------------------------------------------------------


def credential_overrides(url: str, username: str) -> list[str]:
    """Config overrides for a credentialed exec against ``url``.

    The username is config (not an askpass answer); the target's own url prefix is pinned
    with an identity ``insteadOf`` rule so a shorter rewrite of its scheme cannot win.
    """
    base = remote_base(url)
    return [
        *HARDENING_OVERRIDES,
        "-c",
        f"credential.username={username}",
        "-c",
        f"url.{base}.insteadOf={base}",
    ]


def clone_argv(
    url: str, target: str, *, branch: str | None, depth: int | None, overrides: Sequence[str] = ()
) -> list[str]:
    argv = [GIT, *overrides, "clone"]
    if branch is not None:
        argv += ["--branch", branch]
    if depth is not None:
        argv += ["--depth", str(depth)]
    return [*argv, "--", url, target]


def commit_argv(
    repo: str, message: str, *, author_name: str | None, author_email: str | None
) -> list[str]:
    identity: list[str] = []
    if author_name is not None:
        identity += ["-c", f"user.name={author_name}"]
    if author_email is not None:
        identity += ["-c", f"user.email={author_email}"]
    return [GIT, "-C", repo, *identity, "commit", "-m", message]


# -- status parsing ------------------------------------------------------------------


def _parse_branch(header: str) -> tuple[str | None, int, int]:
    """``## main...origin/main [ahead 1, behind 2]`` -> ``("main", 1, 2)``."""
    text, tracking = header[3:], ""
    if text.endswith("]") and " [" in text:
        text, _, tracking = text[:-1].rpartition(" [")
    for prefix in ("No commits yet on ", "Initial commit on "):
        text = text.removeprefix(prefix)
    branch = text.split("...", 1)[0]
    counts = {"ahead": 0, "behind": 0}
    for item in tracking.split(","):
        word, _, count = item.strip().partition(" ")
        if word in counts and count.isdigit():
            counts[word] = int(count)
    detached = not branch or branch.startswith("HEAD (")
    return (None if detached else branch), counts["ahead"], counts["behind"]


def parse_status(stdout: bytes) -> RepoStatus:
    """Parse ``git status --porcelain=v1 --branch -z`` output."""
    records = stdout.decode(errors="replace").split("\x00")
    branch: str | None = None
    ahead = behind = 0
    files: list[FileStatus] = []
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if record.startswith("## "):
            branch, ahead, behind = _parse_branch(record)
        elif len(record) > 3:
            files.append(FileStatus(path=record[3:], index=record[0], worktree=record[1]))
            if record[0] in "RC":
                index += 1  # -z puts the rename/copy source in the next record
    return RepoStatus(branch=branch, ahead=ahead, behind=behind, files=tuple(files))


def _text(result: ExecResult, hidden: Sequence[str] = ()) -> str:
    return redact(result.stdout.decode(errors="replace"), *hidden, truncated=result.truncated)


def _excerpt(result: ExecResult, hidden: Sequence[str]) -> str:
    raw = (result.stderr or result.stdout).decode(errors="replace")
    return redact(raw, *hidden, truncated=result.truncated).strip()[:ERROR_EXCERPT_CHARS]


def is_missing_identity(result: ExecResult) -> bool:
    """True when git refused to commit because no author or committer identity is set.

    Only stderr is scanned: a hook printing the phrase on stdout is not git's complaint.
    """
    text = result.stderr.decode(errors="replace").lower()
    return any(marker in text for marker in IDENTITY_MARKERS)


def is_git_missing(result: ExecResult) -> bool:
    """True when the exec failed because the image has no ``git`` binary.

    Needs the not-found exit code and a not-found line for git on stderr; a different missing
    program, another exit code, or the phrase on stdout is not this failure.
    """
    if result.exit_code != COMMAND_NOT_FOUND_EXIT_CODE:
        return False
    return _GIT_NOT_FOUND.search(result.stderr.decode(errors="replace")) is not None


def _missing_identity_field(author_name: str | None, author_email: str | None) -> str:
    """The request field the caller should supply: the email when only it is missing."""
    return "author_email" if author_name is not None and author_email is None else "author_name"


def _failure(action: str, result: ExecResult, hidden: Sequence[str]) -> Conflict:
    if is_git_missing(result):
        return Conflict(GIT_MISSING_MESSAGE, reason=GIT_MISSING, details={"action": action})
    excerpt = _excerpt(result, hidden)
    message = f"git {action} failed: {excerpt}" if excerpt else f"git {action} failed"
    return Conflict(message, reason=OPERATION_FAILED, details={"exit_code": result.exit_code})


class GitToolbox:
    def __init__(self, driver: SandboxDriver, recorder: AuditSink, clock: Clock) -> None:
        self._driver = driver
        self._recorder = recorder
        self._clock = clock

    # -- plumbing ----------------------------------------------------------------------

    async def _begin(
        self,
        uow: UnitOfWorkPort,
        actor: Actor,
        sandbox_id: str,
        action: str,
        details: Mapping[str, Any],
    ) -> Sandbox:
        """Guard the sandbox, then audit the call before the driver is touched."""
        async with uow:
            sandbox = await load_started_sandbox(uow, actor.org_id, sandbox_id, self._clock)
            await self._recorder.record(
                uow,
                org_id=actor.org_id,
                actor_type=ActorType.API_KEY,
                actor_id=actor.key_id,
                action=action,
                target_type="sandbox",
                target_id=sandbox_id,
                details=details,
            )
            await uow.commit()
            return sandbox

    @staticmethod
    def _ref(sandbox: Sandbox) -> str:
        if sandbox.driver_ref is None:
            raise no_container_conflict(sandbox.state.value, visible_stop_cause(sandbox))
        return sandbox.driver_ref

    async def _run(
        self,
        sandbox: Sandbox,
        argv: Sequence[str],
        *,
        action: str,
        timeout_s: float = LOCAL_TIMEOUT_S,
        env: Mapping[str, str] | None = None,
        hidden: Sequence[str] = (),
    ) -> ExecResult:
        result = await self._exec(sandbox, argv, action=action, timeout_s=timeout_s, env=env)
        if result.exit_code != 0:
            raise _failure(action, result, hidden)
        return result

    async def _exec(
        self,
        sandbox: Sandbox,
        argv: Sequence[str],
        *,
        action: str,
        timeout_s: float = LOCAL_TIMEOUT_S,
        env: Mapping[str, str] | None = None,
    ) -> ExecResult:
        """Run git once; a timeout raises, any exit code is returned to the caller."""
        request = ExecRequest(
            argv=list(argv), env=dict(env or {}), timeout_s=timeout_s, max_output_bytes=OUTPUT_BYTES
        )
        result = await self._driver.exec(self._ref(sandbox), request)
        if result.timed_out:
            raise DriverTimeout(f"git {action} timed out", ref=sandbox.driver_ref)
        return result

    async def _remote(
        self,
        sandbox: Sandbox,
        argv_for: Callable[[Sequence[str]], list[str]],
        *,
        action: str,
        credential: Credential | None,
        url: str,
    ) -> str:
        """Run a network operation, with an askpass helper around it when credentialed.

        ``url`` is the remote the credential may be used for; ``argv_for`` receives the
        config overrides to place after the global options (empty when uncredentialed).
        """
        if credential is None:
            result = await self._run(
                sandbox, argv_for(()), action=action, timeout_s=REMOTE_TIMEOUT_S, env=REMOTE_ENV
            )
            return _text(result)
        overrides = credential_overrides(url, credential.username)
        async with ephemeral_askpass(self._driver, self._ref(sandbox), credential, url) as askpass:
            hidden = (credential.token, askpass.path)
            result = await self._run(
                sandbox,
                argv_for(overrides),
                action=action,
                timeout_s=REMOTE_TIMEOUT_S,
                env={**REMOTE_ENV, **ISOLATED_CONFIG_ENV, **askpass.env},
                hidden=hidden,
            )
            return _text(result, hidden)

    async def _remote_url(self, sandbox: Sandbox, repo: str, remote: str, action: str) -> str:
        """The url the repository says ``remote`` is: ``remote`` itself or its config.

        Sandbox code controls this value, so it is only compared with the caller's url.
        """
        if ":" in remote:  # ref names cannot contain ':', so this is a url
            return remote
        push = ["--push"] if action == "push" else []
        argv = [GIT, "-C", repo, *HARDENING_OVERRIDES, "remote", "get-url", *push, remote]
        result = await self._run(
            sandbox, argv, action="remote-url", env={**REMOTE_ENV, **ISOLATED_CONFIG_ENV}
        )
        return result.stdout.decode(errors="replace").strip()

    # -- operations ----------------------------------------------------------------------

    async def clone(
        self,
        uow: UnitOfWorkPort,
        actor: Actor,
        sandbox_id: str,
        url: str,
        path: str,
        *,
        branch: str | None = None,
        depth: int | None = None,
        credential: Credential | None = None,
    ) -> GitOutput:
        target = normalize_path(path)
        _check_arg(url, "url")
        _check_arg(branch, "branch")
        if depth is not None and depth < 1:
            raise Unprocessable("depth must be at least 1")
        if credential is not None:
            validate_credential(credential)
            remote_base(url)  # fail before anything runs when the url is not http(s)
        details = {
            "url": strip_userinfo(url),
            "path": target,
            "branch": branch,
            "depth": depth,
            "authenticated": credential is not None,
        }
        sandbox = await self._begin(uow, actor, sandbox_id, "toolbox.git.clone", details)

        def argv_for(overrides: Sequence[str]) -> list[str]:
            return clone_argv(url, target, branch=branch, depth=depth, overrides=overrides)

        output = await self._remote(
            sandbox, argv_for, action="clone", credential=credential, url=url
        )
        return GitOutput(target, output)

    async def status(
        self, uow: UnitOfWorkPort, actor: Actor, sandbox_id: str, path: str
    ) -> RepoStatus:
        repo = normalize_path(path)
        sandbox = await self._begin(uow, actor, sandbox_id, "toolbox.git.status", {"path": repo})
        argv = [GIT, "-C", repo, "status", "--porcelain=v1", "--branch", "-z"]
        result = await self._run(sandbox, argv, action="status")
        return parse_status(result.stdout)

    async def add(
        self, uow: UnitOfWorkPort, actor: Actor, sandbox_id: str, path: str, files: Sequence[str]
    ) -> GitOutput:
        repo = normalize_path(path)
        names = _check_files(files)
        details = {"path": repo, "files": names}
        sandbox = await self._begin(uow, actor, sandbox_id, "toolbox.git.add", details)
        result = await self._run(sandbox, [GIT, "-C", repo, "add", "--", *names], action="add")
        return GitOutput(repo, _text(result))

    async def commit(
        self,
        uow: UnitOfWorkPort,
        actor: Actor,
        sandbox_id: str,
        path: str,
        message: str,
        *,
        author_name: str | None = None,
        author_email: str | None = None,
    ) -> str:
        """Commit the index and return the new ``HEAD`` sha."""
        repo = normalize_path(path)
        if not message or "\x00" in message:
            raise Unprocessable("message must be non-empty and free of NUL bytes")
        _check_text(author_name, "author_name")
        _check_text(author_email, "author_email")
        details = {
            "path": repo,
            "message_bytes": len(message.encode()),
            "author_configured": author_name is not None or author_email is not None,
        }
        sandbox = await self._begin(uow, actor, sandbox_id, "toolbox.git.commit", details)
        argv = commit_argv(repo, message, author_name=author_name, author_email=author_email)
        result = await self._exec(sandbox, argv, action="commit", env=COMMIT_LOCALE_ENV)
        if result.exit_code != 0:
            if is_missing_identity(result):
                field = _missing_identity_field(author_name, author_email)
                raise Unprocessable(MISSING_IDENTITY_MESSAGE, details={"field": field})
            raise _failure("commit", result, ())
        head = await self._run(sandbox, [GIT, "-C", repo, "rev-parse", "HEAD"], action="rev-parse")
        return head.stdout.decode(errors="replace").strip()

    async def push(
        self,
        uow: UnitOfWorkPort,
        actor: Actor,
        sandbox_id: str,
        path: str,
        *,
        remote: str = "origin",
        branch: str | None = None,
        credential: Credential | None = None,
        remote_url: str | None = None,
    ) -> GitOutput:
        target = _SyncTarget(remote, branch, credential, remote_url)
        return await self._sync("push", uow, actor, sandbox_id, path, target)

    async def pull(
        self,
        uow: UnitOfWorkPort,
        actor: Actor,
        sandbox_id: str,
        path: str,
        *,
        remote: str = "origin",
        branch: str | None = None,
        credential: Credential | None = None,
        remote_url: str | None = None,
    ) -> GitOutput:
        target = _SyncTarget(remote, branch, credential, remote_url)
        return await self._sync("pull", uow, actor, sandbox_id, path, target)

    async def _sync(
        self,
        action: str,
        uow: UnitOfWorkPort,
        actor: Actor,
        sandbox_id: str,
        path: str,
        target: "_SyncTarget",
    ) -> GitOutput:
        """``push`` or ``pull`` of ``remote`` (and ``branch`` when given).

        With ``remote_url`` the repository's remote must name the same scheme and host
        (422 otherwise) and git is handed the caller's url, so sandbox config cannot
        redirect where the credential goes. A credential requires ``remote_url``.
        """
        repo = normalize_path(path)
        bound = target.validated()
        details: dict[str, Any] = {
            "path": repo,
            "remote": strip_userinfo(target.remote),
            "branch": target.branch,
            "authenticated": target.credential is not None,
        }
        if bound is not None:
            details["remote_url"] = bound
        sandbox = await self._begin(uow, actor, sandbox_id, f"toolbox.git.{action}", details)
        if bound is not None:
            resolved = await self._remote_url(sandbox, repo, target.remote, action)
            require_same_target(resolved, bound)

        def argv_for(overrides: Sequence[str]) -> list[str]:
            refs = [] if target.branch is None else [target.branch]
            where = target.remote if bound is None else bound
            return [GIT, "-C", repo, *overrides, action, where, *refs]

        output = await self._remote(
            sandbox, argv_for, action=action, credential=target.credential, url=bound or ""
        )
        return GitOutput(repo, output)


@dataclass(frozen=True, slots=True)
class _SyncTarget:
    """Where a push or pull goes: remote name or url, branch, credential, caller's url."""

    remote: str
    branch: str | None
    credential: Credential | None
    remote_url: str | None

    def validated(self) -> str | None:
        """Check every field; return the caller's url without userinfo, if one was given."""
        _check_arg(self.remote, "remote")
        _check_arg(self.branch, "branch")
        if self.credential is not None:
            validate_credential(self.credential)
            if self.remote_url is None:
                raise Unprocessable(
                    "remote_url is required with a credential", details={"field": "remote_url"}
                )
        if self.remote_url is None:
            return None
        _check_arg(self.remote_url, "remote_url")
        remote_base(self.remote_url)  # 422 before anything runs when it is not http(s)
        return strip_userinfo(self.remote_url)
