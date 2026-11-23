"""Sandbox facades: a sandbox record bound to the transport that fetched it.

Toolboxes hang off the facade: ``sandbox.fs``, ``sandbox.git``, ``sandbox.process``,
``sandbox.pty`` and ``sandbox.code_contexts`` (persistent Python kernels). ``process_exec`` and
``code_run`` remain as shortcuts to ``sandbox.process``.
"""

from collections.abc import Sequence
from types import TracebackType
from typing import Self

from sandfort_sdk._requests import DEFAULT_EXEC_TIMEOUT_S, DEFAULT_POLL_INTERVAL_S, sandbox_path
from sandfort_sdk._transport import AsyncTransport, SyncTransport
from sandfort_sdk.code_contexts import AsyncCodeContexts, CodeContexts
from sandfort_sdk.fs import AsyncFs, Fs
from sandfort_sdk.git import AsyncGit, Git
from sandfort_sdk.handles import SandboxFields, delete_error_is_ignored
from sandfort_sdk.models import ExecResult, PreviewInfo, SandboxInfo
from sandfort_sdk.process import AsyncProcess, Process
from sandfort_sdk.pty import AsyncPty, Pty


def _preview_body(port: int, ttl_seconds: int | None) -> dict[str, int]:
    body = {"port": port}
    if ttl_seconds is not None:
        body["ttl_seconds"] = ttl_seconds
    return body


class Sandbox(SandboxFields):
    """Synchronous handle exposing the toolboxes of one sandbox.

    A context manager: leaving the ``with`` block deletes the sandbox (see ``__exit__``).
    """

    def __init__(self, info: SandboxInfo, transport: SyncTransport) -> None:
        self.info = info
        self._transport = transport
        self.fs = Fs(info.id, transport)
        self.git = Git(info.id, transport)
        self.process = Process(info.id, transport)
        self.pty = Pty(info.id, transport)
        self.code_contexts = CodeContexts(info.id, transport)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Delete the sandbox. A delete error is raised, except for a sandbox that is gone
        already (ignored) and while an exception is propagating (logged, so it is not masked)."""
        try:
            self.delete()
        except Exception as error:
            if not delete_error_is_ignored(error, exc_type is not None, self.id):
                raise

    def refresh(self) -> Self:
        """Fetch the sandbox again and replace ``info`` with the fresh record."""
        return self._apply("GET", sandbox_path(self.id))

    def start(
        self,
        *,
        wait: bool = False,
        wait_timeout_s: float | None = None,
        poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
    ) -> Self:
        """Start the sandbox and replace ``info`` with the reply.

        Without ``wait`` this sends the one start request, as before. ``wait``,
        ``wait_timeout_s`` and ``poll_interval_s`` are passed to
        :meth:`sandfort_sdk.client.Client.start` over this handle's transport: one deadline
        bounds the start request and the long-poll for ``started``; a wait that runs out raises
        :class:`SandboxTimeoutError`, a sandbox that ends in ``error`` raises
        :class:`SandboxFailedError`, and with ``wait=True`` a ``wait_timeout_s`` that is not a
        finite number greater than 0 raises :class:`ValueError` before any request.
        """
        if not wait:
            return self._apply("POST", sandbox_path(self.id, "/start"))
        from sandfort_sdk.client import Client  # deferred: client imports this module

        owner = Client.__new__(Client)  # bound to this transport; ``start`` needs nothing else
        owner._transport = self._transport
        started = owner.start(
            self.id, wait=True, wait_timeout_s=wait_timeout_s, poll_interval_s=poll_interval_s
        )
        self.info = started.info
        return self

    def stop(self) -> Self:
        return self._apply("POST", sandbox_path(self.id, "/stop"))

    def reset(self) -> Self:
        """Replace the container with a fresh one from the same image and spec.

        The id, name, labels and volumes are kept; everything written to the old container is
        gone. Works on a started or stopped sandbox and leaves it in the same state.
        """
        return self._apply("POST", sandbox_path(self.id, "/reset"))

    def delete(self) -> Self:
        return self._apply("DELETE", sandbox_path(self.id))

    def _apply(self, method: str, path: str) -> Self:
        reply = self._transport.request(method, path)
        self.info = SandboxInfo.from_payload(reply.data)
        return self

    def preview(self, port: int, *, ttl_seconds: int | None = None) -> PreviewInfo:
        """Mint a preview token for ``port`` and return its URL (server default ttl when None)."""
        path = sandbox_path(self.id, "/preview-tokens")
        reply = self._transport.request("POST", path, json=_preview_body(port, ttl_seconds))
        return PreviewInfo.from_payload(reply.data)

    def process_exec(
        self,
        command: str | Sequence[str] | None = None,
        *,
        argv: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_s: int = DEFAULT_EXEC_TIMEOUT_S,
        stdin: str | None = None,
        idempotency_key: str | None = None,
    ) -> ExecResult:
        return self.process.exec(
            command, argv=argv, cwd=cwd, env=env, timeout_s=timeout_s, stdin=stdin,
            idempotency_key=idempotency_key,
        )  # fmt: skip

    def code_run(
        self,
        language: str,
        code: str,
        *,
        argv: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_s: int = DEFAULT_EXEC_TIMEOUT_S,
        idempotency_key: str | None = None,
    ) -> ExecResult:
        return self.process.code_run(
            language, code, argv=argv, cwd=cwd, env=env, timeout_s=timeout_s,
            idempotency_key=idempotency_key,
        )  # fmt: skip


class AsyncSandbox(SandboxFields):
    """Asynchronous handle exposing the toolboxes of one sandbox.

    An async context manager: leaving the ``async with`` block deletes the sandbox.
    """

    def __init__(self, info: SandboxInfo, transport: AsyncTransport) -> None:
        self.info = info
        self._transport = transport
        self.fs = AsyncFs(info.id, transport)
        self.git = AsyncGit(info.id, transport)
        self.process = AsyncProcess(info.id, transport)
        self.pty = AsyncPty(info.id, transport)
        self.code_contexts = AsyncCodeContexts(info.id, transport)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Delete the sandbox. A delete error is raised, except for a sandbox that is gone
        already (ignored) and while an exception is propagating (logged, so it is not masked)."""
        try:
            await self.delete()
        except Exception as error:
            if not delete_error_is_ignored(error, exc_type is not None, self.id):
                raise

    async def refresh(self) -> Self:
        """Fetch the sandbox again and replace ``info`` with the fresh record."""
        return await self._apply("GET", sandbox_path(self.id))

    async def start(
        self,
        *,
        wait: bool = False,
        wait_timeout_s: float | None = None,
        poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
    ) -> Self:
        """Start the sandbox and replace ``info`` with the reply.

        Without ``wait`` this sends the one start request, as before. ``wait``,
        ``wait_timeout_s`` and ``poll_interval_s`` are passed to
        :meth:`sandfort_sdk.async_client.AsyncClient.start` over this handle's transport, with
        the same deadline, errors and :class:`ValueError` for an unusable budget as
        :meth:`Sandbox.start`.
        """
        if not wait:
            return await self._apply("POST", sandbox_path(self.id, "/start"))
        from sandfort_sdk.async_client import AsyncClient  # deferred: it imports this module

        owner = AsyncClient.__new__(AsyncClient)  # bound to this transport; see Sandbox.start
        owner._transport = self._transport
        started = await owner.start(
            self.id, wait=True, wait_timeout_s=wait_timeout_s, poll_interval_s=poll_interval_s
        )
        self.info = started.info
        return self

    async def stop(self) -> Self:
        return await self._apply("POST", sandbox_path(self.id, "/stop"))

    async def reset(self) -> Self:
        """Replace the container with a fresh one from the same image and spec.

        The id, name, labels and volumes are kept; everything written to the old container is
        gone. Works on a started or stopped sandbox and leaves it in the same state.
        """
        return await self._apply("POST", sandbox_path(self.id, "/reset"))

    async def delete(self) -> Self:
        return await self._apply("DELETE", sandbox_path(self.id))

    async def _apply(self, method: str, path: str) -> Self:
        reply = await self._transport.request(method, path)
        self.info = SandboxInfo.from_payload(reply.data)
        return self

    async def preview(self, port: int, *, ttl_seconds: int | None = None) -> PreviewInfo:
        """Mint a preview token for ``port`` and return its URL (server default ttl when None)."""
        path = sandbox_path(self.id, "/preview-tokens")
        reply = await self._transport.request("POST", path, json=_preview_body(port, ttl_seconds))
        return PreviewInfo.from_payload(reply.data)

    async def process_exec(
        self,
        command: str | Sequence[str] | None = None,
        *,
        argv: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_s: int = DEFAULT_EXEC_TIMEOUT_S,
        stdin: str | None = None,
        idempotency_key: str | None = None,
    ) -> ExecResult:
        return await self.process.exec(
            command, argv=argv, cwd=cwd, env=env, timeout_s=timeout_s, stdin=stdin,
            idempotency_key=idempotency_key,
        )  # fmt: skip

    async def code_run(
        self,
        language: str,
        code: str,
        *,
        argv: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_s: int = DEFAULT_EXEC_TIMEOUT_S,
        idempotency_key: str | None = None,
    ) -> ExecResult:
        return await self.process.code_run(
            language, code, argv=argv, cwd=cwd, env=env, timeout_s=timeout_s,
            idempotency_key=idempotency_key,
        )  # fmt: skip
