"""Asynchronous client (same surface as :class:`sandfort_sdk.client.Client`)."""

import asyncio
import logging
import time
from collections.abc import AsyncIterator, Coroutine, Sequence
from datetime import datetime
from types import TracebackType
from typing import Any, Self

from sandfort_sdk._create_cleanup import (
    CreateClock,
    acheck_name,
    adelete_after_timeout,
    cleanup_applies,
    create_body,
    finish_tasks,
    poll_pause,
    poll_window,
    wait_expired,
)
from sandfort_sdk._requests import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_POLL_INTERVAL_S,
    DEFAULT_WAIT_TIMEOUT_S,
    ISOLATION_PATH,
    SANDBOXES_PATH,
    IdentifiedPage,
    SortOrder,
    idempotency_headers,
    list_params,
    sandbox_path,
    wait_params,
)
from sandfort_sdk._transport import DEFAULT_TIMEOUT_S, AsyncTransport, Reply
from sandfort_sdk.api_keys import ApiKeyInfo, AsyncApiKeys, CreatedApiKey, RevokedApiKey
from sandfort_sdk.audit import AsyncAudit
from sandfort_sdk.client import (
    API_KEYS_PATH,
    ERROR_STATE,
    ID_PREFIX,
    STATUS_PATH,
    ApiKeyListStatus,
    api_key_infos,
    api_key_list_params,
    select_named,
    settled,
    start_timeout_error,
)
from sandfort_sdk.egress import aset_allowlist
from sandfort_sdk.exceptions import (
    InvalidResponseError,
    RequestTimedOut,
    SandboxFailedError,
    SandfortSDKError,
)
from sandfort_sdk.handles import check_wait_budget, create_timeout_error, with_create_request_id
from sandfort_sdk.members import SSO_EXCHANGE_PATH, AsyncMembers, sso_exchange_body, sso_session
from sandfort_sdk.models import IsolationInfo, Resources, SandboxInfo, SsoSession, StatusInfo
from sandfort_sdk.quota import AsyncQuota
from sandfort_sdk.sandbox import AsyncSandbox
from sandfort_sdk.snapshots import AsyncSnapshots, PathArg
from sandfort_sdk.stop_causes import StopCause
from sandfort_sdk.usage import AsyncUsage
from sandfort_sdk.volumes import AsyncVolumes, VolumeMount
from sandfort_sdk.webhooks import AsyncWebhooks

logger = logging.getLogger(__name__)

# Longest ``aclose`` waits for this client's pending cancellation cleanups.
CLEANUP_WAIT_S = 10.0

# The event loop only weakly references tasks: hold the cleanup tasks until they finish.
_BACKGROUND_TASKS: set[asyncio.Task[Any]] = set()


def _spawn(coro: Coroutine[Any, Any, Any]) -> asyncio.Task[Any]:
    task = asyncio.get_running_loop().create_task(coro)
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)
    return task


class AsyncClient:
    """``max_retries``: as for :class:`sandfort_sdk.client.Client` (0 disables)."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        self._transport = AsyncTransport(base_url, api_key, timeout, max_retries=max_retries)
        self._members = AsyncMembers(self._transport)
        self._snapshots = AsyncSnapshots(self._transport)
        self._volumes = AsyncVolumes(self._transport)
        self._api_keys = AsyncApiKeys(self._transport)
        self._audit = AsyncAudit(self._transport)
        self._webhooks = AsyncWebhooks(self._transport)
        self._usage = AsyncUsage(self._transport)
        self._quota = AsyncQuota(self._transport)
        self._cleanups: set[asyncio.Task[Any]] = set()

    @property
    def quota(self) -> AsyncQuota:
        """The quota view of this key: the org snapshot, or a scoped key's own cap and count."""
        return self._quota

    @property
    def usage(self) -> AsyncUsage:
        """The org usage report (totals, or grouped by sandbox or label; ``get``, ``iter``)."""
        return self._usage

    @property
    def webhooks(self) -> AsyncWebhooks:
        """Webhook endpoints, delivery history and redelivery."""
        return self._webhooks

    @property
    def audit(self) -> AsyncAudit:
        """Audit events (list, iterate, verify the hash chain, export)."""
        return self._audit

    @property
    def members(self) -> AsyncMembers:
        """Organization members (add, list, change role, remove)."""
        return self._members

    @property
    def snapshots(self) -> AsyncSnapshots:
        """Snapshots and declarative image builds."""
        return self._snapshots

    @property
    def volumes(self) -> AsyncVolumes:
        return self._volumes

    async def exchange_sso(self, id_token: str) -> SsoSession:
        """As :meth:`sandfort_sdk.client.Client.exchange_sso` (any 401 is a refusal)."""
        body = sso_exchange_body(id_token)
        return sso_session(await self._transport.request("POST", SSO_EXCHANGE_PATH, json=body))

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Let pending cancellation cleanups finish (bounded), then close the transport."""
        await self._finish_cleanups()
        await self._transport.aclose()

    async def _finish_cleanups(self) -> None:
        """Wait up to ``CLEANUP_WAIT_S`` for this client's cleanup tasks; never raises."""
        # A live set: finishing a create request spawns the delete that follows it.
        await finish_tasks(self._cleanups, CLEANUP_WAIT_S)

    def _track_cleanup(self, task: asyncio.Task[Any]) -> None:
        self._cleanups.add(task)
        task.add_done_callback(self._cleanups.discard)

    async def create_sandbox(
        self,
        *,
        name: str | None = None,
        snapshot: str | None = None,
        resources: Resources | None = None,
        env: dict[str, str] | None = None,
        labels: dict[str, str] | None = None,
        block_network: bool | None = None,
        auto_stop_minutes: int | None = None,
        auto_delete_minutes: int | None = None,
        public: bool | None = None,
        mounts: Sequence[VolumeMount | tuple[str, str]] | None = None,
        isolation: str | None = None,
        inherit_resources: bool = False,
        idempotency_key: str | None = None,
        wait: bool = True,
        wait_timeout_s: float = DEFAULT_WAIT_TIMEOUT_S,
        poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
        delete_on_cancel: bool = True,
        delete_on_failure: bool = True,
    ) -> AsyncSandbox:
        """``mounts``, ``isolation``, ``inherit_resources``, ``idempotency_key``: as
        :meth:`.client.Client.create_sandbox`.

        ``delete_on_cancel``: when the awaiting task is cancelled, the sandbox must not leak.
        Cancelled during the create request, it still runs to the end (shielded) and the sandbox
        it made is then deleted in the background; cancelled while waiting for ``started``, the
        known sandbox is deleted in the background. Best effort: a failure is logged, and
        ``CancelledError`` is always re-raised. ``False`` leaves the sandbox alone (to adopt it);
        the id of a sandbox whose create request was in flight is then lost.

        ``delete_on_failure``: when waiting ends in the ``error`` state, the sandbox is deleted
        before :class:`SandboxFailedError` is raised (``deleted`` is True and the message says
        so). ``False`` keeps it; so does a delete that fails (the original error is raised).

        ``wait_timeout_s``: with ``wait=True`` one deadline, ``wait_timeout_s`` from just before
        the create request is sent, bounds the whole blocking create: each attempt's connect,
        write, read and pool timeouts are at most the time left, none starts after the deadline,
        a pause before a resend counts (one past it is not taken), and the wait for ``started``
        long-polls only for the time left. The name check runs before the deadline starts. A
        request timeout raises :class:`SandboxTimeoutError` naming the sandbox (``deleted`` True
        and its id when the cleanup below deleted it; else the create may still finish, and with a
        key, resending the same call returns it); a wait that runs out carries ``sandbox_id``.

        Create timeout cleanup (``wait``, ``delete_on_failure`` and a ``name``): the name is
        looked up once before the request. After a timeout once any attempt may have been sent
        (never when none was written), the sandbox found under the name is deleted, once, only
        when the name was free before and its ``created_at`` is no earlier than just before the
        request less ``CLOCK_SKEW_ALLOWANCE_S`` (60 s); any other is left alone (logged).
        """
        check_wait_budget(wait, wait_timeout_s)
        body = create_body(
            name=name,
            snapshot=snapshot,
            resources=resources,
            env=env,
            labels=labels,
            block_network=block_network,
            auto_stop_minutes=auto_stop_minutes,
            auto_delete_minutes=auto_delete_minutes,
            public=public,
            mounts=mounts,
            isolation=isolation,
            inherit_resources=inherit_resources,
        )
        headers = idempotency_headers(idempotency_key)
        check = None
        if name and cleanup_applies(wait, delete_on_failure, name):
            check = await acheck_name(name, self.get)
        clock = CreateClock.start(wait_timeout_s, time.monotonic()) if wait else None
        deadline = None if clock is None else clock.deadline
        try:
            reply = await self._post_create(body, headers, deadline, delete_on_cancel)
        except RequestTimedOut as timeout:
            if clock is None:
                raise
            sent = check if timeout.request_sent else None
            removed = await adelete_after_timeout(sent, clock.posted_after, self.get, self.delete)
            raise create_timeout_error(name, idempotency_key, wait_timeout_s, removed) from timeout
        info = SandboxInfo.from_payload(reply.data)
        if clock is not None:
            try:
                info = await self._wait_started(reply, clock.deadline, poll_interval_s)
            except asyncio.CancelledError:
                if delete_on_cancel:
                    self._track_cleanup(_spawn(self._delete_quietly(info.id)))
                raise
            except SandboxFailedError as exc:
                deleted = await self._delete_failed(exc) if delete_on_failure else None
                if deleted is None:
                    raise
                raise deleted from exc
        return with_create_request_id(AsyncSandbox(info, self._transport), reply.request_id)

    async def _delete_failed(self, failure: SandboxFailedError) -> SandboxFailedError | None:
        """Delete the sandbox of an ``error`` failure; the marked error, or None to keep it."""
        if failure.state != ERROR_STATE:
            return None
        try:
            await self.delete(failure.sandbox_id)
        except SandfortSDKError:
            logger.warning("cannot delete failed sandbox %s", failure.sandbox_id, exc_info=True)
            return None
        return failure.as_deleted()

    async def status(self) -> StatusInfo:
        """Version, build, start time and the operator notice (the route needs no key)."""
        return StatusInfo.from_payload((await self._transport.request("GET", STATUS_PATH)).data)

    async def create_api_key(
        self,
        name: str,
        scopes: Sequence[str],
        *,
        sandbox_labels: dict[str, str] | None = None,
        max_sandboxes: int | None = None,
        expires_at: datetime | None = None,
        shared_volume_labels: dict[str, str] | None = None,
    ) -> CreatedApiKey:
        """As :meth:`sandfort_sdk.client.Client.create_api_key`; the plaintext key is shown once."""
        return await self._api_keys.create(
            name,
            scopes,
            sandbox_labels=sandbox_labels,
            max_sandboxes=max_sandboxes,
            expires_at=expires_at,
            shared_volume_labels=shared_volume_labels,
        )

    async def list_api_keys(
        self, *, status: ApiKeyListStatus | None = None
    ) -> tuple[ApiKeyInfo, ...]:
        """The org's API keys; ``status`` ("active" or "revoked") filters on the server.

        Any other string raises ``ValueError`` before a request is sent.
        """
        params = api_key_list_params(status)
        return api_key_infos(await self._transport.request("GET", API_KEYS_PATH, params=params))

    async def revoke_api_key(self, key_id: str, *, cascade: bool = False) -> RevokedApiKey:
        """Revoke a key; ``cascade=True`` also revokes its live descendants."""
        return await self._api_keys.revoke(key_id, cascade=cascade)

    async def export_snapshot(self, snapshot_id: str, path: PathArg) -> int:
        """Stream a ready snapshot to ``path`` as an image tar; returns the bytes written."""
        return await self._snapshots.export(snapshot_id, path)

    async def _post_create(
        self,
        body: dict[str, Any],
        headers: dict[str, str] | None,
        deadline: float | None,
        shielded: bool,
    ) -> Reply:
        request = self._transport.request(
            "POST", SANDBOXES_PATH, json=body, headers=headers, deadline=deadline
        )
        if not shielded:
            return await request
        post = _spawn(request)
        try:
            reply: Reply = await asyncio.shield(post)
        except asyncio.CancelledError:
            post.add_done_callback(self._delete_when_created)
            self._track_cleanup(post)
            raise
        return reply

    def _delete_when_created(self, post: asyncio.Task[Any]) -> None:
        """Done-callback of an orphaned create request: delete the sandbox it made."""
        if post.cancelled() or post.exception() is not None:
            return  # nothing was created (``exception()`` also marks the error as retrieved)
        try:
            sandbox_id = SandboxInfo.from_payload(post.result().data).id
        except Exception:
            logger.warning("cannot read the sandbox id of a cancelled create", exc_info=True)
            return
        self._track_cleanup(_spawn(self._delete_quietly(sandbox_id)))

    async def _delete_quietly(self, sandbox_id: str) -> None:
        try:
            await self.delete(sandbox_id)
        except Exception:
            logger.warning("cleanup delete of sandbox %s failed", sandbox_id, exc_info=True)

    async def isolation(self) -> IsolationInfo:
        """The isolation tiers this server offers and the default a create gets."""
        reply = await self._transport.request("GET", ISOLATION_PATH)
        return IsolationInfo.from_payload(reply.data)

    async def list_sandboxes(
        self,
        *,
        state: str | None = None,
        labels: dict[str, str] | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        include_destroyed: bool = False,
        order: SortOrder | None = None,
        stop_cause: StopCause | None = None,
    ) -> IdentifiedPage[AsyncSandbox]:
        """``include_destroyed``: also list ``destroyed`` tombstones; sent only when true.
        ``order``: a :data:`~sandfort_sdk.SortOrder` (``"asc"``/``"desc"``); sent only if given.
        ``stop_cause``: only sandboxes with this stop cause, one of the
        :data:`~sandfort_sdk.StopCause` literal values; sent only if given."""
        params = list_params(state, labels, cursor, limit, include_destroyed, order, stop_cause)
        reply = await self._transport.request("GET", SANDBOXES_PATH, params=params)
        if not isinstance(reply.data, list):
            raise InvalidResponseError("expected a list of sandboxes")
        transport = self._transport
        items = tuple(AsyncSandbox(SandboxInfo.from_payload(d), transport) for d in reply.data)
        return IdentifiedPage(items, reply.next_cursor, reply.request_id)

    async def iter_sandboxes(
        self,
        *,
        state: str | None = None,
        labels: dict[str, str] | None = None,
        limit: int | None = None,
        include_destroyed: bool = False,
        order: SortOrder | None = None,
        stop_cause: StopCause | None = None,
    ) -> AsyncIterator[AsyncSandbox]:
        """Every page of :meth:`list_sandboxes`; ``order`` and ``stop_cause`` as there."""
        cursor: str | None = None
        while True:
            page = await self.list_sandboxes(
                state=state, labels=labels, cursor=cursor, limit=limit,
                include_destroyed=include_destroyed, order=order, stop_cause=stop_cause,
            )  # fmt: skip
            for item in page.items:
                yield item
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    async def get(self, ref: str) -> AsyncSandbox:
        """Fetch by id or live name; rules and errors as :meth:`sandfort_sdk.client.Client.get`."""
        if ref.startswith(ID_PREFIX):
            reply = await self._fetch(ref)
            return AsyncSandbox(SandboxInfo.from_payload(reply.data), self._transport)
        infos: list[SandboxInfo] = []
        cursor: str | None = None
        while True:
            page = await self.list_sandboxes(cursor=cursor)
            infos += [sandbox.info for sandbox in page]
            if (cursor := page.next_cursor) is None:
                return AsyncSandbox(select_named(ref, infos, page.request_id), self._transport)

    get_sandbox = get  # documented alias, as on the sync client

    async def start(
        self,
        sandbox_id: str,
        *,
        wait: bool = False,
        wait_timeout_s: float | None = None,
        poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
    ) -> AsyncSandbox:
        """Start a stopped sandbox; ``wait``, ``wait_timeout_s`` and ``poll_interval_s`` behave
        as in :meth:`sandfort_sdk.client.Client.start` (one deadline before the POST, the POST
        sent under it, the long-poll for ``started`` under what is left; no effect without
        ``wait``). A ``wait_timeout_s`` that is not a finite number greater than 0 raises
        :class:`ValueError` when ``wait`` is set.
        """
        check_wait_budget(wait, wait_timeout_s)
        path = sandbox_path(sandbox_id, "/start")
        if not wait:
            return await self._act("POST", path)
        budget = DEFAULT_WAIT_TIMEOUT_S if wait_timeout_s is None else wait_timeout_s
        clock = CreateClock.start(budget, time.monotonic())
        try:
            reply = await self._transport.request("POST", path, deadline=clock.deadline)
        except RequestTimedOut as timeout:
            raise start_timeout_error(sandbox_id, budget) from timeout
        info = await self._wait_started(reply, clock.deadline, poll_interval_s)
        return AsyncSandbox(info, self._transport)

    async def stop(self, sandbox_id: str) -> AsyncSandbox:
        return await self._act("POST", sandbox_path(sandbox_id, "/stop"))

    async def delete(self, sandbox_id: str) -> AsyncSandbox:
        return await self._act("DELETE", sandbox_path(sandbox_id))

    async def set_egress_allowlist(self, sandbox_id: str, entries: Sequence[str]) -> AsyncSandbox:
        """Replace the egress allowlist of a sandbox created with one; ``[]`` blocks all hosts.

        Entries are sent as given and validated by the server. The server stores the list at
        once and the egress proxy picks it up within its cache window, so the change is not
        instant. Errors: :class:`Forbidden` (operator policy), :class:`InvalidState` (the
        sandbox has no allowlist to replace, was created with an empty one while the network
        blocks all hosts, or needs ``reset`` first), :class:`Unprocessable` or
        :class:`ValidationFailed` (invalid entries).
        """
        return await aset_allowlist(self._transport, sandbox_id, entries)

    async def _act(self, method: str, path: str) -> AsyncSandbox:
        reply = await self._transport.request(method, path)
        return AsyncSandbox(SandboxInfo.from_payload(reply.data), self._transport)

    async def _fetch(
        self, sandbox_id: str, long_poll_s: float | None = None, deadline: float | None = None
    ) -> Reply:
        params: dict[str, Any] | None = None if long_poll_s is None else wait_params(long_poll_s)
        return await self._transport.request(
            "GET", sandbox_path(sandbox_id), params=params, server_wait_s=long_poll_s,
            deadline=deadline,
        )  # fmt: skip

    async def _wait_started(
        self, reply: Reply, deadline: float, poll_interval_s: float
    ) -> SandboxInfo:
        while True:  # every poll and pause ends by ``deadline`` (monotonic)
            info, ready = settled(reply)
            if ready:
                return info
            window = poll_window(info, deadline, time.monotonic())
            try:
                reply = await self._fetch(info.id, window, deadline)
            except RequestTimedOut as timeout:
                raise wait_expired(info) from timeout
            if not settled(reply)[1]:
                await asyncio.sleep(poll_pause(deadline, time.monotonic(), poll_interval_s))
