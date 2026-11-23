"""Synchronous client."""

import logging
import time
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime
from types import TracebackType
from typing import Any, Literal, Self

from sandfort_sdk._create_cleanup import (
    CreateClock,
    check_name,
    cleanup_applies,
    create_body,
    delete_after_timeout,
    is_ready,
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
from sandfort_sdk._transport import DEFAULT_TIMEOUT_S, Reply, SyncTransport
from sandfort_sdk.api_keys import ApiKeyInfo, ApiKeys, CreatedApiKey, RevokedApiKey
from sandfort_sdk.audit import Audit
from sandfort_sdk.exceptions import (
    AmbiguousSandboxName,
    InvalidResponseError,
    NotFound,
    RequestTimedOut,
    SandboxFailedError,
    SandboxTimeoutError,
    SandfortSDKError,
)
from sandfort_sdk.handles import check_wait_budget, create_timeout_error, with_create_request_id
from sandfort_sdk.members import SSO_EXCHANGE_PATH, Members, sso_exchange_body, sso_session
from sandfort_sdk.models import (
    IsolationInfo,
    Resources,
    SandboxInfo,
    SsoSession,
    StatusInfo,
    _as_list,
)
from sandfort_sdk.quota import Quota
from sandfort_sdk.sandbox import Sandbox
from sandfort_sdk.snapshots import PathArg, Snapshots
from sandfort_sdk.stop_causes import StopCause
from sandfort_sdk.usage import Usage
from sandfort_sdk.volumes import VolumeMount, Volumes, mounts_wire
from sandfort_sdk.webhooks import Webhooks

logger = logging.getLogger(__name__)

ID_PREFIX = "sbx_"
STATUS_PATH = "/v1/status"
DESTROYED_STATE = "destroyed"
ERROR_STATE = "error"
API_KEYS_PATH = "/v1/api-keys"
ApiKeyListStatus = Literal["active", "revoked"]
API_KEY_STATUSES: tuple[str, ...] = ("active", "revoked")


def api_key_list_params(status: str | None) -> dict[str, Any] | None:
    """The query for a key list: ``status`` when given, else none.

    Raises ``ValueError`` for any other string, before a request is made.
    """
    if status is None:
        return None
    if status not in API_KEY_STATUSES:
        raise ValueError(f"status must be one of {', '.join(API_KEY_STATUSES)}; got {status!r}")
    return {"status": status}


def api_key_infos(reply: Reply) -> tuple[ApiKeyInfo, ...]:
    """The keys in a list reply."""
    return tuple(ApiKeyInfo.from_payload(item) for item in _as_list(reply.data, "api keys"))


def select_named(ref: str, infos: Iterable[SandboxInfo], rid: str | None = None) -> SandboxInfo:
    """The live sandbox called ``ref``; shared by the sync and async ``get``.

    Several sandboxes may share a name (destroyed ones are ignored); those in the ``error``
    state lose against any other. No match raises :class:`NotFound`; a tie that remains raises
    :class:`AmbiguousSandboxName` with the candidate ids. ``rid``: the request id of the last
    list reply; the :class:`NotFound` carries it.
    """
    matches = [i for i in infos if i.name == ref and i.state != DESTROYED_STATE]
    if not matches:
        raise NotFound(f"no sandbox named '{ref}'", status_code=404, request_id=rid)
    candidates = [i for i in matches if i.state != ERROR_STATE] or matches
    if len(candidates) == 1:
        return candidates[0]
    raise AmbiguousSandboxName(ref, tuple((i.id, i.state) for i in candidates))


def start_timeout_error(sandbox_id: str, wait_timeout_s: float) -> SandboxTimeoutError:
    """The error of a start whose request outlived ``wait_timeout_s``."""
    return SandboxTimeoutError(
        f"starting sandbox {sandbox_id} did not finish within {wait_timeout_s:g} s; "
        "the start may still finish on the server",
        sandbox_id=sandbox_id,
    )


def settled(reply: Reply) -> tuple[SandboxInfo, bool]:
    """The reply's sandbox and whether it started; a failure carries the reply's request id."""
    info = SandboxInfo.from_payload(reply.data)
    try:
        return info, is_ready(info)
    except SandboxFailedError as failed:
        failed.request_id = reply.request_id
        raise


class Client:
    """``max_retries``: resends of a call that is safe to repeat (0 disables).

    GET, HEAD, DELETE and a POST that carries an ``Idempotency-Key`` (``create_sandbox``
    with ``idempotency_key``) are resent on 429 (after ``Retry-After``, at most 30 s), 503
    and a connection or timeout error (after 0.5 s, 1 s, 2 s, ... with full jitter: a random
    pause between half and all of that delay). ``Retry-After`` may be seconds or an HTTP-date.
    Any other call (a POST without a key) is resent only after a 429 ``RATE_LIMITED``: the
    server did not process it. A 429 ``QUOTA_EXCEEDED`` is never resent (a quota does not
    free itself). A POST carrying an
    ``Idempotency-Key`` is also resent on a 409 ``in_progress`` (the first create is still
    running). Streams are never resent. The last attempt's error is raised as is.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        self._transport = SyncTransport(base_url, api_key, timeout, max_retries=max_retries)
        self._members = Members(self._transport)
        self._snapshots = Snapshots(self._transport)
        self._volumes = Volumes(self._transport)
        self._api_keys = ApiKeys(self._transport)
        self._audit = Audit(self._transport)
        self._webhooks = Webhooks(self._transport)
        self._usage = Usage(self._transport)
        self._quota = Quota(self._transport)

    @property
    def quota(self) -> Quota:
        """The quota view of this key: the org snapshot, or a scoped key's own cap and count."""
        return self._quota

    @property
    def usage(self) -> Usage:
        """The org usage report (totals, or grouped by sandbox or label; ``get``, ``iter``)."""
        return self._usage

    @property
    def webhooks(self) -> Webhooks:
        """Webhook endpoints, delivery history and redelivery."""
        return self._webhooks

    @property
    def audit(self) -> Audit:
        """Audit events (list, iterate, verify the hash chain, export)."""
        return self._audit

    @property
    def members(self) -> Members:
        """Organization members (add, list, change role, remove)."""
        return self._members

    @property
    def snapshots(self) -> Snapshots:
        """Snapshots and declarative image builds."""
        return self._snapshots

    @property
    def volumes(self) -> Volumes:
        return self._volumes

    def exchange_sso(self, id_token: str) -> SsoSession:
        """Trade an OIDC identity token for a short-lived session (any 401 is a refusal).

        The route needs no authentication: the identity token is the credential, and the
        server ignores the client's api key header, so the call goes through as it is.
        """
        body = sso_exchange_body(id_token)
        return sso_session(self._transport.request("POST", SSO_EXCHANGE_PATH, json=body))

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._transport.close()

    def create_sandbox(
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
        egress_allowlist: Sequence[str] | None = None,
        isolation: str | None = None,
        idempotency_key: str | None = None,
        wait: bool = True,
        wait_timeout_s: float = DEFAULT_WAIT_TIMEOUT_S,
        poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
        delete_on_failure: bool = True,
    ) -> Sandbox:
        """``mounts``: ``(volume_id, mount_path)`` pairs or :class:`VolumeMount` (which adds
        ``read_only=True`` for a read-only mount), e.g. ``[VolumeMount(vid, "/data")]``.

        ``delete_on_failure``: when waiting ends in the ``error`` state, the sandbox is deleted
        before :class:`SandboxFailedError` is raised (``deleted`` is True and the message says
        so), so a failed create leaves no live error row. ``False`` keeps it for inspection;
        so does a delete that fails (then the original error is raised, ``deleted`` False).

        ``egress_allowlist``: host names the sandbox may reach (through the egress proxy);
        ``None`` leaves the field out and keeps the server's default egress.

        ``isolation``: tier to run on (``"container"``, ``"gvisor"`` or ``"microvm"``; the
        server answers 422 for one it does not offer); ``None`` leaves the field out and the
        server default applies.

        ``idempotency_key``: sent as the ``Idempotency-Key`` header. Retrying with the same
        key and the same arguments returns the same sandbox instead of creating another (the
        server marks the answer ``idempotent-replayed: true``); the same key with other
        arguments answers 422 ``IDEMPOTENCY_MISMATCH``. With a key the client also resends
        the create on its own after 429, 503 or a lost connection (see ``max_retries``).

        ``wait_timeout_s``: with ``wait=True`` one deadline, ``wait_timeout_s`` from just before
        the create request is sent, bounds the whole blocking create. Each attempt's connect,
        write, read and pool timeouts are at most the time left, none starts after the deadline,
        and a pause before a resend counts (one past the deadline is not taken and the error is
        raised); the wait for ``started`` long-polls only for the time left. The name
        check below runs before the deadline starts. When the request times out,
        :class:`SandboxTimeoutError` names the sandbox: with its ``sandbox_id`` (``deleted`` True)
        when the cleanup below deleted it, else saying the create may still finish (with a key,
        resending the same call returns it); a wait that runs out carries ``sandbox_id``, ``state``.

        Create timeout cleanup (``wait``, ``delete_on_failure`` and a ``name``): the name is
        looked up once before the request. After a timeout once any attempt may have been sent
        (never when none was written), the sandbox found under the name is deleted, in one logged
        try, only when the name was free before and its ``created_at`` is no earlier than just
        before the request less ``CLOCK_SKEW_ALLOWANCE_S`` (60 s); any other sandbox is left
        alone and a warning names it.
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
            mounts=None,
            egress_allowlist=egress_allowlist,
            isolation=isolation,
        )
        if mounts is not None:
            body["volumes"] = mounts_wire(mounts)
        headers = idempotency_headers(idempotency_key)
        check = None
        if name and cleanup_applies(wait, delete_on_failure, name):
            check = check_name(name, self.get)
        clock = CreateClock.start(wait_timeout_s, time.monotonic()) if wait else None
        try:
            reply = self._transport.request(
                "POST", SANDBOXES_PATH, json=body, headers=headers,
                deadline=None if clock is None else clock.deadline,
            )  # fmt: skip
        except RequestTimedOut as timeout:
            if clock is None:
                raise
            sent = check if timeout.request_sent else None
            removed = delete_after_timeout(sent, clock.posted_after, self.get, self.delete)
            raise create_timeout_error(name, idempotency_key, wait_timeout_s, removed) from timeout
        info = SandboxInfo.from_payload(reply.data)
        if clock is not None:
            try:
                info = self._wait_started(reply, clock.deadline, poll_interval_s)
            except SandboxFailedError as exc:
                deleted = self._delete_failed(exc) if delete_on_failure else None
                if deleted is None:
                    raise
                raise deleted from exc
        return with_create_request_id(Sandbox(info, self._transport), reply.request_id)

    def _delete_failed(self, failure: SandboxFailedError) -> SandboxFailedError | None:
        """Delete the sandbox of an ``error`` failure; the marked error, or None to keep it."""
        if failure.state != ERROR_STATE:
            return None
        try:
            self.delete(failure.sandbox_id)
        except SandfortSDKError:
            logger.warning("cannot delete failed sandbox %s", failure.sandbox_id, exc_info=True)
            return None
        return failure.as_deleted()

    def status(self) -> StatusInfo:
        """Version, build, start time and the operator notice (the route needs no key)."""
        return StatusInfo.from_payload(self._transport.request("GET", STATUS_PATH).data)

    def create_api_key(
        self,
        name: str,
        scopes: Sequence[str],
        *,
        sandbox_labels: dict[str, str] | None = None,
        max_sandboxes: int | None = None,
        expires_at: datetime | None = None,
        shared_volume_labels: dict[str, str] | None = None,
    ) -> CreatedApiKey:
        """Create an API key (needs ``api_keys:admin``); the plaintext ``key`` is shown once.

        ``sandbox_labels`` restricts the key to sandboxes with all those labels;
        ``max_sandboxes`` caps its live sandboxes (needs ``sandbox_labels``; a create at the
        cap answers 429 ``QUOTA_EXCEEDED``). ``shared_volume_labels`` (needs ``sandbox_labels``)
        also lets the key list, get and mount read-only the volumes carrying those labels, e.g.
        a class dataset; it can never write or delete them. ``expires_at`` must be
        timezone-aware.
        """
        return self._api_keys.create(
            name,
            scopes,
            sandbox_labels=sandbox_labels,
            max_sandboxes=max_sandboxes,
            expires_at=expires_at,
            shared_volume_labels=shared_volume_labels,
        )

    def list_api_keys(self, *, status: ApiKeyListStatus | None = None) -> tuple[ApiKeyInfo, ...]:
        """The org's API keys, metadata only (revoked ones included unless filtered).

        ``status`` ("active" or "revoked") asks the server to filter; any other string raises
        ``ValueError`` before a request is sent.
        """
        params = api_key_list_params(status)
        return api_key_infos(self._transport.request("GET", API_KEYS_PATH, params=params))

    def revoke_api_key(self, key_id: str, *, cascade: bool = False) -> RevokedApiKey:
        """Revoke a key; repeating the call answers the already revoked key.

        ``cascade=True`` also revokes the key's live descendants; without it they stay alive
        and the answer lists them in ``dependants``.
        """
        return self._api_keys.revoke(key_id, cascade=cascade)

    def export_snapshot(self, snapshot_id: str, path: PathArg) -> int:
        """Stream a ready snapshot to ``path`` as an image tar; returns the bytes written."""
        return self._snapshots.export(snapshot_id, path)

    def isolation(self) -> IsolationInfo:
        """The isolation tiers this server offers and the default a create gets."""
        return IsolationInfo.from_payload(self._transport.request("GET", ISOLATION_PATH).data)

    def list_sandboxes(
        self,
        *,
        state: str | None = None,
        labels: dict[str, str] | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        include_destroyed: bool = False,
        order: SortOrder | None = None,
        stop_cause: StopCause | None = None,
    ) -> IdentifiedPage[Sandbox]:
        """``include_destroyed``: also list ``destroyed`` tombstones (hidden by default; a
        ``state`` filter of ``destroyed`` returns them anyway). Sent only when true.
        ``order``: a :data:`~sandfort_sdk.SortOrder` (``"asc"``/``"desc"``); sent only if given.
        ``stop_cause``: only sandboxes with this stop cause, one of the
        :data:`~sandfort_sdk.StopCause` literal values; sent only if given."""
        params = list_params(state, labels, cursor, limit, include_destroyed, order, stop_cause)
        reply = self._transport.request("GET", SANDBOXES_PATH, params=params)
        if not isinstance(reply.data, list):
            raise InvalidResponseError("expected a list of sandboxes")
        items = tuple(Sandbox(SandboxInfo.from_payload(d), self._transport) for d in reply.data)
        return IdentifiedPage(items, reply.next_cursor, reply.request_id)

    def iter_sandboxes(
        self,
        *,
        state: str | None = None,
        labels: dict[str, str] | None = None,
        limit: int | None = None,
        include_destroyed: bool = False,
        order: SortOrder | None = None,
        stop_cause: StopCause | None = None,
    ) -> Iterator[Sandbox]:
        """Every page of :meth:`list_sandboxes`; ``order`` and ``stop_cause`` as there."""
        cursor: str | None = None
        while True:
            page = self.list_sandboxes(
                state=state, labels=labels, cursor=cursor, limit=limit,
                include_destroyed=include_destroyed, order=order, stop_cause=stop_cause,
            )  # fmt: skip
            yield from page.items
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    def get(self, ref: str) -> Sandbox:
        """Fetch a sandbox by id (``sbx_...``) or by the name of a live sandbox.

        A name is looked up among the live sandboxes: none raises :class:`NotFound` naming it,
        and several raise :class:`AmbiguousSandboxName` listing their ids (a sandbox in the
        ``error`` state loses against any other with the same name). ``get_sandbox`` is the
        same method under the name next to ``create_sandbox`` and ``list_sandboxes``.
        """
        if ref.startswith(ID_PREFIX):
            return Sandbox(SandboxInfo.from_payload(self._fetch(ref).data), self._transport)
        infos: list[SandboxInfo] = []
        cursor: str | None = None
        while True:
            page = self.list_sandboxes(cursor=cursor)
            infos += [sandbox.info for sandbox in page]
            if (cursor := page.next_cursor) is None:
                return Sandbox(select_named(ref, infos, page.request_id), self._transport)

    get_sandbox = get

    def start(
        self,
        sandbox_id: str,
        *,
        wait: bool = False,
        wait_timeout_s: float | None = None,
        poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
    ) -> Sandbox:
        """Start a stopped sandbox; with ``wait=True`` block until it reports ``started``.

        ``wait_timeout_s``: with ``wait=True`` one deadline, ``wait_timeout_s`` (default
        ``DEFAULT_WAIT_TIMEOUT_S``) from just before the start request is sent, bounds the whole
        call, as for :meth:`create_sandbox`: each attempt's connect, write, read and pool timeouts
        are at most the time left, none starts after the deadline, and the wait for ``started``
        long-polls only for the time left. A reply that already says ``started`` ends the call
        with no further request. A start request that times out raises
        :class:`SandboxTimeoutError` naming the sandbox (the start may still finish); a wait that
        runs out carries ``sandbox_id`` and ``state``; a sandbox that ends in ``error`` raises
        :class:`SandboxFailedError` and is kept. ``wait_timeout_s`` and ``poll_interval_s`` have
        no effect without ``wait``, which sends the one request as before. With ``wait=True`` a
        ``wait_timeout_s`` that is not a finite number greater than 0 raises :class:`ValueError`.
        """
        check_wait_budget(wait, wait_timeout_s)
        path = sandbox_path(sandbox_id, "/start")
        if not wait:
            return self._act("POST", path)
        budget = DEFAULT_WAIT_TIMEOUT_S if wait_timeout_s is None else wait_timeout_s
        clock = CreateClock.start(budget, time.monotonic())
        try:
            reply = self._transport.request("POST", path, deadline=clock.deadline)
        except RequestTimedOut as timeout:
            raise start_timeout_error(sandbox_id, budget) from timeout
        info = self._wait_started(reply, clock.deadline, poll_interval_s)
        return Sandbox(info, self._transport)

    def stop(self, sandbox_id: str) -> Sandbox:
        return self._act("POST", sandbox_path(sandbox_id, "/stop"))

    def delete(self, sandbox_id: str) -> Sandbox:
        return self._act("DELETE", sandbox_path(sandbox_id))

    def _act(self, method: str, path: str) -> Sandbox:
        reply = self._transport.request(method, path)
        return Sandbox(SandboxInfo.from_payload(reply.data), self._transport)

    def _fetch(
        self, sandbox_id: str, long_poll_s: float | None = None, deadline: float | None = None
    ) -> Reply:
        params: dict[str, Any] | None = None if long_poll_s is None else wait_params(long_poll_s)
        return self._transport.request(
            "GET", sandbox_path(sandbox_id), params=params, server_wait_s=long_poll_s,
            deadline=deadline,
        )  # fmt: skip

    def _wait_started(self, reply: Reply, deadline: float, poll_interval_s: float) -> SandboxInfo:
        """Long-poll until started; every poll and pause ends by ``deadline`` (monotonic)."""
        while True:
            info, ready = settled(reply)
            if ready:
                return info
            window = poll_window(info, deadline, time.monotonic())
            try:
                reply = self._fetch(info.id, window, deadline)
            except RequestTimedOut as timeout:
                raise wait_expired(info) from timeout
            if not settled(reply)[1]:
                time.sleep(poll_pause(deadline, time.monotonic(), poll_interval_s))
