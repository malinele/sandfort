"""Client of the internal egress policy route, with the proxy's policy cache.

``PolicyClient`` asks the api for the policy of sandboxes (``sandfort.egress.policy_wire`` has
the wire format) and keeps one ``PolicyEntry`` per sandbox id (docs/egress-v2-design.md
section 5.2):

- An entry is fresh for ``cache_s`` seconds counted from the moment its request was SENT, so a
  fetch that began before a change committed cannot extend the old policy past the window.
- A result replaces the cached entry only if its request was sent later than the cached
  entry's request: a slow, older response never overwrites a newer one.
- When a replacement differs in ``found``, ``generation`` or ``epoch``, the ``on_change``
  callback runs at once, whichever path fetched it (the proxy re-checks the sandbox's tunnels).
- Concurrent lookups of one sandbox share a single in-flight request.
- The cache is an LRU of at most ``max_entries``; a stale entry whose sandbox has no open
  tunnel (the ``has_tunnels`` seam) may be evicted.

Every response must carry a valid, fresh signature. A timeout, a transport error, an unverified
response (an unsigned 404 from an api without the route included) or a malformed body raises
``PolicyUnavailable``: it is never read as "not found". ``clock`` (monotonic seconds) and
``now`` (unix seconds for the MACs) are seams for tests.
"""

import asyncio
import logging
import secrets
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import httpx

from sandfort.egress.policy_wire import (
    AUTH_HEADER,
    MAX_POLICY_IDS,
    POLICY_PATH,
    SIGNATURE_HEADER,
    PolicyRecord,
    encode_policy_request,
    parse_policy_response,
    request_key,
    response_key,
    sign_request,
    verify_response,
)

POLICY_CACHE_MAX_ENTRIES = 65536
MAX_POLICY_RESPONSE_BYTES = 1_048_576
NONCE_BYTES = 16  # random bytes of one request nonce (22 base64url characters)

_log = logging.getLogger("sandfort.egress")


class PolicyUnavailable(Exception):  # noqa: N818 - the name is part of the round 2 contract
    """The policy could not be fetched or verified; callers fail closed (503)."""


@dataclass(frozen=True, slots=True)
class PolicyEntry:
    found: bool
    generation: int
    epoch: int
    rules: tuple[str, ...]
    requested_at: float  # client clock when the request that produced this entry was sent


def _wall_clock() -> int:
    return int(time.time())


class PolicyClient:
    def __init__(
        self,
        url: str,
        secret: str,
        *,
        cache_s: float,
        timeout_s: float,
        max_stale_s: float,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], int] = _wall_clock,
        max_entries: int = POLICY_CACHE_MAX_ENTRIES,
    ) -> None:
        self._endpoint = url.rstrip("/") + POLICY_PATH
        self._request_key = request_key(secret)
        self._response_key = response_key(secret)
        self._cache_s = cache_s
        self._timeout_s = timeout_s
        self._max_stale_s = max_stale_s
        self._clock = clock
        self._now = now
        self._max_entries = max_entries
        self._http = httpx.AsyncClient(
            transport=transport, timeout=timeout_s, trust_env=False, follow_redirects=False
        )
        self._cache: OrderedDict[str, PolicyEntry] = OrderedDict()
        self._succeeded: dict[str, float] = {}
        self._inflight: dict[str, asyncio.Task[dict[str, PolicyEntry]]] = {}
        self._on_change: Callable[[str, PolicyEntry], None] | None = None
        self._has_tunnels: Callable[[str], bool] = lambda sandbox_id: False

    @property
    def cache_s(self) -> float:
        return self._cache_s

    @property
    def timeout_s(self) -> float:
        return self._timeout_s

    @property
    def max_stale_s(self) -> float:
        return self._max_stale_s

    @property
    def clock(self) -> Callable[[], float]:
        return self._clock

    def set_on_change(self, callback: Callable[[str, PolicyEntry], None]) -> None:
        self._on_change = callback

    def set_has_tunnels(self, has_tunnels: Callable[[str], bool]) -> None:
        self._has_tunnels = has_tunnels

    def get_cached(self, sandbox_id: str) -> PolicyEntry | None:
        return self._cache.get(sandbox_id)

    def is_fresh(self, entry: PolicyEntry) -> bool:
        return self._clock() - entry.requested_at < self._cache_s

    def last_success_at(self, sandbox_id: str) -> float | None:
        """Client-clock send time of the last successful refresh that covered the sandbox."""
        return self._succeeded.get(sandbox_id)

    async def aclose(self) -> None:
        """Cancel in-flight lookups, then close the http client."""
        tasks = list(self._inflight.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self._http.aclose()

    async def lookup(self, sandbox_id: str) -> PolicyEntry:
        """The fresh entry for ``sandbox_id``, fetched when the cached one is missing or stale."""
        cached = self._cache.get(sandbox_id)
        if cached is not None and self.is_fresh(cached):
            self._cache.move_to_end(sandbox_id)
            return cached
        task = self._inflight.get(sandbox_id)
        if task is None:
            task = asyncio.create_task(self._fetch_one(sandbox_id))
            task.add_done_callback(_observe)
            self._inflight[sandbox_id] = task
        # shield: one waiter giving up (a cancelled admission) must not cancel the others
        landed = await asyncio.shield(task)
        # a stale cache entry never satisfies a lookup: only a fresh one or this fetch's own
        cached = self._cache.get(sandbox_id)
        if cached is not None and self.is_fresh(cached):
            return cached
        stored = landed.get(sandbox_id)
        if stored is None:
            raise PolicyUnavailable("the response did not cover the sandbox")
        return stored

    async def refresh_many(self, sandbox_ids: Sequence[str]) -> None:
        """Fetch fresh policies in batches of up to 256, concurrently; failures are logged.

        A sweep never joins an in-flight lookup: its request is sent now.
        """
        unique = list(dict.fromkeys(sandbox_ids))
        batches = [
            unique[start : start + MAX_POLICY_IDS]
            for start in range(0, len(unique), MAX_POLICY_IDS)
        ]
        results = await asyncio.gather(
            *(self._fetch(batch) for batch in batches), return_exceptions=True
        )
        for result in results:
            if isinstance(result, PolicyUnavailable):
                _log.warning("egress policy refresh failed: %s", result)
            elif isinstance(result, BaseException):
                raise result

    async def _fetch_one(self, sandbox_id: str) -> dict[str, PolicyEntry]:
        try:
            return await self._fetch([sandbox_id])
        finally:
            self._inflight.pop(sandbox_id, None)

    async def _fetch(self, sandbox_ids: list[str]) -> dict[str, PolicyEntry]:
        sent = self._clock()
        records = await self._post(sandbox_ids)
        if any(sandbox_id not in records for sandbox_id in sandbox_ids):
            raise PolicyUnavailable("the response did not cover every requested sandbox")
        return {
            sandbox_id: self._store(sandbox_id, records[sandbox_id], sent)
            for sandbox_id in sandbox_ids
        }

    async def _post(self, sandbox_ids: list[str]) -> dict[str, PolicyRecord]:
        body = encode_policy_request(sandbox_ids, secrets.token_urlsafe(NONCE_BYTES))
        headers = {
            AUTH_HEADER: sign_request(self._request_key, body, self._now()),
            "Content-Type": "application/json",
        }
        try:
            response = await asyncio.wait_for(
                self._http.post(self._endpoint, content=body, headers=headers), self._timeout_s
            )
        except (httpx.HTTPError, TimeoutError, OSError) as exc:
            raise PolicyUnavailable(f"policy request failed: {type(exc).__name__}") from None
        if len(response.content) > MAX_POLICY_RESPONSE_BYTES:
            raise PolicyUnavailable("policy response too large")
        signature = response.headers.get(SIGNATURE_HEADER)
        if not verify_response(self._response_key, signature, body, response.content, self._now()):
            raise PolicyUnavailable(f"unverified policy response (status {response.status_code})")
        if response.status_code != 200:
            raise PolicyUnavailable(f"policy route answered {response.status_code}")
        try:
            return parse_policy_response(response.content)[1]
        except ValueError:
            raise PolicyUnavailable("malformed policy response") from None

    def _store(self, sandbox_id: str, record: PolicyRecord, sent: float) -> PolicyEntry:
        entry = PolicyEntry(record.found, record.generation, record.epoch, record.rules, sent)
        self._succeeded[sandbox_id] = max(self._succeeded.get(sandbox_id, sent), sent)
        current = self._cache.get(sandbox_id)
        if current is not None and sent <= current.requested_at:
            return entry  # an older answer: the cache keeps the newer entry
        self._cache[sandbox_id] = entry
        self._cache.move_to_end(sandbox_id)
        self._evict()
        if current is not None and self._on_change is not None and _differs(current, entry):
            self._on_change(sandbox_id, entry)
        return entry

    def _evict(self) -> None:
        if len(self._cache) <= self._max_entries:
            return
        for sandbox_id in list(self._cache):  # least recently used first
            if len(self._cache) <= self._max_entries:
                break
            entry = self._cache[sandbox_id]
            if not self.is_fresh(entry) and not self._has_tunnels(sandbox_id):
                del self._cache[sandbox_id]
                self._succeeded.pop(sandbox_id, None)


def _differs(old: PolicyEntry, new: PolicyEntry) -> bool:
    return (old.found, old.generation, old.epoch) != (new.found, new.generation, new.epoch)


def _observe(task: asyncio.Task[dict[str, PolicyEntry]]) -> None:
    """Mark a shared fetch's outcome as seen, so an abandoned failure is not logged twice."""
    if not task.cancelled():
        task.exception()
