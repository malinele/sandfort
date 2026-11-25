"""PolicyClient tests (egress v2 round 2, design sections 5.2 and 12.3); hermetic, no network.

The policy route is simulated with httpx.MockTransport and a fake monotonic clock; MAC wall time
is pinned. Expected signatures are recomputed here from the documented labels, never taken from
``policy_wire``. Case ids (U5, U6, U7, U10, U11, U14) are those of docs/egress-v2-design.md 12.3.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import re
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest

from sandfort.egress.policy_client import PolicyClient, PolicyEntry, PolicyUnavailable

SECRET = "test-egress-secret"
NOW = 1_795_000_000
SIGNATURE_HEADER = "X-Sandfort-Egress-Signature"
AUTH_HEADER = "X-Sandfort-Egress-Auth"
K_REQ = hmac.new(SECRET.encode(), b"sandfort/egress/policy/request/v1", hashlib.sha256).digest()
K_RESP = hmac.new(SECRET.encode(), b"sandfort/egress/policy/response/v1", hashlib.sha256).digest()

Factory = Callable[..., PolicyClient]


def _mac(key: bytes, message: str) -> str:
    digest = hmac.new(key, message.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _response_sig(request_body: bytes, body: bytes, stamp: int = NOW, key: bytes = K_RESP) -> str:
    """Response MAC bound to the request: ``<t>, sha256 of request, sha256 of response``."""
    request_digest = hashlib.sha256(request_body).hexdigest()
    message = f"{stamp}\n{request_digest}\n{hashlib.sha256(body).hexdigest()}"
    return f"t={stamp},s={_mac(key, message)}"


def _request_sig(body: bytes, stamp: int = NOW) -> str:
    message = f"POST\n/internal/egress/v1/policies\n{stamp}\n{hashlib.sha256(body).hexdigest()}"
    return f"t={stamp},s={_mac(K_REQ, message)}"


def _policy(generation: int, epoch: int, rules: list[str]) -> dict[str, Any]:
    return {"generation": generation, "epoch": epoch, "rules": rules}


class FakeClock:
    now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class Route:
    """The simulated policy route: what it knows, what it received, and how it answers."""

    def __init__(self) -> None:
        self.policies: dict[str, dict[str, Any]] = {}  # absent id -> found false
        self.omit: set[str] = set()  # ids left out of the answer
        self.sent: list[httpx.Request] = []
        self.gates: dict[int, asyncio.Event] = {}  # request number (1-based) -> release event
        self.inflight = 0
        self.max_inflight = 0
        self.failure: Exception | None = None
        self.status = 200
        self.raw_body: bytes | None = None
        self.issued_at = NOW  # the body's issued_at; the signature timestamp must equal it
        self.sign: Callable[[bytes, bytes], str | None] = _response_sig

    def _body(self, ids: list[str]) -> bytes:
        if self.raw_body is not None:
            return self.raw_body
        records = [
            {"sandbox_id": i, "found": True, **self.policies[i]}
            if i in self.policies
            else {"sandbox_id": i, "found": False}
            for i in ids
            if i not in self.omit
        ]
        return json.dumps({"issued_at": self.issued_at, "policies": records}).encode()

    async def handler(self, request: httpx.Request) -> httpx.Response:
        ids = json.loads(request.content)["sandbox_ids"]
        self.sent.append(request)
        number = len(self.sent)
        if self.failure is not None:
            raise self.failure
        body = self._body(ids)  # the answer reflects the route's state when it was asked
        self.inflight += 1
        self.max_inflight = max(self.max_inflight, self.inflight)
        try:
            gate = self.gates.get(number)
            if gate is not None:
                await gate.wait()
        finally:
            self.inflight -= 1
        signature = self.sign(request.content, body)
        headers = {SIGNATURE_HEADER: signature} if signature else {}
        return httpx.Response(self.status, content=body, headers=headers)


async def _until(predicate: Callable[[], bool]) -> None:
    for _ in range(500):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition never became true")


@pytest.fixture
def route() -> Route:
    return Route()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
async def make_client(route: Route, clock: FakeClock) -> AsyncIterator[Factory]:
    made: list[PolicyClient] = []

    def factory(**overrides: Any) -> PolicyClient:
        settings: dict[str, Any] = {
            "cache_s": 5.0,
            "timeout_s": 2.0,
            "max_stale_s": 60.0,
            "transport": httpx.MockTransport(route.handler),
            "clock": clock,
            "now": lambda: NOW,
        }
        client = PolicyClient("http://policy.test", SECRET, **{**settings, **overrides})
        made.append(client)
        return client

    yield factory
    for client in made:
        await client.aclose()


async def test_request_is_signed_under_k_req(route: Route, make_client: Factory) -> None:
    rules = ["api.example.com", "198.51.100.0/24"]
    route.policies["sbx_1"] = _policy(4, 1, rules)

    entry = await make_client().lookup("sbx_1")

    assert entry == PolicyEntry(True, 4, 1, tuple(rules), 0.0)
    request = route.sent[0]
    assert str(request.url) == "http://policy.test/internal/egress/v1/policies"
    sent = json.loads(request.content)
    assert sorted(sent) == ["nonce", "sandbox_ids"]
    assert sent["sandbox_ids"] == ["sbx_1"]
    assert request.headers[AUTH_HEADER] == _request_sig(request.content)


async def test_each_request_carries_a_fresh_nonce(
    route: Route, clock: FakeClock, make_client: Factory
) -> None:
    route.policies["sbx_1"] = _policy(1, 1, ["a.example.com"])
    client = make_client()

    await client.lookup("sbx_1")
    clock.advance(10)  # past cache_s: the next lookup goes to the route again
    await client.lookup("sbx_1")

    nonces = [json.loads(request.content)["nonce"] for request in route.sent]
    assert len(nonces) == 2 and nonces[0] != nonces[1]
    assert all(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", nonce) for nonce in nonces)
    assert route.sent[0].content != route.sent[1].content  # same ids, different bytes


async def test_a_captured_signed_response_is_refused_for_a_later_request_with_the_same_ids(
    route: Route, clock: FakeClock, make_client: Factory
) -> None:
    route.policies["sbx_1"] = _policy(1, 0, ["wide.example.com"])
    client = make_client()
    assert (await client.lookup("sbx_1")).rules == ("wide.example.com",)
    captured_body = route.sent[0].content
    captured_answer = route._body(["sbx_1"])
    captured_signature = _response_sig(captured_body, captured_answer)

    clock.advance(10)  # the cached entry expires; the attacker replays the 200 inside 30 s
    route.policies["sbx_1"] = _policy(2, 0, ["narrow.example.com"])
    route.raw_body = captured_answer
    route.sign = lambda request, body: captured_signature

    with pytest.raises(PolicyUnavailable):
        await client.lookup("sbx_1")


async def test_fresh_for_cache_s(route: Route, clock: FakeClock, make_client: Factory) -> None:
    route.policies["sbx_1"] = _policy(1, 1, ["a.example.com"])
    client = make_client()
    first = await client.lookup("sbx_1")

    clock.advance(4.5)
    assert await client.lookup("sbx_1") == first
    assert len(route.sent) == 1

    clock.advance(0.5)  # exactly cache_s old: no longer fresh
    assert not client.is_fresh(first)
    second = await client.lookup("sbx_1")
    assert len(route.sent) == 2
    assert second.requested_at == 5.0


async def test_fresh_from_send(route: Route, clock: FakeClock, make_client: Factory) -> None:
    route.policies["sbx_1"] = _policy(1, 1, ["a.example.com"])
    route.gates[1] = gate = asyncio.Event()
    client = make_client()
    pending = asyncio.create_task(client.lookup("sbx_1"))
    await _until(lambda: route.inflight == 1)

    clock.advance(4.5)  # the answer lands 4.5 s after the request left
    gate.set()
    entry = await pending

    assert entry.requested_at == 0.0
    assert client.is_fresh(entry)
    clock.advance(0.5)
    assert not client.is_fresh(entry)
    await client.lookup("sbx_1")
    assert len(route.sent) == 2


async def test_u5_transport_error(route: Route, clock: FakeClock, make_client: Factory) -> None:
    route.policies["sbx_1"] = _policy(1, 1, ["a.example.com"])
    client = make_client()
    first = await client.lookup("sbx_1")
    route.failure = httpx.ConnectError("route down")

    clock.advance(4.5)
    assert await client.lookup("sbx_1") == first
    assert len(route.sent) == 1  # served from the cache, the route was not asked

    clock.advance(0.5)
    with pytest.raises(PolicyUnavailable):
        await client.lookup("sbx_1")
    assert len(route.sent) == 2


async def test_lookup_timeout(route: Route, make_client: Factory) -> None:
    route.gates[1] = asyncio.Event()  # never released
    client = make_client(timeout_s=0.05)

    with pytest.raises(PolicyUnavailable):
        await client.lookup("sbx_1")


_NO_SIG: Callable[[bytes, bytes], str | None] = lambda request, body: None  # noqa: E731
_UNVERIFIED = {  # id -> (status, raw body, signer); the 404 cases are the unsigned U6 answers
    "u6-old-api-body": (404, b'{"detail":"Not Found"}', _NO_SIG),
    "u6-found-false-body": (404, None, _NO_SIG),  # the route's own well-formed body
    "missing": (200, None, _NO_SIG),
    "wrong-key": (200, None, lambda request, body: _response_sig(request, body, key=K_REQ)),
    "other-body": (200, None, lambda request, body: _response_sig(request, b"another body")),
    "other-request": (200, None, lambda request, body: _response_sig(b"another request", body)),
    "malformed-header": (200, None, lambda request, body: "t=not-a-number,s=AAAA"),
}


@pytest.mark.parametrize("case", _UNVERIFIED.values(), ids=list(_UNVERIFIED))
async def test_unverified_response(route: Route, make_client: Factory, case: Any) -> None:
    route.status, route.raw_body, route.sign = case
    if route.status == 200:
        route.policies["sbx_1"] = _policy(1, 1, ["a.example.com"])
    client = make_client()

    with pytest.raises(PolicyUnavailable):
        await client.lookup("sbx_1")
    assert client.get_cached("sbx_1") is None


async def test_u7_stale_signature(route: Route, make_client: Factory) -> None:
    route.policies["sbx_1"] = _policy(1, 1, ["a.example.com"])
    client = make_client()

    route.issued_at = NOW - 31
    route.sign = lambda request, body: _response_sig(request, body, NOW - 31)
    with pytest.raises(PolicyUnavailable):
        await client.lookup("sbx_1")

    route.issued_at = NOW - 29
    route.sign = lambda request, body: _response_sig(request, body, NOW - 29)
    assert (await client.lookup("sbx_1")).found


_FOUND = {"sandbox_id": "sbx_1", "found": True, **_policy(1, 1, [])}
_OVER = json.dumps({"issued_at": NOW, "policies": [_FOUND]}).encode() + b" " * 1_048_576  # > cap
_CASES = {  # id -> (status, raw body, ids left out, a stale entry is cached first)
    "signed-500": (500, None, set(), False),
    "signed-malformed-body": (200, b"this is not json", set(), False),
    "id-not-covered": (200, None, {"sbx_1"}, False),
    "id-not-covered-stale": (200, None, {"sbx_1"}, True),  # a stale entry must not stand in
    "oversized": (200, _OVER, set(), False),
}


@pytest.mark.parametrize("case", _CASES.values(), ids=list(_CASES))
async def test_signed_but_unusable(
    route: Route, clock: FakeClock, make_client: Factory, case: tuple[Any, ...]
) -> None:
    client = make_client()
    if case[3]:
        route.policies["sbx_1"] = _policy(1, 1, ["a.example.com"])
        await client.lookup("sbx_1")
        clock.advance(6.0)  # past cache_s: the cached entry is stale
    route.status, route.raw_body, route.omit = case[:3]

    with pytest.raises(PolicyUnavailable):
        await client.lookup("sbx_1")


async def test_u11_single_flight(route: Route, make_client: Factory) -> None:
    route.policies["sbx_1"] = _policy(3, 1, ["a.example.com"])
    route.gates[1] = gate = asyncio.Event()
    client = make_client()
    lookups = [asyncio.create_task(client.lookup("sbx_1")) for _ in range(5)]
    await _until(lambda: route.inflight == 1)
    await asyncio.sleep(0)

    gate.set()
    entries = await asyncio.gather(*lookups)

    assert len(route.sent) == 1
    assert len({id(entry) for entry in entries}) == 1
    assert entries[0].generation == 3


async def test_u14_newer_request_wins(route: Route, clock: FakeClock, make_client: Factory) -> None:
    route.policies["sbx_1"] = _policy(1, 1, ["a.example.com"])
    client = make_client()
    changes: list[PolicyEntry] = []
    client.set_on_change(lambda sandbox_id, entry: changes.append(entry))
    await client.lookup("sbx_1")  # request 1, sent at 0
    clock.advance(6.0)
    route.gates[2] = gate = asyncio.Event()
    older = asyncio.create_task(client.refresh_many(["sbx_1"]))  # sent at 6 under generation 1
    await _until(lambda: route.inflight == 1)

    clock.advance(1.0)
    route.policies["sbx_1"] = _policy(2, 1, ["b.example.com"])  # the PATCH commits
    await client.refresh_many(["sbx_1"])  # sent at 7 under generation 2, lands first

    gate.set()
    await older  # the request sent at 6 lands now

    final = client.get_cached("sbx_1")
    assert final is not None
    assert (final.generation, final.requested_at, final.rules) == (2, 7.0, ("b.example.com",))
    assert [entry.generation for entry in changes] == [2]
    assert client.last_success_at("sbx_1") == 7.0


async def test_u10_batches_of_256(route: Route, make_client: Factory) -> None:
    ids = [f"sbx_{n}" for n in range(300)]
    for sandbox_id in ids:
        route.policies[sandbox_id] = _policy(1, 1, ["a.example.com"])
    route.gates[1] = route.gates[2] = release = asyncio.Event()
    client = make_client()
    refreshing = asyncio.create_task(client.refresh_many(ids))

    await _until(lambda: route.max_inflight == 2)  # both batches left before either returned
    release.set()
    await refreshing

    batches = [json.loads(request.content)["sandbox_ids"] for request in route.sent]
    assert sorted(len(batch) for batch in batches) == [44, 256]
    assert sorted(i for batch in batches for i in batch) == sorted(ids)
    assert all(client.get_cached(sandbox_id) is not None for sandbox_id in ids)


async def test_last_success_at(route: Route, clock: FakeClock, make_client: Factory) -> None:
    route.policies["sbx_1"] = _policy(1, 1, [])
    client = make_client()
    assert client.last_success_at("sbx_1") is None

    await client.lookup("sbx_1")
    assert client.last_success_at("sbx_1") == 0.0
    clock.advance(7.0)
    await client.refresh_many(["sbx_1", "sbx_2"])
    assert (client.last_success_at("sbx_1"), client.last_success_at("sbx_2")) == (7.0, 7.0)
    assert client.last_success_at("sbx_3") is None
    clock.advance(7.0)
    route.failure = httpx.ConnectError("route down")
    await client.refresh_many(["sbx_1"])
    assert client.last_success_at("sbx_1") == 7.0


async def test_evict_stale(route: Route, clock: FakeClock, make_client: Factory) -> None:
    client = make_client(max_entries=2)
    client.set_has_tunnels(lambda sandbox_id: sandbox_id == "sbx_a")
    await client.lookup("sbx_a")
    await client.lookup("sbx_b")
    clock.advance(6.0)  # both stale
    await client.lookup("sbx_c")

    assert client.get_cached("sbx_a") is not None  # stale but it has tunnels
    assert client.get_cached("sbx_b") is None
    assert client.get_cached("sbx_c") is not None


async def test_on_change(route: Route, clock: FakeClock, make_client: Factory) -> None:
    client = make_client()
    seen: list[tuple[str, PolicyEntry, PolicyEntry | None]] = []
    client.set_on_change(
        lambda sandbox_id, entry: seen.append((sandbox_id, entry, client.get_cached(sandbox_id)))
    )
    route.policies["sbx_1"] = _policy(1, 1, ["a.example.com"])

    async def refresh() -> None:
        clock.advance(1.0)
        await client.refresh_many(["sbx_1"])

    await client.lookup("sbx_1")
    assert seen == []  # nothing was replaced by the first fetch
    await refresh()  # identical
    assert seen == []
    route.policies["sbx_1"] = _policy(1, 1, ["b.example.com"])  # same generation and epoch
    await refresh()
    assert seen == []
    route.policies["sbx_1"] = _policy(2, 1, ["b.example.com"])
    await refresh()
    assert [entry.generation for _, entry, _ in seen] == [2]
    route.policies["sbx_1"] = _policy(2, 2, ["b.example.com"])
    await refresh()
    assert [entry.epoch for _, entry, _ in seen] == [1, 2]
    del route.policies["sbx_1"]  # found: false
    await refresh()
    assert [entry.found for _, entry, _ in seen] == [True, True, False]
    assert all(cached is entry for _, entry, cached in seen)  # the cache was updated first
