"""DNS pinning (egress v2 round 4): docs/egress-v2-design.md 4.4 and 12.2, cases P1 to P9.

Hermetic: the resolver, the checker and the connect step are stubs, and the pin clock is a fake.
``open_pinned`` is the unit under test; ``EgressProxy._dial`` calls it for name targets.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from ipaddress import ip_address, ip_network
from typing import cast

import pytest

from sandfort.egress import upstream as upstream_module
from sandfort.egress.admission import admission_cap_s
from sandfort.egress.pinning import MAX_PINS_PER_SANDBOX, MAX_PINS_TOTAL, PinStore
from sandfort.egress.policy_client import PolicyEntry
from sandfort.egress.proxy_limits import (
    DEFAULT_DNS_PIN_S,
    DNS_PIN_RANGE_S,
    ENV_DNS_PIN_S,
    ProxyConfig,
)
from sandfort.egress.relay import Connection, Deny
from sandfort.egress.upstream import open_pinned
from sandfort.webhooks.ssrf import IpAddress

SANDBOX, OTHER = "sbx_1", "sbx_2"
NAME, KEPT = "a.example.com", "keep.example.com"
FIRST, SECOND = ip_address("203.0.113.9"), ip_address("203.0.113.10")
WINDOW_S = 30.0
PORT = 443
SECRET = "test-egress-secret"
LOOPBACK_ONLY = (ip_network("10.0.0.0/8"),)

type Resolver = Callable[[str], Awaitable[list[str]]]


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Net:
    """A scripted resolver and connect step that record every call."""

    def __init__(self, *answers: list[str]) -> None:
        self.answers = list(answers)
        self.resolved: list[str] = []
        self.dialed: list[list[IpAddress]] = []
        self.refusing: set[IpAddress] = set()
        self.failure: Exception | None = None
        self.hang = False

    async def resolve(self, host: str) -> list[str]:
        self.resolved.append(host)
        if self.hang:
            await asyncio.sleep(3600)
        if self.failure is not None:
            raise self.failure
        return self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]

    async def connect(self, addresses: list[IpAddress], port: int) -> Connection:
        self.dialed.append(list(addresses))
        if all(address in self.refusing for address in addresses):
            raise Deny(502, "Bad Gateway", "upstream connection failed")
        return cast(Connection, (object(), object()))


def _permit(address: IpAddress) -> None:
    """Stands in for the public-address rules; the denied networks stay under test."""


def _store(clock: Clock, window_s: float = WINDOW_S) -> PinStore:
    return PinStore(window_s, clock)


async def _connect(
    net: Net, pins: PinStore, sandbox: str = SANDBOX, host: str = NAME
) -> tuple[Connection, list[IpAddress]]:
    return await open_pinned(
        sandbox,
        host,
        PORT,
        pins=pins,
        resolver=net.resolve,
        checker=_permit,
        denied=LOOPBACK_ONLY,
        opener=net.connect,
    )


def _entry(*rules: str, found: bool = True) -> PolicyEntry:
    return PolicyEntry(found, 1, 1, tuple(rules), 0.0)


async def test_p1_second_connect_in_the_window_uses_the_pin_without_resolving() -> None:
    net, clock = Net(["203.0.113.9"], ["203.0.113.10"]), Clock()
    pins = _store(clock)

    await _connect(net, pins)
    clock.now += WINDOW_S - 1
    _, addresses = await _connect(net, pins)

    assert net.resolved == [NAME]
    assert net.dialed == [[FIRST], [FIRST]]
    assert addresses == [FIRST]


async def test_p2_after_the_window_a_rebinding_answer_is_denied() -> None:
    net, clock = Net(["203.0.113.9"], ["10.0.0.5"]), Clock()
    pins = _store(clock)
    await _connect(net, pins)

    clock.now += WINDOW_S
    with pytest.raises(Deny) as denied:
        await _connect(net, pins)

    assert denied.value.status == 403
    assert net.resolved == [NAME, NAME]
    assert pins.get(SANDBOX, NAME) is None


async def test_p3_every_pinned_address_refuses_so_the_name_is_resolved_once_more() -> None:
    net, clock = Net(["203.0.113.9"], ["203.0.113.10"]), Clock()
    pins = _store(clock)
    await _connect(net, pins)
    net.refusing.add(FIRST)

    _, addresses = await _connect(net, pins)

    assert addresses == [SECOND]
    assert net.resolved == [NAME, NAME]
    assert net.dialed == [[FIRST], [FIRST], [SECOND]]
    assert pins.get(SANDBOX, NAME) == [SECOND]  # the new set is pinned in place of the old


async def test_p3_a_second_failure_is_502_and_leaves_no_pin() -> None:
    net, clock = Net(["203.0.113.9"], ["203.0.113.10"]), Clock()
    pins = _store(clock)
    await _connect(net, pins)
    net.refusing.update({FIRST, SECOND})

    with pytest.raises(Deny) as denied:
        await _connect(net, pins)

    assert denied.value.status == 502
    assert len(net.resolved) == 2  # one re-resolution, not a loop
    assert pins.get(SANDBOX, NAME) is None


async def test_p3_a_fresh_set_that_cannot_connect_is_not_pinned() -> None:
    net = Net(["203.0.113.9"])
    net.refusing.add(FIRST)
    pins = _store(Clock())

    with pytest.raises(Deny):
        await _connect(net, pins)

    assert pins.get(SANDBOX, NAME) is None


async def test_p4_a_resolver_error_is_502_and_never_pinned() -> None:
    net, clock = Net(["203.0.113.9"]), Clock()
    pins = _store(clock)
    net.failure = OSError("nxdomain")

    with pytest.raises(Deny) as denied:
        await _connect(net, pins)
    assert denied.value.status == 502
    assert pins.get(SANDBOX, NAME) is None

    net.failure = None
    await _connect(net, pins)  # the next CONNECT resolves again
    assert net.resolved == [NAME, NAME]


async def test_p4_an_empty_answer_is_502_and_never_pinned() -> None:
    net, pins = Net([]), _store(Clock())

    with pytest.raises(Deny) as denied:
        await _connect(net, pins)

    assert denied.value.status == 502
    assert pins.get(SANDBOX, NAME) is None


async def test_p5_pins_are_per_sandbox() -> None:
    net, pins = Net(["203.0.113.9"], ["203.0.113.10"]), _store(Clock())

    _, first = await _connect(net, pins, SANDBOX)
    _, second = await _connect(net, pins, OTHER)

    assert net.resolved == [NAME, NAME]
    assert (first, second) == ([FIRST], [SECOND])


async def test_p6_window_zero_resolves_on_every_connect() -> None:
    net, pins = Net(["203.0.113.9"], ["203.0.113.10"]), _store(Clock(), window_s=0)

    await _connect(net, pins)
    _, second = await _connect(net, pins)

    assert net.resolved == [NAME, NAME]
    assert second == [SECOND]
    assert len(pins) == 0


def test_p7_a_pin_is_dropped_when_the_policy_no_longer_admits_the_name() -> None:
    pins = _store(Clock())
    pins.put(SANDBOX, NAME, [FIRST])
    pins.put(SANDBOX, KEPT, [SECOND])
    pins.put(OTHER, NAME, [FIRST])

    pins.recheck_sandbox(SANDBOX, _entry(KEPT))

    assert pins.get(SANDBOX, NAME) is None
    assert pins.get(SANDBOX, KEPT) == [SECOND]
    assert pins.get(OTHER, NAME) == [FIRST]  # another sandbox's pin is not touched


def test_p7_a_domain_rule_keeps_the_names_under_it() -> None:
    pins = _store(Clock())
    pins.put(SANDBOX, NAME, [FIRST])

    pins.recheck_sandbox(SANDBOX, _entry(".example.com"))

    assert pins.get(SANDBOX, NAME) == [FIRST]


@pytest.mark.parametrize("entry", [_entry(found=False), _entry("a.example.com/24x")])
def test_p7_a_missing_or_unparsable_policy_drops_every_pin_of_the_sandbox(
    entry: PolicyEntry,
) -> None:
    pins = _store(Clock())
    pins.put(SANDBOX, NAME, [FIRST])
    pins.put(SANDBOX, KEPT, [SECOND])
    pins.put(OTHER, NAME, [FIRST])

    pins.recheck_sandbox(SANDBOX, entry)

    assert len(pins) == 1
    assert pins.get(OTHER, NAME) == [FIRST]


async def test_p8_a_hanging_pinned_address_is_replaced_within_the_admission_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(upstream_module, "CONNECT_TIMEOUT_S", 0.05)
    monkeypatch.setattr(upstream_module, "CONNECT_ROUND_S", 0.2)
    reached: list[str] = []

    async def open_connection(host: str, port: int) -> Connection:
        reached.append(host)
        if host == str(FIRST):
            await asyncio.sleep(3600)  # the pinned address never answers
        return cast(Connection, (object(), object()))

    monkeypatch.setattr(upstream_module.asyncio, "open_connection", open_connection)
    net, pins = Net(["203.0.113.10"]), _store(Clock())
    pins.put(SANDBOX, NAME, [FIRST])

    _, addresses = await open_pinned(
        SANDBOX,
        NAME,
        PORT,
        pins=pins,
        resolver=net.resolve,
        checker=_permit,
        denied=LOOPBACK_ONLY,
    )

    assert reached == [str(FIRST), str(SECOND)]
    assert addresses == [SECOND]
    assert net.resolved == [NAME]


def test_p8_the_real_budgets_fit_a_pinned_round_a_resolution_and_a_fresh_round() -> None:
    worst_case = (
        upstream_module.CONNECT_ROUND_S
        + upstream_module.RESOLVE_TIMEOUT_S
        + upstream_module.CONNECT_ROUND_S
    )
    assert upstream_module.CONNECT_TIMEOUT_S == 10.0
    assert worst_case <= admission_cap_s(2.0) == 38.0


async def test_p9_a_resolver_that_hangs_is_502_after_the_resolve_timeout_and_not_pinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(upstream_module, "RESOLVE_TIMEOUT_S", 0.05)
    net, pins = Net(["203.0.113.9"]), _store(Clock())
    net.hang = True

    with pytest.raises(Deny) as denied:
        await _connect(net, pins)

    assert denied.value.status == 502
    assert pins.get(SANDBOX, NAME) is None


def test_p9_the_real_resolve_timeout_is_five_seconds() -> None:
    assert upstream_module.RESOLVE_TIMEOUT_S == 5.0


def test_a_pin_expires_exactly_at_the_end_of_the_window() -> None:
    clock = Clock()
    pins = _store(clock)
    pins.put(SANDBOX, NAME, [FIRST])

    clock.now += WINDOW_S - 0.001
    assert pins.get(SANDBOX, NAME) == [FIRST]
    clock.now += 0.001
    assert pins.get(SANDBOX, NAME) is None
    assert len(pins) == 0  # an expired pin is forgotten, not kept


def test_names_are_pinned_case_and_trailing_dot_insensitively() -> None:
    pins = _store(Clock())
    pins.put(SANDBOX, "A.Example.COM.", [FIRST])

    assert pins.get(SANDBOX, NAME) == [FIRST]


def test_a_sandbox_holds_at_most_256_pins_and_evicts_the_least_recently_used() -> None:
    assert MAX_PINS_PER_SANDBOX == 256
    pins = _store(Clock())
    for index in range(MAX_PINS_PER_SANDBOX):
        pins.put(SANDBOX, f"h{index}.example.com", [FIRST])
    pins.get(SANDBOX, "h0.example.com")  # a read makes it recent

    pins.put(SANDBOX, "new.example.com", [FIRST])

    assert pins.count(SANDBOX) == MAX_PINS_PER_SANDBOX
    assert pins.get(SANDBOX, "h0.example.com") == [FIRST]
    assert pins.get(SANDBOX, "h1.example.com") is None
    assert pins.get(SANDBOX, "new.example.com") == [FIRST]


def test_the_proxy_holds_at_most_the_global_number_of_pins() -> None:
    assert MAX_PINS_TOTAL == 65536
    pins = PinStore(WINDOW_S, Clock(), max_per_sandbox=2, max_total=3)
    pins.put("s1", "a.test", [FIRST])
    pins.put("s2", "a.test", [FIRST])
    pins.put("s3", "a.test", [FIRST])

    pins.put("s4", "a.test", [FIRST])

    assert len(pins) == 3
    assert pins.get("s1", "a.test") is None  # the oldest pin of the whole proxy went
    assert pins.get("s4", "a.test") == [FIRST]


def test_replacing_a_pin_does_not_grow_the_store() -> None:
    pins = _store(Clock())
    pins.put(SANDBOX, NAME, [FIRST])
    pins.put(SANDBOX, NAME, [SECOND])

    assert len(pins) == 1
    assert pins.get(SANDBOX, NAME) == [SECOND]


async def test_no_pin_path_logs_the_queried_name(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    net, pins = Net(["203.0.113.9"], ["203.0.113.10"]), _store(Clock())

    await _connect(net, pins)
    net.refusing.add(FIRST)
    await _connect(net, pins)
    pins.recheck_sandbox(SANDBOX, _entry(KEPT))

    assert NAME not in caplog.text


def test_the_pin_window_is_a_proxy_setting_with_a_30_second_default() -> None:
    assert (DEFAULT_DNS_PIN_S, DNS_PIN_RANGE_S) == (30, (0, 300))
    base = {"SANDFORT_EGRESS_SECRET": SECRET}

    assert ProxyConfig.from_env(base).dns_pin_s == 30
    assert ProxyConfig.from_env({**base, ENV_DNS_PIN_S: "0"}).dns_pin_s == 0
    assert ProxyConfig.from_env({**base, ENV_DNS_PIN_S: " 300 "}).dns_pin_s == 300


@pytest.mark.parametrize("value", ["301", "-1", "abc", "", "1.5"])
def test_an_invalid_pin_window_names_the_variable(value: str) -> None:
    with pytest.raises(ValueError, match=ENV_DNS_PIN_S):
        ProxyConfig.from_env({"SANDFORT_EGRESS_SECRET": SECRET, ENV_DNS_PIN_S: value})
