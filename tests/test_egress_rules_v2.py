"""Egress v2 round 1 (docs/egress-v2-design.md section 3.1): address rules, pure unit tests.

No sockets and no Docker: the rule matcher, the strict literal classifier and the fixed
translation prefixes.
"""

from ipaddress import IPv4Address, IPv6Address

import pytest

from sandfort.egress import proxy, proxy_limits
from sandfort.egress.relay import Deny
from sandfort.egress.rules import (
    TRANSLATION_PREFIXES,
    EgressRules,
    is_translation_address,
    target_address,
)

ENTRIES = ["api.example.com", ".example.com", "198.51.100.0/24", "2001:db8:10::/48"]


def test_from_entries_splits_host_domain_and_network_rules() -> None:
    rules = EgressRules.from_entries(ENTRIES)

    assert rules.admits_name("api.example.com")
    assert rules.admits_name("x.example.com")
    assert rules.admits_address(IPv4Address("198.51.100.7"))
    assert rules.admits_address(IPv6Address("2001:db8:10::5"))


@pytest.mark.parametrize(
    ("host", "entries", "expected"),
    [
        ("api.example.com", ["api.example.com"], True),
        ("x.api.example.com", ["api.example.com"], False),
        ("example.com", [".example.com"], True),
        ("a.b.example.com", [".example.com"], True),
        ("API.Example.com.", ["api.example.com"], True),
        ("badexample.com", [".example.com"], False),
        ("example.com.evil.test", [".example.com"], False),  # C3 shape
        ("198.51.100.7", ["198.51.100.0/24"], False),  # C6 shape: a CIDR never admits a name
        ("name.test", ["198.51.100.0/24"], False),
        ("anything.test", [], False),  # C16 shape
        ("", [".example.com"], False),
    ],
)
def test_admits_name(host: str, entries: list[str], expected: bool) -> None:
    assert EgressRules.from_entries(entries).admits_name(host) is expected


@pytest.mark.parametrize(
    ("address", "entries", "expected"),
    [
        (IPv4Address("198.51.100.7"), ["198.51.100.0/24"], True),
        (IPv4Address("198.51.101.7"), ["198.51.100.0/24"], False),  # C5
        (IPv6Address("2001:db8:10::5"), ["2001:db8:10::/48"], True),  # C7
        (IPv6Address("2001:db8:11::5"), ["2001:db8:10::/48"], False),
        (IPv4Address("198.51.100.7"), ["2001:db8:10::/48"], False),
        (IPv6Address("2001:db8:10::5"), ["198.51.100.0/24"], False),
        (IPv4Address("198.51.100.7"), [], False),
        (IPv6Address("2001:db8:10::5"), [], False),
        (IPv4Address("198.51.100.7"), ["api.example.com", ".example.com"], False),
    ],
)
def test_admits_address(
    address: IPv4Address | IPv6Address, entries: list[str], expected: bool
) -> None:
    assert EgressRules.from_entries(entries).admits_address(address) is expected


@pytest.mark.parametrize(
    "host", ["api.example.com", "2130706433", "0x7f.0.0.1", "010.0.0.1", "1.2.3", "localhost"]
)
def test_target_address_leaves_names_and_loose_numbers_as_names(host: str) -> None:
    assert target_address(host) is None


def test_target_address_parses_strict_literals() -> None:
    assert target_address("198.51.100.7") == IPv4Address("198.51.100.7")
    assert target_address("2001:db8::1") == IPv6Address("2001:db8::1")


def test_target_address_folds_ipv4_mapped_to_ipv4() -> None:
    folded = target_address("::ffff:10.0.0.1")

    assert folded == IPv4Address("10.0.0.1")
    assert isinstance(folded, IPv4Address)


def test_target_address_refuses_a_zone_id() -> None:
    with pytest.raises(Deny) as caught:
        target_address("fe80::1%eth0")

    assert caught.value.status == 400
    assert caught.value.detail == "zone id in target"


@pytest.mark.parametrize(
    "text",
    [
        "64:ff9b::a00:1",
        "64:ff9b:1::1",
        "2002:c000:204::1",
        "2001::1",
        "::7f00:1",  # IPv4-compatible form of 127.0.0.1
        "::a9fe:a9fe",  # IPv4-compatible form of the metadata IP
        "::ffff:0:a00:1",  # IPv4-translated (SIIT) form of 10.0.0.1
        "fec0::1",  # deprecated site-local
    ],
)
def test_translation_addresses_are_recognised(text: str) -> None:
    assert is_translation_address(IPv6Address(text))


@pytest.mark.parametrize("text", ["2001:db8::1", "8.8.8.8", "2606:4700::1", "::", "::1"])
def test_other_addresses_are_not_translation_addresses(text: str) -> None:
    address = IPv4Address(text) if "." in text else IPv6Address(text)

    assert not is_translation_address(address)


def test_the_translation_prefixes_are_the_fixed_set() -> None:
    assert {str(network) for network in TRANSLATION_PREFIXES} == {
        "::/96",
        "::ffff:0:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "2002::/16",
        "2001::/32",
        "fec0::/10",
    }


def test_host_allowed_is_importable_from_both_modules_and_ignores_cidr_entries() -> None:
    assert proxy.host_allowed is proxy_limits.host_allowed
    assert proxy_limits.host_allowed("api.example.com", ["api.example.com"]) is True
    assert proxy_limits.host_allowed("API.Example.com.", ["api.example.com"]) is True
    assert proxy_limits.host_allowed("example.com", [".example.com"]) is True
    assert proxy_limits.host_allowed("example.com.evil.test", [".example.com"]) is False
    assert proxy_limits.host_allowed("198.51.100.7", ["198.51.100.0/24"]) is False
    assert proxy_limits.host_allowed("a.test", ["198.51.100.0/24", "a.test"]) is True
