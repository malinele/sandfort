"""Isolation tier settings: ``SANDFORT_ISOLATION_RUNTIMES`` and ``SANDFORT_DEFAULT_ISOLATION``."""

import re

import pytest

from sandfort.config import Settings
from sandfort.domain.isolation import (
    CONTAINER,
    GVISOR,
    ISOLATION_LABEL,
    MICROVM,
    TIERS,
    parse_tier_runtimes,
    tier_of,
)
from sandfort.services.volumes import RESERVED_LABEL_PREFIX, is_reserved_label


def load(**env: str) -> Settings:
    return Settings.from_env({f"SANDFORT_{name}": value for name, value in env.items()})


def test_tier_names_are_exactly_the_three_documented_ones() -> None:
    assert TIERS == (CONTAINER, GVISOR, MICROVM) == ("container", "gvisor", "microvm")


def test_the_isolation_label_is_a_reserved_label() -> None:
    assert ISOLATION_LABEL == "sandfort.isolation"
    assert ISOLATION_LABEL.startswith(RESERVED_LABEL_PREFIX)
    assert is_reserved_label(ISOLATION_LABEL)


def test_a_valid_map_offers_every_listed_tier_with_its_runtime() -> None:
    settings = load(ISOLATION_RUNTIMES="container=,gvisor=runsc,microvm=kata")

    assert settings.isolation_runtimes == (
        ("container", ""),
        ("gvisor", "runsc"),
        ("microvm", "kata"),
    )
    assert settings.default_isolation == "container"
    assert settings.isolation_tiers() == {"container": "", "gvisor": "runsc", "microvm": "kata"}


def test_whitespace_around_pairs_is_ignored() -> None:
    settings = load(ISOLATION_RUNTIMES=" container = , gvisor = runsc ")

    assert settings.isolation_tiers() == {"container": "", "gvisor": "runsc"}


def test_a_default_listed_in_the_map_is_accepted() -> None:
    settings = load(ISOLATION_RUNTIMES="container=,gvisor=runsc", DEFAULT_ISOLATION="gvisor")

    assert settings.default_isolation == "gvisor"


def test_no_map_offers_only_the_default_tier_on_the_daemon_default() -> None:
    settings = load()

    assert settings.isolation_runtimes == ()
    assert settings.default_isolation == "container"
    assert settings.isolation_tiers() == {"container": ""}
    assert Settings().isolation_tiers() == {"container": ""}


def test_no_map_keeps_the_container_runtime_setting_for_the_default_tier() -> None:
    settings = load(CONTAINER_RUNTIME="runsc")

    assert settings.isolation_tiers() == {"container": "runsc"}


def test_no_map_with_another_default_tier_uses_the_container_runtime() -> None:
    settings = load(CONTAINER_RUNTIME="runsc", DEFAULT_ISOLATION="gvisor")

    assert settings.isolation_tiers() == {"gvisor": "runsc"}


def test_a_blank_map_is_the_same_as_no_map() -> None:
    assert load(ISOLATION_RUNTIMES="  ").isolation_runtimes == ()


@pytest.mark.parametrize(
    "raw", ["firecracker=fc", "container=,vm=kata", "Container=", "gvisor =runsc,docker=runc"]
)
def test_an_unknown_tier_name_is_rejected(raw: str) -> None:
    with pytest.raises(ValueError, match="SANDFORT_ISOLATION_RUNTIMES: unknown tier"):
        load(ISOLATION_RUNTIMES=raw)


@pytest.mark.parametrize(
    "raw",
    ["container", "gvisor:runsc", "=runsc", "container=,", "container=,,gvisor=runsc", "x=a b"],
)
def test_a_malformed_pair_is_rejected(raw: str) -> None:
    with pytest.raises(ValueError, match="SANDFORT_ISOLATION_RUNTIMES: malformed pair"):
        load(ISOLATION_RUNTIMES=raw)


def test_a_tier_listed_twice_is_rejected() -> None:
    with pytest.raises(ValueError, match="SANDFORT_ISOLATION_RUNTIMES: tier 'gvisor' is listed"):
        load(ISOLATION_RUNTIMES="gvisor=runsc,gvisor=kata")


def test_a_default_tier_missing_from_the_map_is_rejected() -> None:
    with pytest.raises(
        ValueError,
        match=(
            "SANDFORT_DEFAULT_ISOLATION: default tier 'microvm' is not available; "
            "available: container, gvisor"
        ),
    ):
        load(ISOLATION_RUNTIMES="container=,gvisor=runsc", DEFAULT_ISOLATION="microvm")


@pytest.mark.parametrize("default", ["vm", "", "CONTAINER"])
def test_an_unknown_default_tier_is_rejected(default: str) -> None:
    with pytest.raises(ValueError, match="SANDFORT_DEFAULT_ISOLATION: unknown tier"):
        load(DEFAULT_ISOLATION=default)


def test_parse_keeps_the_listed_order() -> None:
    parsed = parse_tier_runtimes("microvm=kata,container=")

    assert parsed == (("microvm", "kata"), ("container", ""))


def test_a_sandbox_without_the_label_reports_the_default_tier() -> None:
    assert tier_of({}, "gvisor") == "gvisor"
    assert tier_of({ISOLATION_LABEL: "microvm"}, "container") == "microvm"


# --- SANDFORT_ENFORCE_DISK_QUOTA ----------------------------------------------------


def test_enforce_disk_quota_defaults_to_false() -> None:
    assert load().enforce_disk_quota is False
    assert Settings().enforce_disk_quota is False


@pytest.mark.parametrize(("raw", "expected"), [("true", True), ("1", True), ("false", False)])
def test_enforce_disk_quota_parses_as_a_boolean(raw: str, expected: bool) -> None:
    assert load(ENFORCE_DISK_QUOTA=raw).enforce_disk_quota is expected


def test_enforce_disk_quota_rejects_a_non_boolean() -> None:
    with pytest.raises(ValueError, match="SANDFORT_ENFORCE_DISK_QUOTA must be a boolean"):
        load(ENFORCE_DISK_QUOTA="maybe")


# --- SANDFORT_DEFAULT_BLOCK_NETWORK -------------------------------------------------


def test_default_block_network_defaults_to_false() -> None:
    assert load().default_block_network is False
    assert Settings().default_block_network is False


@pytest.mark.parametrize(("raw", "expected"), [("true", True), ("1", True), ("false", False)])
def test_default_block_network_parses_as_a_boolean(raw: str, expected: bool) -> None:
    assert load(DEFAULT_BLOCK_NETWORK=raw).default_block_network is expected


def test_default_block_network_rejects_a_non_boolean() -> None:
    with pytest.raises(ValueError, match="SANDFORT_DEFAULT_BLOCK_NETWORK must be a boolean"):
        load(DEFAULT_BLOCK_NETWORK="maybe")


# --- SANDFORT_GVISOR_DNS ------------------------------------------------------------


def test_gvisor_dns_defaults_to_two_public_resolvers() -> None:
    for settings in (load(), Settings()):
        assert settings.gvisor_dns == "1.1.1.1,8.8.8.8"
        assert settings.gvisor_nameservers() == ("1.1.1.1", "8.8.8.8")


def test_gvisor_dns_accepts_a_custom_ipv4_and_ipv6_list_in_order() -> None:
    settings = load(GVISOR_DNS=" 9.9.9.9 , 2606:4700:4700::1111,1.0.0.1 ")

    assert settings.gvisor_nameservers() == ("9.9.9.9", "2606:4700:4700::1111", "1.0.0.1")


@pytest.mark.parametrize("raw", ["", "   "])
def test_an_empty_gvisor_dns_means_do_not_touch_resolv_conf(raw: str) -> None:
    settings = load(GVISOR_DNS=raw)

    assert settings.gvisor_dns == ""
    assert settings.gvisor_nameservers() == ()


@pytest.mark.parametrize(
    ("raw", "bad_entry"),
    [
        ("1.1.1.1,not-an-ip", "not-an-ip"),
        ("dns.example.com", "dns.example.com"),
        ("1.1.1.256,8.8.8.8", "1.1.1.256"),
        ("1.1.1.1,,8.8.8.8", ""),
        ("1.1.1.1,", ""),
        ("fe80::1%eth0", "fe80::1%eth0"),
        ("1.1.1.1 8.8.8.8", "1.1.1.1 8.8.8.8"),
        ("1.1.1.1\nnameserver 6.6.6.6", "1.1.1.1\nnameserver 6.6.6.6"),
    ],
)
def test_an_invalid_gvisor_dns_entry_is_rejected_by_name_at_load_time(
    raw: str, bad_entry: str
) -> None:
    message = f"SANDFORT_GVISOR_DNS entry {bad_entry!r} is not an IPv4 or IPv6 address"

    with pytest.raises(ValueError, match=re.escape(message)):
        load(GVISOR_DNS=raw)


# --- SANDFORT_FORWARDED_ALLOW_IPS ---------------------------------------------------


def test_forwarded_allow_ips_defaults_to_loopback_only() -> None:
    for settings in (load(), Settings()):
        assert settings.forwarded_allow_ips == "127.0.0.1"


@pytest.mark.parametrize("raw", ["10.0.0.1,10.0.0.2", "*", "10.1.2.3"])
def test_forwarded_allow_ips_is_read_from_the_environment_verbatim(raw: str) -> None:
    assert load(FORWARDED_ALLOW_IPS=raw).forwarded_allow_ips == raw
