"""The DNS sink address parse and the proxy's own variable (egress v2 design 3.8).

The proxy binds ``SANDFORT_EGRESS_DNS_SINK_LISTEN``; ``SANDFORT_EGRESS_DNS_SINK_ADDRESS`` is for
the api and the driver. Both accept a bare IPv4 address or ``addr:53`` and nothing else.
"""

import pytest

from sandfort.config import Settings, parse_dns_sink_address
from sandfort.egress.proxy_limits import ProxyConfig

SINK = "172.30.0.1"
LISTEN_VAR = "SANDFORT_EGRESS_DNS_SINK_LISTEN"
ADDRESS_VAR = "SANDFORT_EGRESS_DNS_SINK_ADDRESS"
BASE = {"SANDFORT_EGRESS_SECRET": "s"}
REFUSED = [
    f"{SINK}:5353",
    f"{SINK}:",
    f"{SINK}:053x",
    "::1",
    "[::1]:53",
    "dns.example.com",
    "dns.example.com:53",
    "300.1.1.1",
    f"{SINK},172.30.0.2",
]


def test_parse_accepts_a_bare_address_and_the_53_suffix() -> None:
    assert parse_dns_sink_address(SINK) == SINK
    assert parse_dns_sink_address(f" {SINK} ") == SINK
    assert parse_dns_sink_address(f"{SINK}:53") == SINK
    assert parse_dns_sink_address("") == ""
    assert parse_dns_sink_address("  ") == ""


@pytest.mark.parametrize("bad", REFUSED)
def test_parse_refuses_any_other_form_naming_the_variable(bad: str) -> None:
    with pytest.raises(ValueError, match=ADDRESS_VAR):
        parse_dns_sink_address(bad)
    with pytest.raises(ValueError, match=LISTEN_VAR):
        parse_dns_sink_address(bad, LISTEN_VAR)


def test_settings_accepts_the_53_suffix_and_stores_the_bare_address() -> None:
    assert Settings.from_env({ADDRESS_VAR: f"{SINK}:53"}).egress_dns_sink_address == SINK


@pytest.mark.parametrize("bad", REFUSED)
def test_settings_refuses_the_same_forms(bad: str) -> None:
    with pytest.raises(ValueError, match=ADDRESS_VAR):
        Settings.from_env({ADDRESS_VAR: bad})


def test_the_proxy_reads_its_own_listen_variable() -> None:
    assert ProxyConfig.from_env(BASE).dns_sink_address == ""
    assert ProxyConfig.from_env({**BASE, LISTEN_VAR: f" {SINK} "}).dns_sink_address == SINK
    assert ProxyConfig.from_env({**BASE, LISTEN_VAR: f"{SINK}:53"}).dns_sink_address == SINK


def test_the_proxy_ignores_the_api_side_address_variable() -> None:
    assert ProxyConfig.from_env({**BASE, ADDRESS_VAR: SINK}).dns_sink_address == ""
    both = ProxyConfig.from_env({**BASE, ADDRESS_VAR: "172.30.0.9", LISTEN_VAR: SINK})
    assert both.dns_sink_address == SINK


@pytest.mark.parametrize("bad", REFUSED)
def test_the_proxy_refuses_bad_listen_values_naming_its_variable(bad: str) -> None:
    with pytest.raises(ValueError, match=LISTEN_VAR):
        ProxyConfig.from_env({**BASE, LISTEN_VAR: bad})
