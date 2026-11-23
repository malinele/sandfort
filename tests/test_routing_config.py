"""Routing settings: the advertised node address, the route secret and the hop timeout."""

import pytest

from sandfort.config import MIN_SESSION_SECRET_CHARS, Settings

GOOD_SECRET = "r" * MIN_SESSION_SECRET_CHARS
GOOD_URL = "http://10.0.0.5:8000"
ROUTING_ENV = {
    "SANDFORT_NODE_INTERNAL_URL": GOOD_URL,
    "SANDFORT_ROUTING_SECRET": GOOD_SECRET,
}


def test_defaults_are_empty_and_routing_is_off() -> None:
    defaults = Settings.from_env({})

    assert defaults.node_internal_url == ""
    assert defaults.routing_secret == ""
    assert defaults.routing_timeout_s == 5.0
    assert Settings().routing_secret == ""


def test_a_valid_address_and_secret_pair_loads() -> None:
    settings = Settings.from_env({**ROUTING_ENV, "SANDFORT_ROUTING_TIMEOUT_S": "2.5"})

    assert settings.node_internal_url == GOOD_URL
    assert settings.routing_secret == GOOD_SECRET
    assert settings.routing_timeout_s == 2.5


@pytest.mark.parametrize(
    "url",
    [
        "http://node-beta:8000",
        "http://sandfort_beta:80",
        "http://[fd00::5]:65535",
        " http://b:1 ",
    ],
)
def test_hostnames_and_bracketed_ipv6_addresses_are_accepted(url: str) -> None:
    settings = Settings.from_env({**ROUTING_ENV, "SANDFORT_NODE_INTERNAL_URL": url})

    assert settings.node_internal_url == url.strip()


def test_a_secret_without_an_address_loads_for_a_forward_only_edge() -> None:
    settings = Settings.from_env({"SANDFORT_ROUTING_SECRET": GOOD_SECRET})

    assert (settings.node_internal_url, settings.routing_secret) == ("", GOOD_SECRET)


@pytest.mark.parametrize("secret", ["x", "s" * (MIN_SESSION_SECRET_CHARS - 1)])
def test_a_short_routing_secret_is_rejected(secret: str) -> None:
    with pytest.raises(ValueError, match="SANDFORT_ROUTING_SECRET must be at least"):
        Settings.from_env({**ROUTING_ENV, "SANDFORT_ROUTING_SECRET": secret})


def test_a_short_routing_secret_is_rejected_without_an_address() -> None:
    with pytest.raises(ValueError, match="SANDFORT_ROUTING_SECRET must be at least"):
        Settings.from_env({"SANDFORT_ROUTING_SECRET": "short"})


@pytest.mark.parametrize(
    "url",
    [
        pytest.param("http://10.0.0.5:8000/v1", id="path"),
        pytest.param("http://10.0.0.5:8000/", id="bare-slash-path"),
        pytest.param("http://10.0.0.5:8000?x=1", id="query"),
        pytest.param("http://10.0.0.5:8000#top", id="fragment"),
        pytest.param("http://ops@10.0.0.5:8000", id="userinfo"),
        pytest.param("http://ops:pw@10.0.0.5:8000", id="userinfo-password"),
        pytest.param("https://10.0.0.5:8000", id="https"),
        pytest.param("10.0.0.5:8000", id="no-scheme"),
        pytest.param("http://10.0.0.5", id="no-port"),
        pytest.param("http://10.0.0.5:0", id="port-zero"),
        pytest.param("http://10.0.0.5:65536", id="port-too-large"),
        pytest.param("http://:8000", id="no-host"),
    ],
)
def test_a_malformed_node_internal_url_is_rejected(url: str) -> None:
    with pytest.raises(ValueError, match="NODE_INTERNAL_URL must be http://host:port"):
        Settings.from_env({**ROUTING_ENV, "SANDFORT_NODE_INTERNAL_URL": url})


def test_the_rejection_does_not_echo_userinfo() -> None:
    url = "http://ops:hunter2-password@10.0.0.5:8000"

    with pytest.raises(ValueError) as caught:
        Settings.from_env({**ROUTING_ENV, "SANDFORT_NODE_INTERNAL_URL": url})

    assert "hunter2-password" not in str(caught.value)


def test_an_address_without_a_routing_secret_is_a_startup_error() -> None:
    with pytest.raises(ValueError, match="NODE_INTERNAL_URL needs SANDFORT_ROUTING_SECRET"):
        Settings.from_env({"SANDFORT_NODE_INTERNAL_URL": GOOD_URL})


@pytest.mark.parametrize("timeout", ["0", "-1", "-0.5", "nan", "inf", "soon"])
def test_a_non_positive_or_malformed_timeout_is_rejected(timeout: str) -> None:
    with pytest.raises(ValueError, match="SANDFORT_ROUTING_TIMEOUT_S"):
        Settings.from_env({**ROUTING_ENV, "SANDFORT_ROUTING_TIMEOUT_S": timeout})

