"""Bridge interface names of the driver-managed networks (isolation audit H5)."""

import logging
from types import SimpleNamespace
from typing import Any

import pytest

from sandfort.api.schemas.sandboxes import CreateSandboxRequest
from sandfort.drivers.docker import networks
from sandfort.drivers.docker.networks import (
    BRIDGE_NAME_OPTION,
    EGRESS_NETWORK_NAME,
    ICC_OPTION,
    NETWORK_NAME,
    ensure_network,
)


@pytest.fixture(autouse=True)
def _reset_warned(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(networks, "_warned", set())
    monkeypatch.delenv("SF_BRIDGE_IFACE", raising=False)
    monkeypatch.delenv("SF_EGRESS_BRIDGE_IFACE", raising=False)


class FakeNetworks:
    def __init__(self, existing: list[Any] | None = None) -> None:
        self.existing = existing or []
        self.created: list[tuple[str, dict[str, Any]]] = []

    def list(self, **_: Any) -> list[Any]:
        return self.existing

    def create(self, name: str, **kwargs: Any) -> None:
        self.created.append((name, kwargs))


def _client(existing: list[Any] | None = None) -> Any:
    return SimpleNamespace(networks=FakeNetworks(existing))


def _network(name: str, options: dict[str, str] | None) -> Any:
    return SimpleNamespace(name=name, attrs={"Options": options})


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("name", "bridge"),
    [(NETWORK_NAME, "sf-br0"), (EGRESS_NETWORK_NAME, "sf-br1")],
)
async def test_creates_network_with_fixed_bridge_name(name: str, bridge: str) -> None:
    client = _client()

    assert await ensure_network(client, name) == name

    created_name, kwargs = client.networks.created[0]
    assert created_name == name
    assert kwargs["options"][BRIDGE_NAME_OPTION] == bridge
    assert kwargs["options"][ICC_OPTION] == "false"


@pytest.mark.anyio
async def test_existing_network_with_expected_bridge_does_not_warn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = _client([_network(NETWORK_NAME, {BRIDGE_NAME_OPTION: "sf-br0"})])

    with caplog.at_level(logging.WARNING):
        await ensure_network(client)

    assert client.networks.created == []
    assert caplog.records == []


@pytest.mark.anyio
@pytest.mark.parametrize("options", [None, {}, {BRIDGE_NAME_OPTION: "br-abc"}])
async def test_existing_network_without_bridge_name_warns_and_is_kept(
    options: dict[str, str] | None, caplog: pytest.LogCaptureFixture
) -> None:
    client = _client([_network(EGRESS_NETWORK_NAME, options)])

    with caplog.at_level(logging.WARNING):
        result = await ensure_network(client, EGRESS_NETWORK_NAME)

    assert result == EGRESS_NETWORK_NAME
    assert client.networks.created == []
    messages = [record.getMessage() for record in caplog.records]
    assert any(EGRESS_NETWORK_NAME in m and "sf-br1" in m for m in messages)


@pytest.mark.anyio
async def test_mismatch_warning_is_logged_once_per_network_name(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = _client([_network(NETWORK_NAME, None), _network(EGRESS_NETWORK_NAME, None)])

    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            await ensure_network(client)
        await ensure_network(client, EGRESS_NETWORK_NAME)
        await ensure_network(client, EGRESS_NETWORK_NAME)

    messages = [record.getMessage() for record in caplog.records]
    assert len(messages) == 2
    assert sum(NETWORK_NAME + " " in m for m in messages) == 1
    assert sum(EGRESS_NETWORK_NAME in m for m in messages) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("name", "variable"),
    [(NETWORK_NAME, "SF_BRIDGE_IFACE"), (EGRESS_NETWORK_NAME, "SF_EGRESS_BRIDGE_IFACE")],
)
async def test_host_script_interface_variable_is_the_expected_name(
    name: str, variable: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(variable, "corp-br7")
    client = _client([_network(name, {BRIDGE_NAME_OPTION: "corp-br7"})])

    with caplog.at_level(logging.WARNING):
        await ensure_network(client, name)

    assert caplog.records == []


@pytest.mark.anyio
async def test_default_name_warns_when_variable_names_another_interface(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("SF_BRIDGE_IFACE", "corp-br7")
    client = _client([_network(NETWORK_NAME, {BRIDGE_NAME_OPTION: "sf-br0"})])

    with caplog.at_level(logging.WARNING):
        await ensure_network(client)

    messages = [record.getMessage() for record in caplog.records]
    assert len(messages) == 1
    assert "corp-br7" in messages[0]


@pytest.mark.anyio
async def test_new_network_uses_the_variable_as_bridge_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SF_BRIDGE_IFACE", "corp-br7")
    client = _client()

    await ensure_network(client)

    assert client.networks.created[0][1]["options"][BRIDGE_NAME_OPTION] == "corp-br7"


def test_egress_allowlist_description_documents_empty_list_and_omission() -> None:
    description = CreateSandboxRequest.model_fields["egress_allowlist"].description or ""

    assert "empty list means no network at all (block-all)" in description
    assert "Omitting the field keeps the operator default" in description


@pytest.mark.anyio
async def test_substring_match_is_not_an_existing_network() -> None:
    client = _client([_network("sf-net-other", None)])

    await ensure_network(client)

    assert len(client.networks.created) == 1


@pytest.mark.anyio
async def test_unmanaged_name_gets_no_bridge_option() -> None:
    client = _client()

    await ensure_network(client, "other-net")

    assert BRIDGE_NAME_OPTION not in client.networks.created[0][1]["options"]
