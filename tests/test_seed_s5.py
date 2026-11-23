"""Seed S5 checks: preview host parser, preview tokens, access policy, conformance entry."""

from datetime import timedelta

import pytest

from sandfort.clock import FrozenClock
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_org_id, new_sandbox_id
from sandfort.proxy.app import create_proxy_app
from sandfort.proxy.routing import PreviewTarget, parse_preview_host
from sandfort.proxy.tokens import (
    InMemoryPreviewTokenStore,
    PreviewTokenInvalid,
    authorize_preview,
)
from sandfort.testing.driver_contract import PROTOCOLS, DriverContract, DriverContractError

SANDBOX_ID = new_sandbox_id()
ID_BODY = SANDBOX_ID.split("_", 1)[1]
ORG_ID = new_org_id()
PORT = 8080
DOMAIN = "preview.example.com"


def host(port: str = str(PORT), sandbox_id: str = SANDBOX_ID, rest: str = DOMAIN) -> str:
    return f"{port}-{sandbox_id}.{rest}"


def test_parses_valid_preview_host() -> None:
    assert parse_preview_host(host()) == PreviewTarget(port=PORT, sandbox_id=SANDBOX_ID)


def test_parses_boundary_ports_and_nested_domain() -> None:
    assert parse_preview_host(host("1024")) == PreviewTarget(1024, SANDBOX_ID)
    nested = host("65535", rest="preview.a.b.example.org")
    assert parse_preview_host(nested) == PreviewTarget(65535, SANDBOX_ID)


def test_host_is_case_insensitive_and_id_is_canonicalised() -> None:
    assert parse_preview_host(host().upper()) == PreviewTarget(PORT, SANDBOX_ID)
    assert parse_preview_host(host().lower()) == PreviewTarget(PORT, SANDBOX_ID)


@pytest.mark.parametrize(
    "port", ["1023", "0", "65536", "99999", "080800", "08080", "-1", "", "80a"]
)
def test_rejects_bad_port(port: str) -> None:
    assert parse_preview_host(host(port)) is None


@pytest.mark.parametrize(
    "sandbox_id",
    [
        "",
        "sbx_short",
        f"org_{ID_BODY}",
        f"sbx_{ID_BODY}0",
        "sbx_" + "U" * 25,
        ID_BODY,
    ],
)
def test_rejects_bad_sandbox_id(sandbox_id: str) -> None:
    assert parse_preview_host(host(sandbox_id=sandbox_id)) is None


@pytest.mark.parametrize(
    "bad_host",
    [
        "",
        "localhost",
        "example.com",
        f"{SANDBOX_ID}.{DOMAIN}",
        f"{PORT}-{SANDBOX_ID}.example.com",
        f"{PORT}-{SANDBOX_ID}.preview",
        f"{PORT}-{SANDBOX_ID}.preview.",
        f"{PORT}-{SANDBOX_ID}.other.example.com",
        f"x.{PORT}-{SANDBOX_ID}.{DOMAIN}",
        f"{PORT}-{SANDBOX_ID}.preview.-bad.com",
        f"{PORT}-{SANDBOX_ID}.{DOMAIN}:8080",
        f" {PORT}-{SANDBOX_ID}.{DOMAIN}",
    ],
)
def test_rejects_missing_or_malformed_labels(bad_host: str) -> None:
    assert parse_preview_host(bad_host) is None


def test_rejects_overlong_host() -> None:
    assert parse_preview_host(host(rest="preview." + "a" * 260)) is None


async def test_preview_token_mint_and_redeem() -> None:
    clock = FrozenClock()
    store = InMemoryPreviewTokenStore(clock)
    token = await store.mint(ORG_ID, SANDBOX_ID, PORT, timedelta(minutes=5))
    grant = await store.redeem(token)
    assert (grant.org_id, grant.sandbox_id, grant.port) == (ORG_ID, SANDBOX_ID, PORT)
    assert grant.expires_at == clock.now() + timedelta(minutes=5)


async def test_preview_token_is_multi_use_until_expiry() -> None:
    clock = FrozenClock()
    store = InMemoryPreviewTokenStore(clock)
    token = await store.mint(ORG_ID, SANDBOX_ID, PORT, timedelta(minutes=5))
    first = await store.redeem(token)
    clock.advance(timedelta(minutes=4))
    assert await store.redeem(token) == first
    clock.advance(timedelta(minutes=1))
    with pytest.raises(PreviewTokenInvalid):
        await store.redeem(token)
    with pytest.raises(PreviewTokenInvalid):
        await store.redeem(token)


async def test_unknown_token_is_invalid() -> None:
    with pytest.raises(PreviewTokenInvalid):
        await InMemoryPreviewTokenStore(FrozenClock()).redeem("nope")


async def test_mint_rejects_bad_port_and_ttl() -> None:
    store = InMemoryPreviewTokenStore(FrozenClock())
    with pytest.raises(ValueError):
        await store.mint(ORG_ID, SANDBOX_ID, 80)
    with pytest.raises(ValueError):
        await store.mint(ORG_ID, SANDBOX_ID, PORT, timedelta(0))


async def test_public_sandbox_bypasses_tokens() -> None:
    store = InMemoryPreviewTokenStore(FrozenClock())
    for token in (None, "junk"):
        grant = await authorize_preview(
            store, sandbox_id=SANDBOX_ID, port=PORT, public=True, token=token
        )
        assert grant is None


async def test_private_sandbox_requires_matching_token() -> None:
    store = InMemoryPreviewTokenStore(FrozenClock())
    token = await store.mint(ORG_ID, SANDBOX_ID, PORT)
    grant = await authorize_preview(
        store, sandbox_id=SANDBOX_ID, port=PORT, public=False, token=token
    )
    assert grant is not None and grant.org_id == ORG_ID
    cases = [
        (SANDBOX_ID, PORT, None),
        (SANDBOX_ID, PORT, ""),
        (SANDBOX_ID, PORT + 1, token),
        (new_sandbox_id(), PORT, token),
    ]
    for sandbox_id, port, candidate in cases:
        with pytest.raises(PreviewTokenInvalid):
            await authorize_preview(
                store, sandbox_id=sandbox_id, port=port, public=False, token=candidate
            )


def test_conformance_entry_check_passes_for_fake_driver() -> None:
    assert DriverContract(FakeDriver()).check_protocols() == list(PROTOCOLS)


def test_conformance_entry_check_reports_missing_protocols() -> None:
    with pytest.raises(DriverContractError, match="compute"):
        DriverContract(object()).check_protocols()


async def test_deferred_checks_name_their_owner() -> None:
    with pytest.raises(NotImplementedError, match="WP 5.6"):
        await DriverContract(FakeDriver()).check_exec()


def test_proxy_app_factory_is_a_stub() -> None:
    with pytest.raises(NotImplementedError, match="WP 5.1"):
        create_proxy_app()
