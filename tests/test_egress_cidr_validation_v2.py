"""Egress v2 round 1 (docs/egress-v2-design.md section 12.1): CIDR entries in validation.

Direct ``check_egress_allowlist`` calls plus one API roundtrip (FakeDriver, temp SQLite).
"""

from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.egress_entries import cidr_problem
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.domain.sandbox import NetworkPolicy, check_egress_allowlist
from sandfort.errors import Unprocessable
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
BASE = "/v1/sandboxes"
LIMIT = 16
OPEN = NetworkPolicy()
BLOCKED = NetworkPolicy(block_all=True)
READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})
PROXY_ADDRESS = "proxy.internal:3128"
EGRESS_SECRET = "e" * 40
PROXY_SETTINGS = {"egress_proxy_address": PROXY_ADDRESS, "egress_secret": EGRESS_SECRET}

AppFactory = Callable[..., FastAPI]


def test_a_public_slash_24_passes() -> None:
    check_egress_allowlist(("8.8.8.0/24",), OPEN, LIMIT)


def test_hosts_domains_and_a_cidr_can_be_mixed() -> None:
    check_egress_allowlist(("api.example.com", ".example.com", "8.8.8.0/24"), OPEN, LIMIT)


def test_a_public_ipv6_range_passes() -> None:
    check_egress_allowlist(("2606:4700::/32",), OPEN, LIMIT)


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        ("10.0.0.1/8", "host bits set"),
        ("10.0.0.0/8", "entirely global"),
        ("192.168.0.0/16", "entirely global"),
        ("127.0.0.0/8", "entirely global"),
        ("0.0.0.0/0", "at least /8"),
        ("::/0", "at least /32"),
        ("2001:DB8::/32", "canonical"),
        ("198.51.100.0/24", "entirely global"),
        ("8.0.0.0/7", "at least /8"),
        ("fe80::/32", "entirely global"),
        ("2606:4700::%eth0/32", "canonical"),  # zone id in a CIDR entry
        ("::ffff:0:0:0/96", "entirely global"),  # IPv4-translated (SIIT) space
        ("::a9fe:0/112", "entirely global"),  # IPv4-compatible block around the metadata IP
        ("fec0::/32", "entirely global"),  # deprecated site-local
        ("5f00::/32", "entirely global"),  # SRv6 SID space
        ("example.com/v1", "path"),  # not a network: the hostname message stays pinned
    ],
)
def test_refuses_unfit_cidr_entries(entry: str, reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        check_egress_allowlist((entry,), OPEN, LIMIT)


def test_an_unparsable_entry_gets_the_canonical_message_from_cidr_problem() -> None:
    problem = cidr_problem("08.8.8.0/24")

    assert problem is not None
    assert "canonical" in problem


def test_a_documentation_range_passes_only_with_an_injected_permissive_check() -> None:
    assert cidr_problem("198.51.100.0/24", is_global=lambda network: True) is None
    assert cidr_problem("198.51.100.0/24") is not None


def test_a_range_overlapping_a_denied_network_is_refused() -> None:
    with pytest.raises(ValueError, match="overlaps a denied network"):
        check_egress_allowlist(("8.8.8.0/24",), OPEN, LIMIT, denied=("8.8.0.0/16",))

    check_egress_allowlist(("8.8.8.0/24",), OPEN, LIMIT, denied=("9.9.9.0/24",))


def test_denied_networks_of_the_other_family_do_not_overlap() -> None:
    check_egress_allowlist(("8.8.8.0/24",), OPEN, LIMIT, denied=("::1/128", "fe80::/10"))


def test_the_cap_counts_every_entry_form() -> None:
    entries = tuple(f"host{index}.example.com" for index in range(9)) + tuple(
        f"8.8.{index}.0/24" for index in range(8)
    )

    with pytest.raises(ValueError, match="at most 16 entries, got 17"):
        check_egress_allowlist(entries, OPEN, LIMIT)


def test_the_caller_still_chooses_the_error_type() -> None:
    with pytest.raises(Unprocessable, match="entirely global"):
        check_egress_allowlist(("10.0.0.0/8",), OPEN, LIMIT, Unprocessable)


def test_a_cidr_entry_contradicts_block_all() -> None:
    with pytest.raises(ValueError, match="contradicts network.block_all"):
        check_egress_allowlist(("8.8.8.0/24",), BLOCKED, LIMIT)


# -- api roundtrip -------------------------------------------------------------------------


@pytest.fixture
async def make_app(tmp_path: Path) -> AsyncIterator[AppFactory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    built: list[FastAPI] = []

    def build(**overrides: Any) -> FastAPI:
        url = f"sqlite+aiosqlite:///{tmp_path / f'egress-{len(built)}.db'}"
        config = Config(str(ROOT / "alembic.ini"))
        config.set_main_option("sqlalchemy.url", url)
        command.upgrade(config, "head")
        settings = Settings(
            driver="fake",
            database_url=url,
            api_key_pepper=PEPPER,
            autostop_enabled=False,
            **overrides,
        )
        app = create_app(settings)
        built.append(app)
        return app

    yield build
    for app in built:
        await app.state.engine.dispose()


async def connect(app: FastAPI) -> str:
    """A fresh org and a plaintext read-write API key for it."""
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=READ_WRITE,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def send(app: FastAPI, key: str, method: str, path: str, **kwargs: Any) -> httpx.Response:
    headers = {"Authorization": f"Bearer {key}"}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        return await http.request(method, path, headers=headers, **kwargs)


async def test_create_with_a_cidr_entry_echoes_it(make_app: AppFactory) -> None:
    app = make_app(**PROXY_SETTINGS)
    key = await connect(app)

    created = await send(
        app, key, "POST", BASE, json={"name": "cidr", "egress_allowlist": ["8.8.8.0/24"]}
    )

    assert created.status_code == 201, created.text
    assert created.json()["data"]["egress_allowlist"] == ["8.8.8.0/24"]


async def test_create_with_a_private_cidr_is_refused_naming_the_entry(
    make_app: AppFactory,
) -> None:
    app = make_app(**PROXY_SETTINGS)
    key = await connect(app)

    response = await send(
        app, key, "POST", BASE, json={"name": "bad", "egress_allowlist": ["10.0.0.0/8"]}
    )

    assert response.status_code == Unprocessable.status, response.text
    message = response.json()["error"]["message"]
    assert "egress_allowlist entry '10.0.0.0/8'" in message
    assert "entirely global" in message
