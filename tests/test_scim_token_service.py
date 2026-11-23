"""ScimTokenService: shown once, hash only, attenuation, active cap, idempotent revoke, audit."""

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sandfort.auth.api_keys import SECRET_LENGTH, parse_prefix, verify_api_key
from sandfort.auth.principal import Principal
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType, AuditEvent
from sandfort.domain.org import Org
from sandfort.domain.user import OrgRole, role_scopes
from sandfort.errors import InvalidState, NotFound, ValidationFailed
from sandfort.ids import SCIM_TOKEN, has_prefix, new_org_id
from sandfort.services.api_key_admin import ScopeEscalation
from sandfort.services.scim_tokens import (
    MAX_ACTIVE_SCIM_TOKENS,
    MAX_NAME_CHARS,
    TOKEN_CREATED,
    TOKEN_REVOKED,
    ScimTokenService,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
ADMIN_KEY_ID = "key_admin"

Factory = async_sessionmaker[AsyncSession]


@pytest.fixture
async def factory(tmp_path: Path) -> AsyncIterator[Factory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'scim_token_service.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    engine = create_engine(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(NOW)


@pytest.fixture
def service(factory: Factory, clock: FrozenClock) -> ScimTokenService:
    return ScimTokenService(lambda: UnitOfWork(factory), PEPPER, clock)


@pytest.fixture
async def org_id(factory: Factory) -> str:
    return await add_org(factory, "acme")


async def add_org(factory: Factory, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    async with UnitOfWork(factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


def principal_for(org_id: str, role: OrgRole = OrgRole.ADMIN) -> Principal:
    return Principal(org_id=org_id, key_id=ADMIN_KEY_ID, scopes=role_scopes(role))


async def audit_events(factory: Factory, org_id: str, action: str) -> Sequence[AuditEvent]:
    async with UnitOfWork(factory) as uow:
        return await uow.audit.list(org_id, action=action)


async def test_mint_shows_the_token_once_and_stores_only_its_hash(
    factory: Factory, service: ScimTokenService, org_id: str
) -> None:
    created = await service.mint(principal_for(org_id), "okta", OrgRole.DEVELOPER)

    assert created.token.startswith("sf_scim_")
    assert parse_prefix(created.token) == created.record.prefix
    assert has_prefix(created.record.id, SCIM_TOKEN)
    assert created.record.secret_hash.startswith("v1$")
    assert created.token not in created.record.secret_hash
    assert created.token not in repr(created)
    async with UnitOfWork(factory) as uow:
        stored = await uow.scim_tokens.get_by_prefix(created.record.prefix)
    assert stored == created.record
    assert stored is not None
    assert verify_api_key(PEPPER, created.token, stored.secret_hash)
    assert not verify_api_key("other-pepper", created.token, stored.secret_hash)
    assert created.token not in stored.model_dump_json()
    listed = await service.list_tokens(org_id)
    assert [token.id for token in listed] == [created.record.id]
    assert created.token not in repr(listed)


async def test_mint_records_the_minter_the_time_and_the_ceiling(
    service: ScimTokenService, org_id: str
) -> None:
    created = await service.mint(principal_for(org_id), "  entra  ", OrgRole.VIEWER)

    record = created.record
    assert record.org_id == org_id
    assert record.name == "entra"
    assert record.max_role is OrgRole.VIEWER
    assert record.created_by == ADMIN_KEY_ID
    assert record.created_at == NOW
    assert record.last_used_at is None
    assert record.revoked_at is None


async def test_every_minted_token_is_distinct(service: ScimTokenService, org_id: str) -> None:
    first = await service.mint(principal_for(org_id), "one", OrgRole.VIEWER)
    second = await service.mint(principal_for(org_id), "two", OrgRole.VIEWER)

    assert first.token != second.token
    assert first.record.prefix != second.record.prefix
    assert first.record.secret_hash != second.record.secret_hash


@pytest.mark.parametrize("name", ["", "   "])
async def test_a_blank_name_is_refused(service: ScimTokenService, org_id: str, name: str) -> None:
    with pytest.raises(ValidationFailed):
        await service.mint(principal_for(org_id), name, OrgRole.VIEWER)

    assert await service.list_tokens(org_id) == []


async def test_a_name_longer_than_the_column_is_refused(
    service: ScimTokenService, org_id: str
) -> None:
    with pytest.raises(ValidationFailed):
        await service.mint(principal_for(org_id), "n" * (MAX_NAME_CHARS + 1), OrgRole.VIEWER)

    assert await service.list_tokens(org_id) == []


def test_an_empty_pepper_is_refused(factory: Factory, clock: FrozenClock) -> None:
    with pytest.raises(ValueError, match="pepper"):
        ScimTokenService(lambda: UnitOfWork(factory), "", clock)


@pytest.mark.parametrize(
    ("minter", "requested"),
    [
        (OrgRole.DEVELOPER, OrgRole.ADMIN),
        (OrgRole.VIEWER, OrgRole.DEVELOPER),
        (OrgRole.VIEWER, OrgRole.ADMIN),
    ],
)
async def test_attenuation_refuses_a_max_role_the_minter_lacks(
    factory: Factory,
    service: ScimTokenService,
    org_id: str,
    minter: OrgRole,
    requested: OrgRole,
) -> None:
    with pytest.raises(ScopeEscalation) as raised:
        await service.mint(principal_for(org_id, minter), "okta", requested)

    assert raised.value.details["max_role"] == requested.value
    assert raised.value.details["excess_scopes"]
    assert await service.list_tokens(org_id) == []
    assert await audit_events(factory, org_id, TOKEN_CREATED) == []


@pytest.mark.parametrize(
    ("minter", "requested"),
    [
        (OrgRole.ADMIN, OrgRole.ADMIN),
        (OrgRole.ADMIN, OrgRole.VIEWER),
        (OrgRole.DEVELOPER, OrgRole.DEVELOPER),
        (OrgRole.DEVELOPER, OrgRole.VIEWER),
        (OrgRole.VIEWER, OrgRole.VIEWER),
    ],
)
async def test_attenuation_allows_a_max_role_the_minter_holds(
    service: ScimTokenService, org_id: str, minter: OrgRole, requested: OrgRole
) -> None:
    created = await service.mint(principal_for(org_id, minter), "okta", requested)

    assert created.record.max_role is requested


async def test_the_sixth_active_token_is_refused(
    factory: Factory, service: ScimTokenService, org_id: str
) -> None:
    admin = principal_for(org_id)
    for serial in range(MAX_ACTIVE_SCIM_TOKENS):
        await service.mint(admin, f"token-{serial}", OrgRole.VIEWER)

    with pytest.raises(InvalidState):
        await service.mint(admin, "one-too-many", OrgRole.VIEWER)

    assert len(await service.list_tokens(org_id)) == MAX_ACTIVE_SCIM_TOKENS
    assert len(await audit_events(factory, org_id, TOKEN_CREATED)) == MAX_ACTIVE_SCIM_TOKENS


async def test_revoking_a_token_frees_a_slot_for_rotation(
    service: ScimTokenService, org_id: str
) -> None:
    admin = principal_for(org_id)
    minted = [await service.mint(admin, f"token-{n}", OrgRole.VIEWER) for n in range(5)]

    await service.revoke(admin, minted[0].record.id)
    replacement = await service.mint(admin, "replacement", OrgRole.VIEWER)

    listed = await service.list_tokens(org_id)
    assert len(listed) == MAX_ACTIVE_SCIM_TOKENS + 1
    assert sum(1 for token in listed if token.revoked_at is None) == MAX_ACTIVE_SCIM_TOKENS
    assert replacement.record.id in {token.id for token in listed}


async def test_the_cap_is_counted_per_org(
    factory: Factory, service: ScimTokenService, org_id: str
) -> None:
    other_org = await add_org(factory, "globex")
    for serial in range(MAX_ACTIVE_SCIM_TOKENS):
        await service.mint(principal_for(org_id), f"token-{serial}", OrgRole.VIEWER)

    created = await service.mint(principal_for(other_org), "okta", OrgRole.VIEWER)

    assert created.record.org_id == other_org
    assert [token.id for token in await service.list_tokens(other_org)] == [created.record.id]


async def test_revoke_marks_the_token_and_audits_once(
    factory: Factory, service: ScimTokenService, clock: FrozenClock, org_id: str
) -> None:
    admin = principal_for(org_id)
    created = await service.mint(admin, "okta", OrgRole.DEVELOPER)
    clock.advance(timedelta(minutes=5))

    revoked = await service.revoke(admin, created.record.id)

    assert revoked.revoked_at == NOW + timedelta(minutes=5)
    assert revoked.id == created.record.id
    async with UnitOfWork(factory) as uow:
        stored = await uow.scim_tokens.get_by_prefix(created.record.prefix)
    assert stored == revoked
    assert len(await audit_events(factory, org_id, TOKEN_REVOKED)) == 1


async def test_revoke_is_idempotent_and_records_no_second_audit_event(
    factory: Factory, service: ScimTokenService, clock: FrozenClock, org_id: str
) -> None:
    admin = principal_for(org_id)
    created = await service.mint(admin, "okta", OrgRole.VIEWER)
    first = await service.revoke(admin, created.record.id)
    clock.advance(timedelta(hours=1))

    again = await service.revoke(admin, created.record.id)

    assert again == first
    assert again.revoked_at == NOW
    assert len(await audit_events(factory, org_id, TOKEN_REVOKED)) == 1


async def test_revoking_an_unknown_token_is_not_found(
    factory: Factory, service: ScimTokenService, org_id: str
) -> None:
    with pytest.raises(NotFound):
        await service.revoke(principal_for(org_id), "stk_" + "0" * 25)

    assert await audit_events(factory, org_id, TOKEN_REVOKED) == []


async def test_a_token_of_another_org_cannot_be_revoked(
    factory: Factory, service: ScimTokenService, org_id: str
) -> None:
    other_org = await add_org(factory, "globex")
    foreign = await service.mint(principal_for(other_org), "okta", OrgRole.VIEWER)

    with pytest.raises(NotFound):
        await service.revoke(principal_for(org_id), foreign.record.id)

    still_active = await service.list_tokens(other_org)
    assert [token.revoked_at for token in still_active] == [None]
    assert await audit_events(factory, other_org, TOKEN_REVOKED) == []


async def test_list_shows_only_the_callers_org_oldest_first(
    service: ScimTokenService, factory: Factory, org_id: str
) -> None:
    other_org = await add_org(factory, "globex")
    first = await service.mint(principal_for(org_id), "first", OrgRole.VIEWER)
    await service.mint(principal_for(other_org), "foreign", OrgRole.VIEWER)
    second = await service.mint(principal_for(org_id), "second", OrgRole.VIEWER)

    listed = await service.list_tokens(org_id)

    assert [token.id for token in listed] == [first.record.id, second.record.id]


async def test_mint_audit_event_carries_name_prefix_and_role_only(
    factory: Factory, service: ScimTokenService, org_id: str
) -> None:
    created = await service.mint(principal_for(org_id), "okta", OrgRole.DEVELOPER)

    events = await audit_events(factory, org_id, TOKEN_CREATED)

    assert len(events) == 1
    event = events[0]
    assert event.actor_type is ActorType.API_KEY
    assert event.actor_id == ADMIN_KEY_ID
    assert event.target_type == "scim_token"
    assert event.target_id == created.record.id
    assert event.details == {
        "name": "okta",
        "prefix": created.record.prefix,
        "max_role": "developer",
    }


async def test_revoke_audit_event_carries_name_prefix_and_role_only(
    factory: Factory, service: ScimTokenService, org_id: str
) -> None:
    admin = principal_for(org_id)
    created = await service.mint(admin, "okta", OrgRole.VIEWER)

    await service.revoke(admin, created.record.id)

    events = await audit_events(factory, org_id, TOKEN_REVOKED)
    assert len(events) == 1
    assert events[0].actor_id == ADMIN_KEY_ID
    assert events[0].target_id == created.record.id
    assert events[0].details == {
        "name": "okta",
        "prefix": created.record.prefix,
        "max_role": "viewer",
    }


async def test_no_audit_event_contains_the_token_or_its_hash(
    factory: Factory, service: ScimTokenService, org_id: str
) -> None:
    admin = principal_for(org_id)
    created = await service.mint(admin, "okta", OrgRole.VIEWER)
    await service.revoke(admin, created.record.id)

    async with UnitOfWork(factory) as uow:
        events = await uow.audit.list(org_id)

    assert {event.action for event in events} == {TOKEN_CREATED, TOKEN_REVOKED}
    secret_part = created.token[len(created.record.prefix) + 1 :]
    assert len(secret_part) == SECRET_LENGTH
    for event in events:
        dumped = event.model_dump_json()
        assert created.token not in dumped
        assert secret_part not in dumped
        assert created.record.secret_hash not in dumped
        assert "secret_hash" not in event.details


async def test_touch_last_used_records_the_time(
    factory: Factory, service: ScimTokenService, clock: FrozenClock, org_id: str
) -> None:
    created = await service.mint(principal_for(org_id), "okta", OrgRole.VIEWER)
    clock.advance(timedelta(minutes=3))

    await service.touch_last_used(created.record.id)

    async with UnitOfWork(factory) as uow:
        stored = await uow.scim_tokens.get_by_prefix(created.record.prefix)
    assert stored is not None
    assert stored.last_used_at == NOW + timedelta(minutes=3)
    assert stored.revoked_at is None
