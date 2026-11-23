"""SCIM token store: add, lookup by prefix, org-scoped listing, revoke and last-used touch."""

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import Org
from sandfort.domain.scim import ScimToken
from sandfort.domain.user import OrgRole
from sandfort.errors import Conflict
from sandfort.ids import new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
PREFIX = "sf_scim_abcd1234"

Factory = async_sessionmaker[AsyncSession]


@pytest.fixture
async def factory(tmp_path: Path) -> AsyncIterator[Factory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'scim_tokens.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    engine = create_engine(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


async def add_org(factory: Factory, slug: str) -> str:
    org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
    async with UnitOfWork(factory) as uow:
        await uow.orgs.add(org)
        await uow.commit()
    return org.id


def make_token(
    org_id: str, serial: int = 1, prefix: str = PREFIX, max_role: OrgRole = OrgRole.VIEWER
) -> ScimToken:
    return ScimToken(
        id=f"stk_{serial:025d}",
        org_id=org_id,
        name=f"okta-{serial}",
        prefix=prefix,
        secret_hash="v1$salt$hashed",
        max_role=max_role,
        created_by="key_admin",
        created_at=NOW,
    )


async def store(factory: Factory, *tokens: ScimToken) -> None:
    async with UnitOfWork(factory) as uow:
        for token in tokens:
            await uow.scim_tokens.add(token)
        await uow.commit()


async def test_added_token_is_found_by_prefix_with_every_field(factory: Factory) -> None:
    org_id = await add_org(factory, "acme")
    token = make_token(org_id, max_role=OrgRole.DEVELOPER)
    await store(factory, token)

    async with UnitOfWork(factory) as uow:
        assert await uow.scim_tokens.get_by_prefix(PREFIX) == token


async def test_unknown_prefix_is_not_found(factory: Factory) -> None:
    org_id = await add_org(factory, "acme")
    await store(factory, make_token(org_id))

    async with UnitOfWork(factory) as uow:
        assert await uow.scim_tokens.get_by_prefix("sf_scim_unknown0") is None


async def test_duplicate_prefix_raises_conflict(factory: Factory) -> None:
    org_id = await add_org(factory, "acme")
    await store(factory, make_token(org_id, serial=1))

    with pytest.raises(Conflict):
        await store(factory, make_token(org_id, serial=2))


async def test_list_for_org_is_oldest_first_and_excludes_other_orgs(factory: Factory) -> None:
    org_id = await add_org(factory, "acme")
    other_id = await add_org(factory, "globex")
    first = make_token(org_id, serial=1, prefix="sf_scim_aaaa0001")
    second = make_token(org_id, serial=2, prefix="sf_scim_aaaa0002")
    foreign = make_token(other_id, serial=3, prefix="sf_scim_bbbb0003")
    await store(factory, second, foreign, first)

    async with UnitOfWork(factory) as uow:
        assert list(await uow.scim_tokens.list_for_org(org_id)) == [first, second]
        assert list(await uow.scim_tokens.list_for_org(other_id)) == [foreign]


async def test_list_for_org_is_empty_without_tokens(factory: Factory) -> None:
    org_id = await add_org(factory, "acme")

    async with UnitOfWork(factory) as uow:
        assert list(await uow.scim_tokens.list_for_org(org_id)) == []


async def test_revoke_marks_the_token_once_and_keeps_it_listed(factory: Factory) -> None:
    org_id = await add_org(factory, "acme")
    token = make_token(org_id)
    await store(factory, token)
    revoked_at = NOW + timedelta(hours=1)

    async with UnitOfWork(factory) as uow:
        assert await uow.scim_tokens.revoke(org_id, token.id, revoked_at)
        assert not await uow.scim_tokens.revoke(org_id, token.id, revoked_at + timedelta(hours=1))
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        stored = await uow.scim_tokens.get_by_prefix(PREFIX)
        assert stored is not None
        assert stored.revoked_at == revoked_at
        assert [item.id for item in await uow.scim_tokens.list_for_org(org_id)] == [token.id]


async def test_revoke_from_another_org_changes_nothing(factory: Factory) -> None:
    org_id = await add_org(factory, "acme")
    other_id = await add_org(factory, "globex")
    token = make_token(org_id)
    await store(factory, token)

    async with UnitOfWork(factory) as uow:
        assert not await uow.scim_tokens.revoke(other_id, token.id, NOW)
        assert not await uow.scim_tokens.revoke(org_id, "stk_missing", NOW)
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        stored = await uow.scim_tokens.get_by_prefix(PREFIX)
        assert stored is not None
        assert stored.revoked_at is None


async def test_touch_last_used_records_the_latest_time(factory: Factory) -> None:
    org_id = await add_org(factory, "acme")
    token = make_token(org_id)
    await store(factory, token)
    first_use = NOW + timedelta(minutes=1)
    second_use = NOW + timedelta(minutes=5)

    async with UnitOfWork(factory) as uow:
        await uow.scim_tokens.touch_last_used(token.id, first_use)
        await uow.scim_tokens.touch_last_used(token.id, second_use)
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        stored = await uow.scim_tokens.get_by_prefix(PREFIX)
        assert stored is not None
        assert stored.last_used_at == second_use
        assert stored.revoked_at is None


async def test_secret_hash_is_not_part_of_the_repr(factory: Factory) -> None:
    org_id = await add_org(factory, "acme")

    assert "hashed" not in repr(make_token(org_id))
