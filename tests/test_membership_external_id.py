"""Membership external id: storage round trip, set and clear, per-org uniqueness."""

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
from sandfort.domain.user import OrgMembership, OrgRole, User
from sandfort.errors import Conflict
from sandfort.ids import new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
LATER = NOW + timedelta(hours=1)
EXTERNAL_ID = "okta-00u1"

Factory = async_sessionmaker[AsyncSession]


def make_user(user_id: str, email: str) -> User:
    return User(id=user_id, email=email, display_name=user_id.title(), created_at=NOW)


def make_org(slug: str) -> Org:
    return Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)


def make_membership(user_id: str, org_id: str, external_id: str | None = None) -> OrgMembership:
    return OrgMembership(
        user_id=user_id,
        org_id=org_id,
        role=OrgRole.VIEWER,
        created_at=NOW,
        external_id=external_id,
    )


@pytest.fixture
async def factory(tmp_path: Path) -> AsyncIterator[Factory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    db_path = tmp_path / "external-id.db"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    command.upgrade(config, "head")
    engine = create_engine(Settings(database_url=f"sqlite+aiosqlite:///{db_path}"))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


async def seed(factory: Factory, *orgs: Org) -> None:
    """Two users and the given orgs, with no memberships yet."""
    async with UnitOfWork(factory) as uow:
        for org in orgs:
            await uow.orgs.add(org)
        await uow.users.add(make_user("usr1", "a@example.com"))
        await uow.users.add(make_user("usr2", "b@example.com"))
        await uow.commit()


def test_external_id_defaults_to_none() -> None:
    membership = OrgMembership(user_id="usr1", org_id="org1", role=OrgRole.ADMIN, created_at=NOW)

    assert membership.external_id is None


async def test_external_id_round_trips_through_add_and_get(factory: Factory) -> None:
    org = make_org("acme")
    await seed(factory, org)
    async with UnitOfWork(factory) as uow:
        await uow.memberships.add(make_membership("usr1", org.id, EXTERNAL_ID))
        await uow.memberships.add(make_membership("usr2", org.id))
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        with_id = await uow.memberships.get("usr1", org.id)
        without_id = await uow.memberships.get("usr2", org.id)
        listed = await uow.memberships.list_for_org(org.id)

    assert with_id is not None
    assert with_id.external_id == EXTERNAL_ID
    assert without_id is not None
    assert without_id.external_id is None
    assert {m.user_id: m.external_id for m in listed} == {"usr1": EXTERNAL_ID, "usr2": None}


async def test_lookup_by_external_id_is_scoped_to_the_org(factory: Factory) -> None:
    org, other = make_org("acme"), make_org("globex")
    await seed(factory, org, other)
    async with UnitOfWork(factory) as uow:
        await uow.memberships.add(make_membership("usr1", org.id, EXTERNAL_ID))
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        found = await uow.memberships.get_by_external_id(org.id, EXTERNAL_ID)
        wrong_org = await uow.memberships.get_by_external_id(other.id, EXTERNAL_ID)
        unknown = await uow.memberships.get_by_external_id(org.id, "okta-missing")

    assert found is not None
    assert found.user_id == "usr1"
    assert wrong_org is None
    assert unknown is None


async def test_set_and_clear_external_id(factory: Factory) -> None:
    org = make_org("acme")
    await seed(factory, org)
    async with UnitOfWork(factory) as uow:
        await uow.memberships.add(make_membership("usr1", org.id))
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        set_result = await uow.memberships.set_external_id("usr1", org.id, EXTERNAL_ID, LATER)
        await uow.commit()
    async with UnitOfWork(factory) as uow:
        after_set = await uow.memberships.get("usr1", org.id)
        replaced = await uow.memberships.set_external_id("usr1", org.id, "okta-00u2", LATER)
        await uow.commit()
    async with UnitOfWork(factory) as uow:
        cleared = await uow.memberships.set_external_id("usr1", org.id, None, LATER)
        await uow.commit()
    async with UnitOfWork(factory) as uow:
        after_clear = await uow.memberships.get("usr1", org.id)
        old_lookup = await uow.memberships.get_by_external_id(org.id, EXTERNAL_ID)

    assert set_result is not None
    assert set_result.external_id == EXTERNAL_ID
    assert after_set is not None
    assert after_set.external_id == EXTERNAL_ID
    assert replaced is not None
    assert replaced.external_id == "okta-00u2"
    assert cleared is not None
    assert cleared.external_id is None
    assert after_clear is not None
    assert after_clear.external_id is None
    assert old_lookup is None


async def test_set_external_id_on_missing_membership_returns_none(factory: Factory) -> None:
    org = make_org("acme")
    await seed(factory, org)

    async with UnitOfWork(factory) as uow:
        result = await uow.memberships.set_external_id("usr1", org.id, EXTERNAL_ID, LATER)

    assert result is None


async def test_duplicate_external_id_in_one_org_conflicts_on_set(factory: Factory) -> None:
    org = make_org("acme")
    await seed(factory, org)
    async with UnitOfWork(factory) as uow:
        await uow.memberships.add(make_membership("usr1", org.id, EXTERNAL_ID))
        await uow.memberships.add(make_membership("usr2", org.id))
        await uow.commit()

    with pytest.raises(Conflict):
        async with UnitOfWork(factory) as uow:
            await uow.memberships.set_external_id("usr2", org.id, EXTERNAL_ID, LATER)

    async with UnitOfWork(factory) as uow:
        loser = await uow.memberships.get("usr2", org.id)
    assert loser is not None
    assert loser.external_id is None


async def test_duplicate_external_id_in_one_org_conflicts_on_add(factory: Factory) -> None:
    org = make_org("acme")
    await seed(factory, org)
    async with UnitOfWork(factory) as uow:
        await uow.memberships.add(make_membership("usr1", org.id, EXTERNAL_ID))
        await uow.commit()

    with pytest.raises(Conflict):
        async with UnitOfWork(factory) as uow:
            await uow.memberships.add(make_membership("usr2", org.id, EXTERNAL_ID))


async def test_same_external_id_in_two_orgs_is_allowed(factory: Factory) -> None:
    org, other = make_org("acme"), make_org("globex")
    await seed(factory, org, other)
    async with UnitOfWork(factory) as uow:
        await uow.memberships.add(make_membership("usr1", org.id, EXTERNAL_ID))
        await uow.memberships.add(make_membership("usr1", other.id))
        await uow.memberships.add(make_membership("usr2", other.id))
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        same_user = await uow.memberships.set_external_id("usr1", other.id, EXTERNAL_ID, LATER)
        other_user = await uow.memberships.set_external_id("usr2", other.id, "okta-00u2", LATER)
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        in_org = await uow.memberships.get_by_external_id(org.id, EXTERNAL_ID)
        in_other = await uow.memberships.get_by_external_id(other.id, EXTERNAL_ID)

    assert same_user is not None
    assert other_user is not None
    assert in_org is not None
    assert in_org.org_id == org.id
    assert in_other is not None
    assert in_other.org_id == other.id


async def test_two_members_without_external_id_do_not_collide(factory: Factory) -> None:
    org = make_org("acme")
    await seed(factory, org)

    async with UnitOfWork(factory) as uow:
        await uow.memberships.add(make_membership("usr1", org.id))
        await uow.memberships.add(make_membership("usr2", org.id))
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        listed = await uow.memberships.list_for_org(org.id)
    assert [m.external_id for m in listed] == [None, None]
