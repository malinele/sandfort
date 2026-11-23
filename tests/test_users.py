"""RBAC foundation: users, org memberships and the role to scope mapping."""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import Org, Scope
from sandfort.domain.user import OrgMembership, OrgRole, User, role_scopes
from sandfort.errors import Conflict
from sandfort.ids import new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)

Factory = async_sessionmaker[AsyncSession]


def make_user(user_id: str, email: str) -> User:
    return User(id=user_id, email=email, display_name=user_id.title(), created_at=NOW)


def make_org(slug: str) -> Org:
    return Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)


def make_membership(user_id: str, org_id: str, role: OrgRole) -> OrgMembership:
    return OrgMembership(user_id=user_id, org_id=org_id, role=role, created_at=NOW)


@pytest.fixture
async def factory(tmp_path: Path) -> AsyncIterator[Factory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    db_path = tmp_path / "users.db"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    command.upgrade(config, "head")
    engine = create_engine(Settings(database_url=f"sqlite+aiosqlite:///{db_path}"))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


async def test_add_and_fetch_user_by_id_and_email(factory: Factory) -> None:
    user = make_user("usr1", "Ada@Example.COM")
    async with UnitOfWork(factory) as uow:
        await uow.users.add(user)
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        by_id = await uow.users.get("usr1")
        by_email = await uow.users.get_by_email("ADA@example.com")
        missing = await uow.users.get("nope")

    assert user.email == "ada@example.com"
    assert by_id == user
    assert by_email == user
    assert missing is None


async def test_duplicate_email_conflicts(factory: Factory) -> None:
    async with UnitOfWork(factory) as uow:
        await uow.users.add(make_user("usr1", "ada@example.com"))
        await uow.commit()

    with pytest.raises(Conflict):
        async with UnitOfWork(factory) as uow:
            await uow.users.add(make_user("usr2", "ADA@example.com"))


async def test_add_and_list_memberships(factory: Factory) -> None:
    org, other = make_org("acme"), make_org("globex")
    async with UnitOfWork(factory) as uow:
        await uow.orgs.add(org)
        await uow.orgs.add(other)
        await uow.users.add(make_user("usr1", "a@example.com"))
        await uow.users.add(make_user("usr2", "b@example.com"))
        await uow.memberships.add(make_membership("usr1", org.id, OrgRole.ADMIN))
        await uow.memberships.add(make_membership("usr2", org.id, OrgRole.VIEWER))
        await uow.memberships.add(make_membership("usr1", other.id, OrgRole.DEVELOPER))
        await uow.commit()

    async with UnitOfWork(factory) as uow:
        listed = await uow.memberships.list_for_org(org.id)
        fetched = await uow.memberships.get("usr1", other.id)
        absent = await uow.memberships.get("usr2", other.id)

    assert {(m.user_id, m.role) for m in listed} == {
        ("usr1", OrgRole.ADMIN),
        ("usr2", OrgRole.VIEWER),
    }
    assert fetched is not None
    assert fetched.role is OrgRole.DEVELOPER
    assert absent is None


async def test_duplicate_membership_conflicts(factory: Factory) -> None:
    org = make_org("acme")
    membership = make_membership("usr1", org.id, OrgRole.ADMIN)
    async with UnitOfWork(factory) as uow:
        await uow.orgs.add(org)
        await uow.users.add(make_user("usr1", "a@example.com"))
        await uow.memberships.add(membership)
        await uow.commit()

    with pytest.raises(Conflict):
        async with UnitOfWork(factory) as uow:
            await uow.memberships.add(membership)


def test_admin_role_has_every_scope() -> None:
    assert role_scopes(OrgRole.ADMIN) == frozenset(Scope)


def test_developer_role_lacks_only_key_admin_and_audit_read() -> None:
    expected = frozenset(Scope) - {Scope.API_KEYS_ADMIN, Scope.AUDIT_READ}

    assert role_scopes(OrgRole.DEVELOPER) == expected


def test_viewer_role_has_exactly_the_read_scopes() -> None:
    assert role_scopes(OrgRole.VIEWER) == frozenset(
        {
            Scope.ORG_READ,
            Scope.SANDBOXES_READ,
            Scope.SNAPSHOTS_READ,
            Scope.VOLUMES_READ,
            Scope.USAGE_READ,
        }
    )
