"""SCIM slice five: ``UserAdminService.update_member`` and the read entry points.

Service level, on a temp SQLite database migrated to head; daemon-free. Storage and audit rows
are read back through a fresh unit of work after every call.
"""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sandfort.auth.principal import Principal
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import AuditEvent
from sandfort.domain.org import Org, Scope
from sandfort.domain.user import OrgMembership, OrgRole, role_scopes
from sandfort.errors import Conflict, InvalidState, NotFound, ValidationFailed
from sandfort.ids import new_org_id
from sandfort.services.api_key_admin import ScopeEscalation
from sandfort.services.user_admin import UNSET, Member, UserAdminService

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
EXT = "okta-00u1"
EXT_2 = "okta-00u2"
ADDED = "membership.added"
ROLE_CHANGED = "membership.role_changed"
EXT_CHANGED = "membership.external_id_changed"
REMOVED = "membership.removed"

Factory = async_sessionmaker[AsyncSession]


@dataclass
class World:
    service: UserAdminService
    factory: Factory
    org_id: str
    other_org_id: str
    admin: Principal  # org admin key: holds every scope
    scim: Principal  # a SCIM token capped at the developer role
    other_admin: Principal  # admin of the other org
    root_id: str  # the org's seeded (and only) admin


def make_org(slug: str) -> Org:
    return Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'user-admin-scim.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    engine = create_engine(Settings(database_url=url))
    try:
        factory = create_session_factory(engine)
        org, other = make_org("acme"), make_org("globex")
        async with UnitOfWork(factory) as uow:
            await uow.orgs.add(org)
            await uow.orgs.add(other)
            await uow.commit()
        service = UserAdminService(lambda: UnitOfWork(factory), FrozenClock(NOW))
        everything = frozenset(Scope)
        admin = Principal(org_id=org.id, key_id="key_admin", scopes=everything)
        scim = Principal(org_id=org.id, key_id="stk_scim", scopes=role_scopes(OrgRole.DEVELOPER))
        other_admin = Principal(org_id=other.id, key_id="key_other", scopes=everything)
        root = await service.create_member(admin, "root@example.com", "Root", OrgRole.ADMIN)
        yield World(service, factory, org.id, other.id, admin, scim, other_admin, root.user.id)
    finally:
        await engine.dispose()


async def add(
    world: World,
    email: str,
    role: OrgRole = OrgRole.VIEWER,
    external_id: str | None = None,
) -> Member:
    return await world.service.create_member(
        world.admin, email, email.split("@")[0].title(), role, external_id=external_id
    )


async def stored(world: World, user_id: str) -> OrgMembership | None:
    async with UnitOfWork(world.factory) as uow:
        return await uow.memberships.get(user_id, world.org_id)


async def audit_rows(world: World, action: str | None = None) -> list[AuditEvent]:
    async with UnitOfWork(world.factory) as uow:
        rows = await uow.audit.list(world.org_id, limit=200)
    return [row for row in rows if action is None or row.action == action]


async def audit_count(world: World) -> int:
    return len(await audit_rows(world))


async def assert_stored(world: World, user_id: str, role: OrgRole, ext: str | None) -> None:
    membership = await stored(world, user_id)
    assert membership is not None
    assert (membership.role, membership.external_id) == (role, ext)


# --- create_member with an external id -------------------------------------------------------


async def test_create_member_stores_the_external_id_and_audits_it(world: World) -> None:
    member = await add(world, "ada@example.com", OrgRole.DEVELOPER, EXT)

    assert member.external_id == EXT
    await assert_stored(world, member.user.id, OrgRole.DEVELOPER, EXT)
    added = [row for row in await audit_rows(world, ADDED) if row.target_id == member.user.id]
    assert len(added) == 1
    assert added[0].actor_id == world.admin.key_id
    assert added[0].details == {"email": "ada@example.com", "role": "developer", "external_id": EXT}


async def test_create_member_without_external_id_keeps_the_audit_details(world: World) -> None:
    member = await add(world, "ada@example.com")

    assert member.external_id is None
    added = [row for row in await audit_rows(world, ADDED) if row.target_id == member.user.id]
    assert added[0].details == {"email": "ada@example.com", "role": "viewer"}


async def test_create_member_with_a_taken_external_id_conflicts_and_writes_nothing(
    world: World,
) -> None:
    await add(world, "ada@example.com", external_id=EXT)
    before = await audit_count(world)

    with pytest.raises(Conflict):
        await add(world, "bob@example.com", external_id=EXT)

    async with UnitOfWork(world.factory) as uow:
        assert await uow.users.get_by_email("bob@example.com") is None
    assert await audit_count(world) == before


@pytest.mark.parametrize("bad", ["", "   ", "x" * 256])
async def test_create_member_rejects_a_blank_or_oversized_external_id(
    world: World, bad: str
) -> None:
    with pytest.raises(ValidationFailed):
        await add(world, "ada@example.com", external_id=bad)

    assert await world.service.find_member_by_email(world.org_id, "ada@example.com") is None


async def test_the_same_external_id_in_another_org_is_allowed(world: World) -> None:
    await add(world, "ada@example.com", external_id=EXT)

    other = await world.service.create_member(
        world.other_admin, "bob@example.com", "Bob", OrgRole.VIEWER, external_id=EXT
    )

    assert other.external_id == EXT


# --- get_member, find_member_by_email, list_members ------------------------------------------


async def test_get_member_returns_the_role_and_external_id(world: World) -> None:
    created = await add(world, "ada@example.com", OrgRole.DEVELOPER, EXT)

    fetched = await world.service.get_member(world.org_id, created.user.id)

    assert fetched == created


async def test_get_member_outside_the_org_is_not_found(world: World) -> None:
    created = await add(world, "ada@example.com")

    with pytest.raises(NotFound):
        await world.service.get_member(world.other_org_id, created.user.id)
    with pytest.raises(NotFound):
        await world.service.get_member(world.org_id, "usr_unknown")


async def test_find_member_by_email_normalises_and_is_scoped_to_the_org(world: World) -> None:
    created = await add(world, "ada@example.com", external_id=EXT)

    found = await world.service.find_member_by_email(world.org_id, "  ADA@Example.com ")
    elsewhere = await world.service.find_member_by_email(world.other_org_id, "ada@example.com")
    unknown = await world.service.find_member_by_email(world.org_id, "nobody@example.com")

    assert found == created
    assert elsewhere is None
    assert unknown is None


async def test_list_members_carries_the_external_id(world: World) -> None:
    await add(world, "ada@example.com", external_id=EXT)

    listed = await world.service.list_members(world.org_id)

    assert {m.user.email: m.external_id for m in listed} == {
        "root@example.com": None,
        "ada@example.com": EXT,
    }


# --- update_member: role, external id, audit -------------------------------------------------


async def test_update_role_audits_and_keeps_the_external_id(world: World) -> None:
    created = await add(world, "ada@example.com", external_id=EXT)

    updated = await world.service.update_member(world.scim, created.user.id, role=OrgRole.DEVELOPER)

    assert (updated.role, updated.external_id) == (OrgRole.DEVELOPER, EXT)
    await assert_stored(world, created.user.id, OrgRole.DEVELOPER, EXT)
    (event,) = await audit_rows(world, ROLE_CHANGED)
    assert event.action == "membership.role_changed"
    assert event.details == {"from_role": "viewer", "role": "developer"}
    assert event.actor_id == world.scim.key_id
    assert event.target_id == created.user.id
    assert await audit_rows(world, EXT_CHANGED) == []


async def test_update_external_id_sets_replaces_and_clears_with_one_audit_each(
    world: World,
) -> None:
    created = await add(world, "ada@example.com")
    user_id = created.user.id

    await world.service.update_member(world.scim, user_id, external_id=EXT)
    await world.service.update_member(world.scim, user_id, external_id=EXT_2)
    cleared = await world.service.update_member(world.scim, user_id, external_id=None)

    assert cleared.external_id is None
    await assert_stored(world, user_id, OrgRole.VIEWER, None)
    events = await audit_rows(world, EXT_CHANGED)
    assert {(e.details["from_external_id"], e.details["external_id"]) for e in events} == {
        (None, EXT),
        (EXT, EXT_2),
        (EXT_2, None),
    }
    assert {e.actor_id for e in events} == {world.scim.key_id}
    assert await audit_rows(world, ROLE_CHANGED) == []


async def test_update_role_and_external_id_together_audit_both(world: World) -> None:
    created = await add(world, "ada@example.com")

    updated = await world.service.update_member(
        world.scim, created.user.id, role=OrgRole.DEVELOPER, external_id=EXT
    )

    assert (updated.role, updated.external_id) == (OrgRole.DEVELOPER, EXT)
    await assert_stored(world, created.user.id, OrgRole.DEVELOPER, EXT)
    assert len(await audit_rows(world, ROLE_CHANGED)) == 1
    assert len(await audit_rows(world, EXT_CHANGED)) == 1


async def test_update_without_effective_changes_writes_no_audit(world: World) -> None:
    created = await add(world, "ada@example.com", external_id=EXT)
    before = await audit_count(world)

    nothing = await world.service.update_member(world.scim, created.user.id)
    same = await world.service.update_member(
        world.scim, created.user.id, role=OrgRole.VIEWER, external_id=EXT
    )

    assert nothing == created
    assert same == created
    assert await audit_count(world) == before


async def test_update_of_unknown_or_foreign_member_is_not_found(world: World) -> None:
    created = await add(world, "ada@example.com", external_id=EXT)
    foreign = Principal(org_id=world.other_org_id, key_id="stk_x", scopes=frozenset(Scope))

    with pytest.raises(NotFound):
        await world.service.update_member(world.scim, "usr_unknown", external_id=EXT_2)
    with pytest.raises(NotFound):
        await world.service.update_member(foreign, created.user.id, role=OrgRole.DEVELOPER)

    await assert_stored(world, created.user.id, OrgRole.VIEWER, EXT)


@pytest.mark.parametrize("bad", ["", "  ", "x" * 256])
async def test_update_rejects_a_blank_or_oversized_external_id(world: World, bad: str) -> None:
    created = await add(world, "ada@example.com", external_id=EXT)

    with pytest.raises(ValidationFailed):
        await world.service.update_member(
            world.scim, created.user.id, role=OrgRole.DEVELOPER, external_id=bad
        )

    await assert_stored(world, created.user.id, OrgRole.VIEWER, EXT)


# --- update_member: atomicity ----------------------------------------------------------------


async def test_a_refused_role_leaves_the_external_id_unchanged(world: World) -> None:
    created = await add(world, "ada@example.com", external_id=EXT)
    before = await audit_count(world)

    with pytest.raises(ScopeEscalation):
        await world.service.update_member(
            world.scim, created.user.id, role=OrgRole.ADMIN, external_id=EXT_2
        )

    await assert_stored(world, created.user.id, OrgRole.VIEWER, EXT)
    assert await audit_count(world) == before


async def test_a_conflicting_external_id_rolls_back_the_role_change(world: World) -> None:
    await add(world, "ada@example.com", external_id=EXT)
    bob = await add(world, "bob@example.com")
    before = await audit_count(world)

    with pytest.raises(Conflict):
        await world.service.update_member(
            world.scim, bob.user.id, role=OrgRole.DEVELOPER, external_id=EXT
        )

    await assert_stored(world, bob.user.id, OrgRole.VIEWER, None)
    assert await audit_count(world) == before


# --- update_member: role ceiling and last-admin guard ----------------------------------------


async def test_the_role_ceiling_blocks_a_grant_above_the_callers_scopes(world: World) -> None:
    created = await add(world, "ada@example.com")

    with pytest.raises(ScopeEscalation) as raised:
        await world.service.update_member(world.scim, created.user.id, role=OrgRole.ADMIN)

    assert raised.value.details["role"] == "admin"
    await assert_stored(world, created.user.id, OrgRole.VIEWER, None)


async def test_the_role_ceiling_is_checked_before_the_member_is_read(world: World) -> None:
    with pytest.raises(ScopeEscalation):
        await world.service.update_member(world.scim, "usr_unknown", role=OrgRole.ADMIN)


async def test_the_role_ceiling_allows_a_role_within_it(world: World) -> None:
    created = await add(world, "ada@example.com")

    updated = await world.service.update_member(world.scim, created.user.id, role=OrgRole.DEVELOPER)

    assert updated.role is OrgRole.DEVELOPER


async def test_the_last_admin_cannot_be_demoted_and_keeps_its_external_id(world: World) -> None:
    await world.service.update_member(world.admin, world.root_id, external_id=EXT)
    before = await audit_count(world)

    with pytest.raises(InvalidState):
        await world.service.update_member(
            world.admin, world.root_id, role=OrgRole.DEVELOPER, external_id=EXT_2
        )

    await assert_stored(world, world.root_id, OrgRole.ADMIN, EXT)
    assert await audit_count(world) == before


async def test_an_admin_can_be_demoted_while_another_admin_remains(world: World) -> None:
    second = await add(world, "second@example.com", OrgRole.ADMIN)

    updated = await world.service.update_member(
        world.admin, second.user.id, role=OrgRole.VIEWER, external_id=EXT
    )

    assert (updated.role, updated.external_id) == (OrgRole.VIEWER, EXT)
    await assert_stored(world, second.user.id, OrgRole.VIEWER, EXT)


# --- update_member: deactivate ---------------------------------------------------------------


async def test_deactivate_removes_the_membership_and_returns_the_member_as_it_was(
    world: World,
) -> None:
    created = await add(world, "ada@example.com", OrgRole.DEVELOPER, EXT)

    removed = await world.service.update_member(world.scim, created.user.id, deactivate=True)

    assert removed == created
    assert await stored(world, created.user.id) is None
    async with UnitOfWork(world.factory) as uow:
        assert await uow.users.get(created.user.id) is not None
    (event,) = await audit_rows(world, REMOVED)
    assert event.details == {"role": "developer", "external_id": EXT}
    assert event.actor_id == world.scim.key_id
    assert event.target_id == created.user.id


async def test_deactivate_ignores_the_other_arguments(world: World) -> None:
    created = await add(world, "ada@example.com", external_id=EXT)

    await world.service.update_member(
        world.admin, created.user.id, role=OrgRole.ADMIN, external_id=EXT_2, deactivate=True
    )

    assert await stored(world, created.user.id) is None
    assert await audit_rows(world, ROLE_CHANGED) == []
    assert await audit_rows(world, EXT_CHANGED) == []
    assert len(await audit_rows(world, REMOVED)) == 1


async def test_deactivate_keeps_the_last_admin_guard(world: World) -> None:
    before = await audit_count(world)

    with pytest.raises(InvalidState):
        await world.service.update_member(world.admin, world.root_id, deactivate=True)

    await assert_stored(world, world.root_id, OrgRole.ADMIN, None)
    assert await audit_count(world) == before


async def test_deactivate_twice_is_not_found(world: World) -> None:
    created = await add(world, "ada@example.com")
    await world.service.update_member(world.scim, created.user.id, deactivate=True)

    with pytest.raises(NotFound):
        await world.service.update_member(world.scim, created.user.id, deactivate=True)


async def test_reactivating_by_create_reuses_the_user_and_frees_the_external_id(
    world: World,
) -> None:
    created = await add(world, "ada@example.com", external_id=EXT)
    await world.service.update_member(world.scim, created.user.id, deactivate=True)

    again = await add(world, "ada@example.com", OrgRole.DEVELOPER, EXT)

    assert again.user.id == created.user.id
    await assert_stored(world, created.user.id, OrgRole.DEVELOPER, EXT)


# --- existing behaviour untouched ------------------------------------------------------------


async def test_existing_calls_keep_their_signatures_and_audit_details(world: World) -> None:
    created = await world.service.create_member(
        world.admin, "ada@example.com", "Ada", OrgRole.VIEWER
    )

    changed = await world.service.change_member_role(
        world.admin, created.user.id, OrgRole.DEVELOPER
    )
    removed = await world.service.remove_member(world.admin, created.user.id)

    assert changed.role is OrgRole.DEVELOPER
    assert removed is None
    (role_event,) = await audit_rows(world, ROLE_CHANGED)
    assert role_event.details == {"from_role": "viewer", "role": "developer"}
    (removed_event,) = await audit_rows(world, REMOVED)
    assert removed_event.details == {"role": "developer"}


async def test_the_existing_last_admin_guard_still_holds_for_remove_member(world: World) -> None:
    with pytest.raises(InvalidState):
        await world.service.remove_member(world.admin, world.root_id)
    with pytest.raises(InvalidState):
        await world.service.change_member_role(world.admin, world.root_id, OrgRole.VIEWER)


async def test_the_unset_default_differs_from_clearing(world: World) -> None:
    created = await add(world, "ada@example.com", external_id=EXT)

    kept = await world.service.update_member(world.scim, created.user.id, external_id=UNSET)
    cleared = await world.service.update_member(world.scim, created.user.id, external_id=None)

    assert kept.external_id == EXT
    assert cleared.external_id is None
