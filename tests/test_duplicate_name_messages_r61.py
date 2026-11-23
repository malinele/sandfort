"""A taken volume or snapshot name and a missing org are told apart in the 409 message."""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.db.repositories import snapshots as snapshot_repo
from sandfort.db.repositories import volumes as volume_repo
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.snapshot import Snapshot
from sandfort.domain.volume import Volume
from sandfort.errors import ALREADY_EXISTS, CONFLICT_REASON, NAME_TAKEN, Conflict
from sandfort.ids import new_snapshot_id, new_volume_id
from test_api_sandboxes import NOW, add_org, migrated_app


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path) as application:
        yield application


def make_volume(org_id: str, name: str = "data") -> Volume:
    return Volume(
        id=new_volume_id(),
        org_id=org_id,
        name=name,
        provider_volume_name=f"sf-vol-{new_volume_id()}",
        created_at=NOW,
    )


def make_snapshot(org_id: str, name: str = "base") -> Snapshot:
    return Snapshot(
        id=new_snapshot_id(),
        org_id=org_id,
        name=name,
        image_ref="alpine:3.20",
        digest="sha256:abc",
        layer_count=1,
        created_at=NOW,
    )


async def add_volume(app: FastAPI, volume: Volume) -> Conflict | None:
    try:
        async with UnitOfWork(app.state.session_factory) as uow:
            await uow.volumes.add(volume)
            await uow.commit()
    except Conflict as exc:
        return exc
    return None


async def add_snapshot(app: FastAPI, snapshot: Snapshot) -> Conflict | None:
    try:
        async with UnitOfWork(app.state.session_factory) as uow:
            await uow.snapshots.add(snapshot)
            await uow.commit()
    except Conflict as exc:
        return exc
    return None


# --- volumes ------------------------------------------------------------------------


async def test_duplicate_volume_name_says_the_name_is_taken(app: FastAPI) -> None:
    org_id = await add_org(app, "acme")
    assert await add_volume(app, make_volume(org_id, "data")) is None

    error = await add_volume(app, make_volume(org_id, "data"))

    assert error is not None
    assert str(error) == "volume 'data' already exists in this org"
    assert "org does not exist" not in str(error)
    assert error.reason == NAME_TAKEN
    assert error.status == 409
    assert error.code == "CONFLICT"


async def test_volume_with_a_missing_org_does_not_claim_the_name_is_taken(
    app: FastAPI,
) -> None:
    error = await add_volume(app, make_volume("org_missing", "data"))

    assert error is not None
    assert str(error) == "volume cannot be created: its org does not exist"
    assert "already exists" not in str(error)
    assert error.reason == volume_repo.ORG_NOT_FOUND == "org_not_found"
    assert error.status == 409


async def test_same_volume_name_in_another_org_is_accepted(app: FastAPI) -> None:
    first = await add_org(app, "acme")
    second = await add_org(app, "globex")

    assert await add_volume(app, make_volume(first, "data")) is None
    assert await add_volume(app, make_volume(second, "data")) is None


async def test_duplicate_volume_id_keeps_a_generic_message(app: FastAPI) -> None:
    org_id = await add_org(app, "acme")
    original = make_volume(org_id, "one")
    assert await add_volume(app, original) is None

    clash = make_volume(org_id, "two").model_copy(update={"id": original.id})
    error = await add_volume(app, clash)

    assert error is not None
    assert str(error) == f"volume id {original.id} already exists"
    assert error.reason == ALREADY_EXISTS


# --- snapshots ----------------------------------------------------------------------


async def test_duplicate_snapshot_name_says_the_name_is_taken(app: FastAPI) -> None:
    org_id = await add_org(app, "acme")
    assert await add_snapshot(app, make_snapshot(org_id, "base")) is None

    error = await add_snapshot(app, make_snapshot(org_id, "base"))

    assert error is not None
    assert str(error) == "snapshot 'base' already exists in this org"
    assert "org does not exist" not in str(error)
    assert error.reason == NAME_TAKEN
    assert error.status == 409
    assert error.code == "CONFLICT"


async def test_snapshot_with_a_missing_org_does_not_claim_the_name_is_taken(
    app: FastAPI,
) -> None:
    error = await add_snapshot(app, make_snapshot("org_missing", "base"))

    assert error is not None
    assert str(error) == "snapshot cannot be created: its org does not exist"
    assert "already exists" not in str(error)
    assert error.reason == snapshot_repo.ORG_NOT_FOUND == "org_not_found"
    assert error.status == 409


async def test_same_snapshot_name_in_another_org_is_accepted(app: FastAPI) -> None:
    first = await add_org(app, "acme")
    second = await add_org(app, "globex")

    assert await add_snapshot(app, make_snapshot(first, "base")) is None
    assert await add_snapshot(app, make_snapshot(second, "base")) is None


async def test_duplicate_snapshot_id_keeps_a_generic_message(app: FastAPI) -> None:
    org_id = await add_org(app, "acme")
    original = make_snapshot(org_id, "one")
    assert await add_snapshot(app, original) is None

    clash = make_snapshot(org_id, "two").model_copy(update={"id": original.id})
    error = await add_snapshot(app, clash)

    assert error is not None
    assert str(error) == f"snapshot id {original.id} already exists"
    assert error.reason == ALREADY_EXISTS


# --- fake driver errors (Postgres and SQLite texts) ----------------------------------


class FailingSession:
    """Stands in for ``AsyncSession``: ``flush`` raises the given driver text."""

    def __init__(self, driver_text: str) -> None:
        self._driver_text = driver_text

    def add(self, row: object) -> None:
        return None

    async def flush(self) -> None:
        raise IntegrityError("INSERT ...", {}, Exception(self._driver_text))


def _session(driver_text: str) -> AsyncSession:
    return cast(AsyncSession, FailingSession(driver_text))


def _pg_unique(name: str) -> str:
    return f'duplicate key value violates unique constraint "{name}"'


def _pg_fk(name: str) -> str:
    return f'insert or update violates foreign key constraint "{name}"'


async def _volume_error(driver_text: str) -> Conflict:
    repo = volume_repo.SqlVolumeRepository(_session(driver_text))
    with pytest.raises(Conflict) as caught:
        await repo.add(make_volume("org_x", "data"))
    return caught.value


async def _snapshot_error(driver_text: str) -> Conflict:
    repo = snapshot_repo.SqlSnapshotRepository(_session(driver_text))
    with pytest.raises(Conflict) as caught:
        await repo.add(make_snapshot("org_x", "base"))
    return caught.value


async def test_postgres_volume_name_text_maps_to_name_taken() -> None:
    error = await _volume_error(_pg_unique("uq_volumes_org_id_name"))

    assert error.reason == NAME_TAKEN
    assert str(error) == "volume 'data' already exists in this org"


async def test_postgres_volume_foreign_key_text_maps_to_org_not_found() -> None:
    error = await _volume_error(_pg_fk("fk_volumes_org_id_organizations"))

    assert error.reason == "org_not_found"
    assert str(error) == "volume cannot be created: its org does not exist"


async def test_postgres_volume_primary_key_text_maps_to_id_exists() -> None:
    error = await _volume_error(_pg_unique("pk_volumes"))

    assert error.reason == ALREADY_EXISTS
    assert "volume id " in str(error)


async def test_unmatched_volume_constraint_gets_the_generic_message() -> None:
    error = await _volume_error('new row violates check constraint "ck_volumes_state"')

    assert str(error) == "could not create the volume (constraint conflict)"
    assert "already exists" not in str(error)
    assert error.reason == CONFLICT_REASON
    assert error.status == 409


async def test_sqlite_unmatched_volume_error_gets_the_generic_message() -> None:
    error = await _volume_error("NOT NULL constraint failed: volumes.provider_volume_name")

    assert str(error) == "could not create the volume (constraint conflict)"


async def test_postgres_snapshot_name_text_maps_to_name_taken() -> None:
    error = await _snapshot_error(_pg_unique("uq_snapshots_org_id_name"))

    assert error.reason == NAME_TAKEN
    assert str(error) == "snapshot 'base' already exists in this org"


async def test_postgres_snapshot_foreign_key_text_maps_to_org_not_found() -> None:
    error = await _snapshot_error(_pg_fk("fk_snapshots_org_id_organizations"))

    assert error.reason == "org_not_found"
    assert str(error) == "snapshot cannot be created: its org does not exist"


async def test_postgres_snapshot_primary_key_text_maps_to_id_exists() -> None:
    error = await _snapshot_error(_pg_unique("pk_snapshots"))

    assert error.reason == ALREADY_EXISTS
    assert "snapshot id " in str(error)


async def test_unmatched_snapshot_constraint_gets_the_generic_message() -> None:
    error = await _snapshot_error('new row violates check constraint "ck_snapshots_state"')

    assert str(error) == "could not create the snapshot (constraint conflict)"
    assert "already exists" not in str(error)
    assert error.reason == CONFLICT_REASON
    assert error.status == 409
