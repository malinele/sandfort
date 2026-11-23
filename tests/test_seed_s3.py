"""Seed S3 checks: phase-3 interfaces import, the fake driver satisfies them, registry works."""

import importlib
import sqlite3
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from sandfort.clock import SystemClock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.image_spec import ImageFile, ImageSpec
from sandfort.drivers.base import (
    BuildHandle,
    ImageBuildDriver,
    ImageRegistryDriver,
    NamedVolumeDriver,
)
from sandfort.drivers.docker import volumes as docker_volumes
from sandfort.drivers.fake import FakeDriver
from sandfort.errors import Conflict, NotFound
from sandfort.workers.handlers import HandlerRegistry, JobContext

ROOT = Path(__file__).resolve().parents[1]
NEW_MODULES = [
    "sandfort.domain.snapshot",
    "sandfort.domain.volume",
    "sandfort.domain.image_spec",
    "sandfort.drivers.docker.images",
    "sandfort.drivers.docker.build",
    "sandfort.drivers.docker.volumes",
    "sandfort.db.models.jobs",
    "sandfort.db.models.snapshots",
    "sandfort.db.models.volumes",
    "sandfort.db.repositories.jobs",
    "sandfort.db.repositories.snapshots",
    "sandfort.db.repositories.volumes",
    "sandfort.workers.handlers",
    "sandfort.migrations.versions.r0003_phase3",
]


@pytest.mark.parametrize("module", NEW_MODULES)
def test_new_module_imports(module: str) -> None:
    assert importlib.import_module(module) is not None


def test_fake_driver_satisfies_phase3_protocols() -> None:
    driver = FakeDriver()

    assert isinstance(driver, ImageRegistryDriver)
    assert isinstance(driver, ImageBuildDriver)
    assert isinstance(driver, NamedVolumeDriver)


async def test_fake_build_log_round_trip() -> None:
    driver = FakeDriver()
    context = {"Dockerfile": b"FROM alpine", "app.txt": b"hi"}

    handle = await driver.start_build(
        context, "sf/test:1", cpu_millicores=500, memory_mib=256, timeout_s=30.0
    )
    lines = [line async for line in handle.logs()]
    digest = await handle.result()

    assert isinstance(handle, BuildHandle)
    assert lines == [
        "COPY Dockerfile (11 bytes)",
        "COPY app.txt (2 bytes)",
        "Successfully tagged sf/test:1",
    ]
    assert digest.startswith("sha256:")
    assert await driver.image_exists("sf/test:1")
    assert await driver.pull_image_digest("sf/test:1") == digest


async def test_fake_image_exists_and_remove() -> None:
    driver = FakeDriver()
    assert not await driver.image_exists("base:1")

    await driver.pull_image_digest("base:1")
    assert await driver.image_exists("base:1")

    await driver.remove_image("base:1")
    assert not await driver.image_exists("base:1")


async def test_fake_volume_inspect() -> None:
    driver = FakeDriver()
    volume = await driver.create_volume("data", labels={})

    inspected: Mapping[str, Any] = await driver.inspect_volume(volume.ref)

    assert inspected["name"] == "data"
    assert inspected["size_bytes"] == 0


async def test_docker_volume_stub_names_owner() -> None:
    with pytest.raises(NotImplementedError, match="volumes work package"):
        await docker_volumes.inspect_volume(None, "x")


def _spec(**overrides: Any) -> ImageSpec:
    base: dict[str, Any] = {
        "base_image": "python:3.12-slim",
        "pip_packages": ["requests", "attrs"],
        "apt_packages": ["git", "curl"],
        "env": {"A": "1", "B": "2"},
        "workdir": "/work",
        "files": [
            ImageFile(destination="/a.txt", content="a"),
            ImageFile(destination="/b.txt", content="b"),
        ],
    }
    return ImageSpec(**{**base, **overrides})


def test_spec_hash_is_order_independent() -> None:
    reordered = _spec(
        pip_packages=["attrs", "requests"],
        apt_packages=["curl", "git"],
        env={"B": "2", "A": "1"},
        files=[
            ImageFile(destination="/b.txt", content="b"),
            ImageFile(destination="/a.txt", content="a"),
        ],
    )

    assert _spec().spec_hash == reordered.spec_hash
    assert len(_spec().spec_hash) == 64


@pytest.mark.parametrize(
    "change",
    [
        {"base_image": "python:3.13-slim"},
        {"pip_packages": ["requests"]},
        {"apt_packages": []},
        {"env": {"A": "1"}},
        {"workdir": None},
        {"files": [ImageFile(destination="/a.txt", content="changed")]},
    ],
)
def test_spec_hash_changes_with_content(change: dict[str, Any]) -> None:
    assert _spec(**change).spec_hash != _spec().spec_hash


def _registry_context() -> JobContext:
    def no_uow() -> UnitOfWorkPort:
        raise AssertionError("the uow is not used by this test")

    return JobContext(uow_factory=no_uow, driver=FakeDriver(), clock=SystemClock())


async def test_handler_registry_register_and_lookup() -> None:
    registry = HandlerRegistry()
    seen: list[Mapping[str, Any]] = []

    @registry.register("snapshot.create")
    async def handler(payload: Mapping[str, Any], context: JobContext) -> None:
        seen.append(payload)

    found = registry.lookup("snapshot.create")
    await found({"name": "s"}, _registry_context())

    assert found is handler
    assert seen == [{"name": "s"}]
    assert registry.kinds() == frozenset({"snapshot.create"})


def test_handler_registry_rejects_duplicate_and_unknown_kind() -> None:
    registry = HandlerRegistry()

    @registry.register("volume.delete")
    async def first(payload: Mapping[str, Any], context: JobContext) -> None:
        return None

    with pytest.raises(Conflict):

        @registry.register("volume.delete")
        async def second(payload: Mapping[str, Any], context: JobContext) -> None:
            return None

    with pytest.raises(NotFound):
        registry.lookup("missing")


def test_migration_chain_creates_phase3_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "s3.db"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")

    command.upgrade(config, "head")

    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        tables = {row[0] for row in rows}
        version = connection.execute("SELECT version_num FROM alembic_version").fetchall()
    assert {"jobs", "snapshots", "volumes"} <= tables
    assert version == [(ScriptDirectory.from_config(config).get_current_head(),)]
