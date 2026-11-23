"""Driver registry: resolves a driver name to a factory and its declared capabilities.

The built-in names (``fake``, ``docker``) always resolve to the in-tree drivers and are
never shadowed. Any other name is looked up among the ``sandfort.drivers`` entry points of
installed distributions; an entry point must load a ``DriverEntry``. A ``DriverEntry``
declares which frozen protocols its driver implements, so partial drivers (for example
compute and exec only) are first-class: the conformance suite skips what is not declared.
"""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from importlib import metadata
from typing import Any, Protocol, runtime_checkable

from sandfort.clock import Clock
from sandfort.config import Settings
from sandfort.drivers.base import (
    ArchiveDriver,
    ArchiveStreamDriver,
    ComputeDriver,
    ExecDriver,
    ImageBuildDriver,
    ImageDriver,
    ImageRegistryDriver,
    InventoryDriver,
    LogsDriver,
    NamedVolumeDriver,
    PtyDriver,
    PtySessionDriver,
    VolumeDriver,
)
from sandfort.drivers.errors import DriverError

ENTRY_POINT_GROUP = "sandfort.drivers"


class Capability(StrEnum):
    """One frozen protocol family of ``drivers.base`` a driver may implement."""

    COMPUTE = "compute"
    EXEC = "exec"
    ARCHIVE = "archive"
    PTY = "pty"
    LOGS = "logs"
    IMAGES = "images"
    BUILD = "build"
    VOLUMES = "volumes"
    INVENTORY = "inventory"


ALL_CAPABILITIES: frozenset[Capability] = frozenset(Capability)


# The phase-1 protocols are not ``runtime_checkable``; these subclasses are, and leave
# the frozen originals untouched.
@runtime_checkable
class RuntimeCompute(ComputeDriver, Protocol): ...


@runtime_checkable
class RuntimeExec(ExecDriver, Protocol): ...


@runtime_checkable
class RuntimeArchive(ArchiveDriver, Protocol): ...


@runtime_checkable
class RuntimePty(PtyDriver, Protocol): ...


@runtime_checkable
class RuntimeImages(ImageDriver, Protocol): ...


@runtime_checkable
class RuntimeVolumes(VolumeDriver, Protocol): ...


# What declaring a capability promises: every listed protocol is implemented.
CAPABILITY_PROTOCOLS: Mapping[Capability, tuple[type, ...]] = {
    Capability.COMPUTE: (RuntimeCompute,),
    Capability.EXEC: (RuntimeExec,),
    Capability.ARCHIVE: (RuntimeArchive, ArchiveStreamDriver),
    Capability.PTY: (RuntimePty, PtySessionDriver),
    Capability.LOGS: (LogsDriver,),
    Capability.IMAGES: (RuntimeImages, ImageRegistryDriver),
    Capability.BUILD: (ImageBuildDriver,),
    Capability.VOLUMES: (RuntimeVolumes, NamedVolumeDriver),
    Capability.INVENTORY: (InventoryDriver,),
}


def detect_capabilities(driver: object) -> frozenset[Capability]:
    """The capabilities whose protocols ``driver`` structurally implements."""
    return frozenset(
        capability
        for capability, protocols in CAPABILITY_PROTOCOLS.items()
        if all(isinstance(driver, protocol) for protocol in protocols)
    )

type DriverFactory = Callable[[Settings, Clock], object]


@dataclass(frozen=True, slots=True)
class DriverEntry:
    """A named driver: how to build it and which protocol families it implements."""

    name: str
    factory: DriverFactory
    capabilities: frozenset[Capability]

    def build(self, settings: Settings, clock: Clock) -> object:
        return self.factory(settings, clock)


class DriverRegistryError(DriverError):
    """A driver name cannot be resolved or a plug-in is malformed."""


class UnknownDriver(DriverRegistryError):
    """No built-in driver or installed entry point carries the requested name."""

    def __init__(self, name: str, known: Iterable[str]) -> None:
        self.known = tuple(sorted(known))
        listed = ", ".join(self.known) or "(none)"
        super().__init__(f"unknown driver {name!r}; known drivers: {listed}", ref=name)

    def __reduce__(self) -> tuple[Any, ...]:
        """Rebuild from the constructor arguments (the base class passes message and ref)."""
        return (type(self), (self.ref, self.known))


def _fake_factory(settings: Settings, clock: Clock) -> object:
    from sandfort.drivers.fake import FakeDriver

    return FakeDriver(clock)


def _docker_factory(settings: Settings, clock: Clock) -> object:
    from sandfort.drivers.docker.driver import DockerDriver

    return DockerDriver(settings)


BUILTIN_DRIVERS: Mapping[str, DriverEntry] = {
    "docker": DriverEntry("docker", _docker_factory, ALL_CAPABILITIES),
    "fake": DriverEntry("fake", _fake_factory, ALL_CAPABILITIES),
}


def _load(entry_point: metadata.EntryPoint) -> DriverEntry:
    try:
        loaded = entry_point.load()
    except Exception as exc:
        raise DriverRegistryError(
            f"driver entry point {entry_point.name!r} ({entry_point.value}) failed: {exc}",
            ref=entry_point.name,
        ) from exc
    if not isinstance(loaded, DriverEntry):
        raise DriverRegistryError(
            f"driver entry point {entry_point.name!r} must load a DriverEntry, "
            f"got {type(loaded).__name__}",
            ref=entry_point.name,
        )
    return replace(loaded, name=entry_point.name)


def _plugin_entry_points() -> dict[str, metadata.EntryPoint]:
    """Installed ``sandfort.drivers`` entry points by name, built-in names excluded."""
    found = metadata.entry_points(group=ENTRY_POINT_GROUP)
    return {point.name: point for point in found if point.name not in BUILTIN_DRIVERS}


def known_drivers() -> tuple[str, ...]:
    """Every resolvable name: the built-ins plus the installed entry points, sorted."""
    return tuple(sorted({*BUILTIN_DRIVERS, *_plugin_entry_points()}))


def resolve_driver(name: str) -> DriverEntry:
    """The entry for ``name``; built-ins resolve without consulting entry points at all."""
    builtin = BUILTIN_DRIVERS.get(name)
    if builtin is not None:
        return builtin
    plugins = _plugin_entry_points()
    point = plugins.get(name)
    if point is None:
        raise UnknownDriver(name, {*BUILTIN_DRIVERS, *plugins})
    return _load(point)
