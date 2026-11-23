"""Docker compute driver against a real local daemon (skipped when none is reachable)."""

import contextlib
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from sandfort.config import Settings
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import NetworkPolicy
from sandfort.drivers.base import InstanceState, SandboxSpec
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.docker.hardening import HardeningOptions
from sandfort.drivers.errors import DriverNotFound

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

IMAGE = "alpine:3.20"
KEEPALIVE = ["tail", "-f", "/dev/null"]
MEMORY_512_MIB = 536_870_912


@pytest.fixture(scope="module")
def client() -> Any:
    try:
        docker_client = make_client()
        docker_client.ping()
    except Exception as exc:
        pytest.skip(f"no reachable Docker daemon: {exc}")
    try:
        docker_client.images.get(IMAGE)
    except docker.errors.ImageNotFound:
        try:
            docker_client.images.pull(IMAGE)
        except Exception as exc:
            pytest.skip(f"cannot pull {IMAGE}: {exc}")
    return docker_client


@pytest.fixture
def driver(client: Any) -> DockerDriver:
    return DockerDriver(Settings(), client=client)


def make_spec(**overrides: Any) -> SandboxSpec:
    token = uuid.uuid4().hex[:10]
    fields: dict[str, Any] = {
        "sandbox_id": f"sbx_t{token}",
        "org_id": f"org_t{token}",
        "name": f"sf-sbx_t{token}",
        "image": IMAGE,
        "resources": ResourceSpec(cpu_millicores=1000, memory_mib=512, disk_gib=1),
        "labels": {"suite": "test_docker_driver"},
    }
    fields.update(overrides)
    return SandboxSpec(**fields)


def force_remove(client: Any, ref: str) -> None:
    with contextlib.suppress(docker.errors.NotFound):
        client.api.remove_container(ref, v=True, force=True)


@pytest.fixture
def cleanup(client: Any) -> Iterator[list[str]]:
    """Refs/names registered by a test are force-removed even if the test fails."""
    refs: list[str] = []
    try:
        yield refs
    finally:
        for ref in refs:
            force_remove(client, ref)


async def test_inspect_shows_hardening_and_labels(
    client: Any, driver: DockerDriver, cleanup: list[str]
) -> None:
    spec = make_spec()
    cleanup.append(spec.name)
    try:
        info = await driver.create(spec)
        raw = client.api.inspect_container(info.ref)
        host = raw["HostConfig"]

        assert host["NanoCpus"] == 1_000_000_000
        assert host["Memory"] == MEMORY_512_MIB
        assert host["MemorySwap"] == MEMORY_512_MIB
        assert host["PidsLimit"] == 512
        assert host["CapDrop"] == ["ALL"]
        assert any("no-new-privileges" in option for option in host["SecurityOpt"])
        assert host["Init"] is True
        assert host["Privileged"] is False

        labels = raw["Config"]["Labels"]
        assert labels["sandfort.managed"] == "true"
        assert labels["sandfort.sandbox_id"] == spec.sandbox_id
        assert labels["sandfort.org_id"] == spec.org_id
        assert labels["suite"] == "test_docker_driver"

        assert info.name == spec.name
        assert info.state is InstanceState.CREATED
        assert info.resources == spec.resources
        assert (await driver.inspect(info.ref)).ref == info.ref
    finally:
        await driver.destroy(spec.name)


async def test_create_is_idempotent_on_name_conflict(
    driver: DockerDriver, cleanup: list[str]
) -> None:
    spec = make_spec()
    cleanup.append(spec.name)
    try:
        first = await driver.create(spec)
        second = await driver.create(spec)

        assert second.ref == first.ref
        listed = await driver.list_managed(org_id=spec.org_id)
        assert [info.ref for info in listed] == [first.ref]
    finally:
        await driver.destroy(spec.name)


async def test_destroy_removes_container_and_anonymous_volumes(
    client: Any, driver: DockerDriver, cleanup: list[str]
) -> None:
    name = f"sf-sbx_t{uuid.uuid4().hex[:10]}"
    cleanup.append(name)
    volume_names: list[str] = []
    try:
        created = client.api.create_container(
            IMAGE, entrypoint=KEEPALIVE, name=name, volumes=["/data"]
        )
        mounts = client.api.inspect_container(created["Id"])["Mounts"]
        volume_names = [mount["Name"] for mount in mounts if mount["Type"] == "volume"]
        assert len(volume_names) == 1

        await driver.destroy(created["Id"], remove_volumes=True)

        with pytest.raises(docker.errors.NotFound):
            client.api.inspect_container(created["Id"])
        with pytest.raises(docker.errors.NotFound):
            client.volumes.get(volume_names[0])
        await driver.destroy(created["Id"])  # idempotent once gone
    finally:
        for volume in volume_names:
            with contextlib.suppress(docker.errors.NotFound):
                client.volumes.get(volume).remove(force=True)


async def test_destroy_can_keep_anonymous_volumes(
    client: Any, driver: DockerDriver, cleanup: list[str]
) -> None:
    name = f"sf-sbx_t{uuid.uuid4().hex[:10]}"
    cleanup.append(name)
    volume_names: list[str] = []
    try:
        created = client.api.create_container(
            IMAGE, entrypoint=KEEPALIVE, name=name, volumes=["/data"]
        )
        mounts = client.api.inspect_container(created["Id"])["Mounts"]
        volume_names = [mount["Name"] for mount in mounts if mount["Type"] == "volume"]

        await driver.destroy(created["Id"], remove_volumes=False)

        assert client.volumes.get(volume_names[0]).name == volume_names[0]
    finally:
        for volume in volume_names:
            with contextlib.suppress(docker.errors.NotFound):
                client.volumes.get(volume).remove(force=True)


async def test_start_stop_and_list_managed(driver: DockerDriver, cleanup: list[str]) -> None:
    spec = make_spec()
    cleanup.append(spec.name)
    try:
        info = await driver.create(spec)
        await driver.start(info.ref)
        assert (await driver.inspect(info.ref)).state is InstanceState.RUNNING

        listed = await driver.list_managed(org_id=spec.org_id)
        assert [item.sandbox_id for item in listed] == [spec.sandbox_id]
        assert await driver.list_managed(org_id="org_does_not_exist") == []

        await driver.stop(info.ref, timeout_s=2)
        assert (await driver.inspect(info.ref)).state is InstanceState.EXITED
    finally:
        await driver.destroy(spec.name)

    with pytest.raises(DriverNotFound):
        await driver.inspect(spec.name)


async def test_network_is_none_when_all_egress_is_blocked(
    client: Any, driver: DockerDriver, cleanup: list[str]
) -> None:
    blocked = make_spec(network=NetworkPolicy(block_all=True))
    open_egress = make_spec()
    cleanup.extend([blocked.name, open_egress.name])
    try:
        blocked_info = await driver.create(blocked)
        open_info = await driver.create(open_egress)

        blocked_host = client.api.inspect_container(blocked_info.ref)["HostConfig"]
        open_host = client.api.inspect_container(open_info.ref)["HostConfig"]
        assert blocked_host["NetworkMode"] == "none"
        assert open_host["NetworkMode"] == "sf-net"
    finally:
        await driver.destroy(blocked.name)
        await driver.destroy(open_egress.name)


async def test_non_root_user_option_is_applied(client: Any, cleanup: list[str]) -> None:
    driver = DockerDriver(Settings(), client=client, options=HardeningOptions(user="1000:1000"))
    spec = make_spec()
    cleanup.append(spec.name)
    try:
        info = await driver.create(spec)
        assert client.api.inspect_container(info.ref)["Config"]["User"] == "1000:1000"
    finally:
        await driver.destroy(spec.name)
