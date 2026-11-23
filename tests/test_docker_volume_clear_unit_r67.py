# ruff: noqa: F401, F811
"""Round 67: the guards in front of the docker volume helper and clear-by-recreate (no daemon).

Uses the fake docker-py client of ``test_docker_volume_transfer_unit_r67``.
"""

import docker
import pytest
from tests.test_docker_volume_transfer_unit_r67 import (
    MANAGED,
    REF,
    FakeClient,
    client,
    drain,
    driver,
    error,
    source,
    tar_of,
)

from sandfort.drivers.docker.client import GENERIC_DRIVER_MESSAGE
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.errors import DriverConflict, DriverError, DriverNotFound

# -- guards ---------------------------------------------------------------------------------


async def test_a_missing_volume_is_not_found_and_nothing_is_created(
    driver: DockerDriver, client: FakeClient
) -> None:
    client.api.volume = None

    with pytest.raises(DriverNotFound):
        await anext(driver.export_volume(REF))
    with pytest.raises(DriverNotFound):
        await driver.restore_volume(REF, source(tar_of(("a", b"1"))))

    assert client.created == []


async def test_a_volume_without_the_managed_label_is_never_mounted(
    driver: DockerDriver, client: FakeClient
) -> None:
    client.api.volume = {"Name": REF, "Driver": "local", "Labels": {"owner": "someone else"}}

    with pytest.raises(DriverNotFound):
        await anext(driver.export_volume(REF))
    with pytest.raises(DriverNotFound):
        await driver.clear_volume(REF)

    assert client.created == []
    assert "remove_volume" not in client.api.events


# -- clear ----------------------------------------------------------------------------------


async def test_clear_removes_and_recreates_the_volume_with_its_name_driver_options_and_labels(
    driver: DockerDriver, client: FakeClient
) -> None:
    await driver.clear_volume(REF)

    assert client.api.events == ["inspect_volume", "remove_volume", "create_volume"]
    assert client.api.created_volumes == [
        {"name": REF, "driver": "local", "driver_opts": {"o": "size=1g"}, "labels": MANAGED}
    ]
    assert client.created == []  # no helper, no code


async def test_clear_that_cannot_remove_the_volume_changes_nothing(
    driver: DockerDriver, client: FakeClient
) -> None:
    client.api.remove_volume_error = error(docker.errors.APIError, 409, "volume is in use")

    with pytest.raises(DriverConflict):
        await driver.clear_volume(REF)

    assert "create_volume" not in client.api.events


async def test_clear_retries_the_creation_after_a_transient_failure(
    driver: DockerDriver, client: FakeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sandfort.drivers.docker.volumes.RECREATE_RETRY_S", 0)
    client.api.create_volume_failures = 2

    await driver.clear_volume(REF)

    assert len(client.api.created_volumes) == 1


async def test_clear_gives_up_loudly_when_the_volume_cannot_be_created_again(
    driver: DockerDriver, client: FakeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sandfort.drivers.docker.volumes.RECREATE_RETRY_S", 0)
    client.api.create_volume_failures = 99

    with pytest.raises(DriverError) as caught:
        await driver.clear_volume(REF)

    assert caught.value.message == GENERIC_DRIVER_MESSAGE
