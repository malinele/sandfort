"""The disk reserve: fill/release archives, start/stop ordering, and the quota headroom."""

import asyncio
import io
import logging
import tarfile
from types import SimpleNamespace
from typing import Any

import pytest

from sandfort.config import Settings
from sandfort.domain.resources import ResourceSpec
from sandfort.drivers.base import SandboxSpec
from sandfort.drivers.docker import disk_reserve as reserve_module
from sandfort.drivers.docker.containers import build_create_kwargs, start_container, stop_container
from sandfort.drivers.docker.disk_reserve import (
    QUOTA_HEADROOM_BYTES,
    RESERVE_FILE_BYTES,
    RESERVE_PATH,
    fill_reserve,
    release_reserve,
)
from sandfort.drivers.docker.hardening import BYTES_PER_GIB, HardeningOptions, build_host_config
from sandfort.drivers.docker.labels import LABEL_DISK_GIB

MIB = 1024 * 1024
ENFORCED = {"StorageOpt": {"size": str(BYTES_PER_GIB + QUOTA_HEADROOM_BYTES)}}
PLAIN_RUNC = {"Runtime": "runc", "NetworkMode": "sf-net"}


class FakeDocker:
    """Records inspect/put_archive/start/stop in call order; failures are injectable."""

    def __init__(self, host_config: dict[str, Any] | None = None) -> None:
        self.host_config: dict[str, Any] = {**PLAIN_RUNC, **ENFORCED}
        if host_config is not None:
            self.host_config = host_config
        self.order: list[str] = []
        self.puts: list[tuple[str, str, bytes]] = []
        self.inspect_error: Exception | None = None
        self.put_error: Exception | None = None
        self.put_result = True
        self.exec_exit: int | None = 0
        self.exec_create_error: Exception | None = None
        self.execs: list[dict[str, Any]] = []
        self.api = SimpleNamespace(
            inspect_container=self._inspect,
            put_archive=self._put,
            exec_create=self._exec_create,
            exec_start=self._exec_start,
            exec_inspect=self._exec_inspect,
            start=lambda ref: self.order.append("start"),
            stop=lambda ref, timeout: self.order.append("stop"),
        )

    def _exec_create(self, ref: str, **kwargs: Any) -> dict[str, str]:
        self.order.append("exec_create")
        if self.exec_create_error is not None:
            raise self.exec_create_error
        self.execs.append({"ref": ref, **kwargs})
        return {"Id": "exec-1"}

    def _exec_start(self, exec_id: str) -> bytes:
        self.order.append("exec_start")
        return b""

    def _exec_inspect(self, exec_id: str) -> dict[str, Any]:
        self.order.append("exec_inspect")
        return {"Running": False, "ExitCode": self.exec_exit}

    def _inspect(self, ref: str) -> dict[str, Any]:
        self.order.append("inspect")
        if self.inspect_error is not None:
            raise self.inspect_error
        return {"Id": ref, "HostConfig": self.host_config}

    def _put(self, ref: str, path: str, data: bytes) -> bool:
        self.order.append("put_archive")
        if self.put_error is not None:
            raise self.put_error
        self.puts.append((ref, path, data))
        return self.put_result


def only_member(data: bytes) -> tuple[tarfile.TarInfo, bytes]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
        [member] = tar.getmembers()
        extracted = tar.extractfile(member)
        assert extracted is not None
        return member, extracted.read()


def make_spec(disk_gib: int = 1) -> SandboxSpec:
    return SandboxSpec(
        sandbox_id="sbx_1",
        org_id="org_1",
        name="sf-sbx_1",
        image="alpine:3.20",
        resources=ResourceSpec(cpu_millicores=1000, memory_mib=512, disk_gib=disk_gib),
    )


def test_constants_match_the_contract() -> None:
    assert RESERVE_PATH == "/.sandfort-reserve"
    assert RESERVE_FILE_BYTES == 16 * MIB
    assert QUOTA_HEADROOM_BYTES == 32 * MIB
    assert RESERVE_FILE_BYTES < QUOTA_HEADROOM_BYTES


async def test_fill_puts_a_real_zero_filled_file_at_the_root() -> None:
    docker = FakeDocker()

    await fill_reserve(docker, "abc")

    [(ref, path, data)] = docker.puts
    member, content = only_member(data)
    assert (ref, path) == ("abc", "/")
    assert member.name == ".sandfort-reserve"
    assert member.isreg()
    assert member.size == RESERVE_FILE_BYTES
    assert member.mode == 0o600
    assert content == bytes(RESERVE_FILE_BYTES)


async def test_release_truncates_in_place_as_root_without_put_archive() -> None:
    docker = FakeDocker()

    await release_reserve(docker, "abc")

    assert docker.execs == [
        {
            "ref": "abc",
            "cmd": ["sh", "-c", ": > /.sandfort-reserve"],
            "user": "0",
        }
    ]
    assert docker.puts == []
    assert "put_archive" not in docker.order
    assert docker.order == ["inspect", "exec_create", "exec_start", "exec_inspect"]


@pytest.mark.parametrize("exit_code", [1, 2, 126, 127, None])
async def test_release_falls_back_to_put_archive_when_the_exec_fails(
    exit_code: int | None,
) -> None:
    docker = FakeDocker()
    docker.exec_exit = exit_code

    await release_reserve(docker, "abc")

    assert len(docker.execs) == 1
    [(_, _, data)] = docker.puts
    assert only_member(data)[0].size == 0


async def test_release_falls_back_to_put_archive_when_exec_create_raises() -> None:
    docker = FakeDocker()
    docker.exec_create_error = RuntimeError("no such container")

    await release_reserve(docker, "abc")

    assert docker.execs == []
    assert len(docker.puts) == 1


async def test_release_falls_back_when_the_exec_times_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = FakeDocker()
    monkeypatch.setattr(reserve_module, "TRUNCATE_TIMEOUT_S", 0.0)

    async def hang(func: Any, *args: Any, **kwargs: Any) -> Any:
        await asyncio.sleep(1)

    monkeypatch.setattr(reserve_module, "run_blocking", _hang_for_exec(hang))

    await release_reserve(docker, "abc")

    assert len(docker.puts) == 1


def _hang_for_exec(hang: Any) -> Any:
    real = reserve_module.run_blocking

    async def dispatch(func: Any, *args: Any, **kwargs: Any) -> Any:
        if func.__name__ == "_truncate_blocking":
            return await hang(func, *args, **kwargs)
        return await real(func, *args, **kwargs)

    return dispatch


async def test_release_puts_an_empty_file_of_the_same_name() -> None:
    docker = FakeDocker()
    docker.exec_exit = 1

    await release_reserve(docker, "abc")

    [(ref, path, data)] = docker.puts
    member, content = only_member(data)
    assert (ref, path) == ("abc", "/")
    assert member.name == ".sandfort-reserve"
    assert member.isreg()
    assert member.size == 0
    assert member.mode == 0o600
    assert content == b""


@pytest.mark.parametrize("action", [fill_reserve, release_reserve])
@pytest.mark.parametrize(
    "host_config",
    [{}, {"StorageOpt": None}, {"StorageOpt": {}}, {"StorageOpt": {"size": ""}}],
)
async def test_nothing_is_put_when_the_quota_is_not_enforced(
    action: Any, host_config: dict[str, Any]
) -> None:
    docker = FakeDocker(host_config)

    await action(docker, "abc")

    assert docker.puts == []
    assert docker.order == ["inspect"]


@pytest.mark.parametrize("action", [fill_reserve, release_reserve])
async def test_an_inspect_error_is_logged_and_not_raised(
    action: Any, caplog: pytest.LogCaptureFixture
) -> None:
    docker = FakeDocker()
    docker.inspect_error = RuntimeError("daemon went away")

    with caplog.at_level(logging.WARNING, logger=reserve_module.logger.name):
        await action(docker, "abc")

    assert docker.puts == []
    assert any("disk reserve" in record.getMessage() for record in caplog.records)


@pytest.mark.parametrize("action", [fill_reserve, release_reserve])
@pytest.mark.parametrize(
    "failure",
    [OSError("no space left on device"), RuntimeError("daemon went away")],
)
async def test_a_put_error_is_logged_and_not_raised(
    action: Any, failure: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    docker = FakeDocker()
    docker.exec_exit = 1
    docker.put_error = failure

    with caplog.at_level(logging.WARNING, logger=reserve_module.logger.name):
        await action(docker, "abc")

    [record] = caplog.records
    assert "disk reserve" in record.getMessage()
    assert record.exc_info is not None
    assert str(failure) in str(record.exc_info[1])


@pytest.mark.parametrize("action", [fill_reserve, release_reserve])
async def test_a_refused_put_only_logs_a_warning(
    action: Any, caplog: pytest.LogCaptureFixture
) -> None:
    docker = FakeDocker()
    docker.exec_exit = 1
    docker.put_result = False

    with caplog.at_level(logging.WARNING, logger=reserve_module.logger.name):
        await action(docker, "abc")

    assert any("refused" in record.getMessage() for record in caplog.records)


async def test_start_fills_the_reserve_after_docker_started_the_container() -> None:
    docker = FakeDocker()

    await start_container(docker, "abc")

    assert docker.order.index("start") < docker.order.index("put_archive")
    [(_, _, data)] = docker.puts
    assert only_member(data)[0].size == RESERVE_FILE_BYTES


async def test_start_does_not_fill_a_container_without_a_quota() -> None:
    docker = FakeDocker(dict(PLAIN_RUNC))

    await start_container(docker, "abc")

    assert docker.puts == []
    assert "start" in docker.order


async def test_stop_truncates_the_reserve_before_docker_stops_the_container() -> None:
    docker = FakeDocker()

    await stop_container(docker, "abc", 2.0)

    assert docker.order.index("exec_inspect") < docker.order.index("stop")
    assert docker.order[-1] == "stop"
    assert docker.puts == []


async def test_stop_falls_back_to_put_archive_before_stopping() -> None:
    docker = FakeDocker()
    docker.exec_exit = 127

    await stop_container(docker, "abc", 2.0)

    assert docker.order.index("put_archive") < docker.order.index("stop")
    assert docker.order[-1] == "stop"
    [(_, _, data)] = docker.puts
    assert only_member(data)[0].size == 0


async def test_stop_still_stops_when_the_release_fails() -> None:
    docker = FakeDocker()
    docker.exec_exit = 1
    docker.put_error = OSError("no space left on device")

    await stop_container(docker, "abc", 2.0)

    assert docker.order[-1] == "stop"


@pytest.mark.parametrize("disk_gib", [1, 2, 10])
def test_the_enforced_quota_is_the_disk_plus_the_headroom(disk_gib: int) -> None:
    options = HardeningOptions(enforce_disk_quota=True)

    config = build_host_config(make_spec(disk_gib), Settings(), options)

    assert config["storage_opt"] == {"size": str(disk_gib * BYTES_PER_GIB + 32 * MIB)}


def test_no_quota_is_set_when_it_is_not_enforced() -> None:
    config = build_host_config(make_spec(), Settings(), HardeningOptions())

    assert "storage_opt" not in config


def test_the_disk_label_keeps_the_users_disk_size_without_the_headroom() -> None:
    options = HardeningOptions(enforce_disk_quota=True)

    kwargs = build_create_kwargs(make_spec(3), Settings(), options)

    assert kwargs["labels"][LABEL_DISK_GIB] == "3"
