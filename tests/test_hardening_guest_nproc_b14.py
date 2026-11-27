"""B14 98b: the runsc family gets an ``nproc`` ulimit and a raised host ``pids_limit``.

Pure mapping tests, no daemon. The live fork-loop checks are in
``tests/test_docker_process_cap_tiers_b14.py``.
"""

from typing import Any

import pytest

from sandfort.config import Settings
from sandfort.domain.resources import ResourceSpec
from sandfort.drivers.base import SandboxSpec
from sandfort.drivers.docker.hardening import (
    GVISOR_PIDS_LIMIT,
    NPROC_LIMIT,
    PIDS_LIMIT,
    HardeningOptions,
    build_host_config,
    options_from_settings,
)

TIER_MAP = (("container", "runc"), ("gvisor", "runsc"), ("microvm", "kata"))
NOFILE = {"Name": "nofile", "Soft": 4096, "Hard": 4096}
NPROC = {"Name": "nproc", "Soft": 512, "Hard": 512}


def make_spec(**overrides: Any) -> SandboxSpec:
    fields: dict[str, Any] = {
        "sandbox_id": "sbx_1",
        "org_id": "org_1",
        "name": "sf-sbx_1",
        "image": "alpine:3.20",
        "resources": ResourceSpec(cpu_millicores=1000, memory_mib=512, disk_gib=2),
    }
    fields.update(overrides)
    return SandboxSpec(**fields)


def config(spec: SandboxSpec, settings: Settings) -> dict[str, Any]:
    return build_host_config(spec, settings, options_from_settings(settings))


def test_gvisor_tier_gets_nproc_equal_to_pids_limit() -> None:
    settings = Settings(isolation_runtimes=TIER_MAP)

    result = config(make_spec(isolation="gvisor"), settings)

    assert result["ulimits"] == [NOFILE, NPROC]


def test_gvisor_tier_raises_the_host_pids_limit_for_the_sentry() -> None:
    settings = Settings(isolation_runtimes=TIER_MAP)

    result = config(make_spec(isolation="gvisor"), settings)

    assert result["pids_limit"] == GVISOR_PIDS_LIMIT == 1536


def test_runsc_alias_runtime_gets_nproc_and_the_raised_pids_limit() -> None:
    settings = Settings(isolation_runtimes=(("container", "runc"), ("gvisor", "runsc-debug")))

    result = config(make_spec(isolation="gvisor"), settings)

    assert NPROC in result["ulimits"]
    assert result["pids_limit"] == 1536


def test_default_tier_runsc_via_options_gets_both() -> None:
    result = build_host_config(
        make_spec(), Settings(), HardeningOptions(runtime="runsc", gvisor=True)
    )

    assert result["ulimits"] == [NOFILE, NPROC]
    assert result["pids_limit"] == 1536


def test_container_tier_keeps_nofile_and_512() -> None:
    settings = Settings(isolation_runtimes=TIER_MAP)

    result = config(make_spec(isolation="container"), settings)

    assert result["ulimits"] == [NOFILE]
    assert result["pids_limit"] == PIDS_LIMIT


def test_microvm_tier_keeps_nofile_and_512() -> None:
    settings = Settings(isolation_runtimes=TIER_MAP)

    result = config(make_spec(isolation="microvm"), settings)

    assert result["ulimits"] == [NOFILE]
    assert result["pids_limit"] == PIDS_LIMIT


def test_nproc_limit_equals_the_pids_limit() -> None:
    assert NPROC_LIMIT == PIDS_LIMIT == 512


def test_gvisor_pids_limit_is_three_times_the_guest_cap() -> None:
    # About 2 sentry host threads per guest task were measured, so 3x leaves headroom: the
    # guest hits nproc before the sentry hits the host pids limit.
    assert GVISOR_PIDS_LIMIT == 3 * PIDS_LIMIT


def test_every_ulimit_entry_builds_a_docker_ulimit() -> None:
    docker = pytest.importorskip("docker")
    settings = Settings(isolation_runtimes=TIER_MAP)

    result = config(make_spec(isolation="gvisor"), settings)

    for entry in result["ulimits"]:
        assert docker.types.Ulimit(**entry).name == entry["Name"]
