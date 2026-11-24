"""Round 59 review fixes: revoke-key selectors and the doctor verdict, driver and capacity rows.

Pure tests: ``pick_key`` runs on in-memory keys, the selector checks run before any database is
opened, and a fake ``DockerCapabilities`` stands in for the daemon.
"""

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet
from typer.testing import CliRunner

from sandfort import admin_cli, admin_doctor, admin_keys
from sandfort.admin_doctor import CheckResult, Status
from sandfort.api.app import NON_DOCKER_DRIVER_MESSAGE
from sandfort.config import Settings
from sandfort.domain.org import ApiKey
from sandfort.drivers.docker.capabilities import DockerCapabilities
from sandfort.errors import NotFound, ValidationFailed

RUNNER = CliRunner()
POSTGRES_URL = "postgresql+asyncpg://sandfort:secret@db.internal/sandfort"
PREFIX = "sf_live_ab12cd34"
SECRET = "S3cretS3cretS3cretS3cretS3cretS3cretS3cre"  # 40 characters, then three more
FULL_KEY = f"{PREFIX}_{SECRET}XYZ"
CPU_MILLICORES = 4000
MEMORY_MIB = 8192
AUDIT_CHAIN_KEY = "a-test-audit-chain-key-32-bytes!!"  # prod refuses to start without one
UNBOUNDED_ENV = "SANDFORT_ALLOW_UNBOUNDED_HOST"
CPU_ENV = "SANDFORT_HOST_CAPACITY_CPU_MILLICORES"
MEMORY_ENV = "SANDFORT_HOST_CAPACITY_MEMORY_MIB"


def make_key(key_id: str, prefix: str) -> ApiKey:
    return ApiKey(
        id=key_id,
        org_id="org_1",
        name=f"name-{key_id}",
        prefix=prefix,
        secret_hash="v1$00$00",
        created_at=datetime(2026, 11, 1, tzinfo=UTC),
    )


KEYS = [make_key("key_1", PREFIX), make_key("key_2", "sf_live_zz99yy88")]


def make_report(**changes: Any) -> DockerCapabilities:
    base = DockerCapabilities(
        "27.0.1",
        "1.46",
        True,
        storage_driver="overlay2",
        backing_filesystem="xfs",
        disk_quota_supported=True,
        runtimes=("runc", "runsc"),
        userns_remap=True,
        default_runtime="runc",
        cgroup_driver="systemd",
    )
    return replace(base, **changes)


def prod_settings(tmp_path: Path, **changes: Any) -> Settings:
    profile = tmp_path / "seccomp.json"
    profile.write_text("{}", encoding="utf-8")
    base = Settings(
        environment="prod",
        egress_acknowledged=True,
        webhook_secret_key=Fernet.generate_key().decode(),
        audit_chain_key=AUDIT_CHAIN_KEY,
        require_userns_remap=True,
        database_url=POSTGRES_URL,
        seccomp_profile_path=str(profile),
        host_capacity_cpu_millicores=CPU_MILLICORES,
        host_capacity_memory_mib=MEMORY_MIB,
    )
    return replace(base, **changes)


def by_name(results: list[CheckResult]) -> dict[str, CheckResult]:
    return {result.name: result for result in results}


# 1. pick_key never echoes more than the prefix


def test_full_key_as_prefix_selects_by_its_prefix() -> None:
    assert admin_keys.pick_key(KEYS, None, FULL_KEY).id == "key_1"


def test_unknown_full_key_error_shows_only_the_prefix() -> None:
    unknown = f"sf_live_nomatch1_{SECRET}XYZ"

    with pytest.raises(NotFound) as caught:
        admin_keys.pick_key(KEYS, None, unknown)

    assert "sf_live_nomatch1" in str(caught.value)
    assert SECRET[:10] not in str(caught.value)


def test_unknown_truncated_key_error_shows_only_the_prefix() -> None:
    with pytest.raises(NotFound) as caught:
        admin_keys.pick_key(KEYS, None, "sf_live_nomatch1_" + SECRET[:10])

    assert SECRET[:10] not in str(caught.value)


def test_ambiguous_prefix_error_never_contains_the_pasted_secret() -> None:
    twins = [make_key("key_1", PREFIX), make_key("key_3", PREFIX)]

    with pytest.raises(ValidationFailed) as caught:
        admin_keys.pick_key(twins, None, FULL_KEY)

    message = str(caught.value)
    assert "matches 2 keys" in message
    assert PREFIX in message
    assert SECRET[:10] not in message


def test_short_prefix_still_matches_by_startswith() -> None:
    assert admin_keys.pick_key(KEYS, None, "sf_live_ab12").id == "key_1"


# 2. blank selectors are a usage error


@pytest.mark.parametrize(
    "args",
    [
        ["--org-slug", "acme", "--key-id", ""],
        ["--org-slug", "acme", "--key-id", "   "],
        ["--org-slug", "", "--key-id", "key_x"],
        ["--org-slug", "  ", "--prefix", "sf_live_"],
        ["--org-id", " ", "--key-id", "key_x"],
        ["--org-slug", "acme", "--prefix", " \t "],
    ],
)
def test_blank_selector_is_a_usage_error_with_exit_2(args: list[str]) -> None:
    result = RUNNER.invoke(admin_cli.app, ["revoke-key", *args])

    assert result.exit_code == 2
    assert result.stderr.startswith("error: ")
    assert "must not be blank" in result.stderr
    assert "unknown" not in result.stderr


def test_check_selectors_strips_and_returns_the_selectors() -> None:
    cleaned = admin_keys.check_selectors(" acme ", None, None, f"  {PREFIX}  ")

    assert cleaned == ("acme", None, None, PREFIX)


# 3. doctor: driver row and verdict


def test_driver_row_passes_for_docker(tmp_path: Path) -> None:
    row = by_name(admin_doctor.evaluate(prod_settings(tmp_path), make_report()))["driver"]

    assert row.status is Status.PASS
    assert "docker" in row.detail


def test_driver_row_fails_in_prod_for_a_non_docker_driver(tmp_path: Path) -> None:
    settings = prod_settings(tmp_path, driver="fake")

    results = admin_doctor.evaluate(settings, make_report())

    row = by_name(results)["driver"]
    assert row.status is Status.FAIL
    assert row.detail == NON_DOCKER_DRIVER_MESSAGE.format(driver="fake")
    assert admin_doctor.has_failure(results)


def test_driver_row_only_warns_outside_prod(tmp_path: Path) -> None:
    dev = prod_settings(tmp_path, driver="fake", environment="dev")

    row = by_name(admin_doctor.evaluate(dev, make_report()))["driver"]

    assert row.status is Status.WARN


def test_verdict_refuses_for_a_non_docker_driver_in_prod(tmp_path: Path) -> None:
    results = admin_doctor.evaluate(prod_settings(tmp_path, driver="fake"), make_report())

    lines = admin_doctor.render_text(results, gate_line=True).splitlines()

    assert lines[-1] == "the start gate would refuse: 1 failing check(s)"


def test_verdict_counts_the_failing_rows(tmp_path: Path) -> None:
    settings = prod_settings(tmp_path, driver="fake", webhook_secret_key="")
    results = admin_doctor.evaluate(settings, make_report())
    failing = sum(1 for r in results if r.status is Status.FAIL)

    verdict = admin_doctor.gate_verdict(results)

    assert failing == 2
    assert verdict == f"the start gate would refuse: {failing} failing check(s)"


def test_json_output_carries_the_verdict_at_the_top_level(tmp_path: Path) -> None:
    results = admin_doctor.evaluate(prod_settings(tmp_path, driver="fake"), make_report())

    parsed = json.loads(admin_doctor.render_json(results))

    assert parsed["verdict"] == admin_doctor.gate_verdict(results)
    assert [item["name"] for item in parsed["checks"]] == [r.name for r in results]
    assert {"name", "status", "detail"} == set(parsed["checks"][0])


def test_json_verdict_says_start_for_a_healthy_host(tmp_path: Path) -> None:
    results = admin_doctor.evaluate(prod_settings(tmp_path), make_report())

    parsed = json.loads(admin_doctor.render_json(results))

    assert parsed["verdict"] == "the start gate would start"


# 4. capacity row names the missing value


def test_unbounded_override_with_only_cpu_set_names_memory(tmp_path: Path) -> None:
    settings = prod_settings(tmp_path, host_capacity_memory_mib=0, allow_unbounded_host=True)

    row = by_name(admin_doctor.evaluate(settings, make_report()))["host capacity"]

    assert row.status is Status.PASS
    assert MEMORY_ENV in row.detail
    assert CPU_ENV not in row.detail
    assert "no host-wide limit" not in row.detail
    assert UNBOUNDED_ENV in row.detail


def test_unbounded_override_with_only_memory_set_names_cpu(tmp_path: Path) -> None:
    settings = prod_settings(tmp_path, host_capacity_cpu_millicores=0, allow_unbounded_host=True)

    row = by_name(admin_doctor.evaluate(settings, make_report()))["host capacity"]

    assert row.status is Status.PASS
    assert CPU_ENV in row.detail
    assert MEMORY_ENV not in row.detail
    assert "no host-wide limit" not in row.detail


def test_unbounded_override_with_nothing_set_still_says_no_limit(tmp_path: Path) -> None:
    settings = prod_settings(
        tmp_path,
        host_capacity_cpu_millicores=0,
        host_capacity_memory_mib=0,
        allow_unbounded_host=True,
    )

    row = by_name(admin_doctor.evaluate(settings, make_report()))["host capacity"]

    assert row.status is Status.PASS
    assert "no host-wide limit" in row.detail
    assert UNBOUNDED_ENV in row.detail
