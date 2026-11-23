"""Round 58: ``admin_cli doctor`` judges a docker capability report and the prod settings.

A fake ``DockerCapabilities`` stands in for the daemon, so no docker is needed. The agreement
test runs the startup gate (``check_isolation``) on the same report and settings and asserts
the doctor reports a FAIL exactly when the gate refuses the start.
"""

import asyncio
import base64
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet
from typer.testing import CliRunner

from sandfort import admin_cli, admin_doctor
from sandfort.admin_doctor import CheckResult, Status
from sandfort.api.app import IsolationUnavailableError, check_isolation
from sandfort.config import Settings
from sandfort.domain.isolation import DEFAULT_TIER
from sandfort.drivers.docker.capabilities import DockerCapabilities, missing_isolation
from sandfort.drivers.errors import DriverError

RUNNER = CliRunner()
POSTGRES_URL = "postgresql+asyncpg://sandfort:secret@db.internal/sandfort"
HOST_CPU_MILLICORES = 4000
HOST_MEMORY_MIB = 8192
AUDIT_CHAIN_KEY = "c" * 40
AUDIT_SIGNING_KEY = base64.urlsafe_b64encode(b"s" * 32).decode()  # the row the audit keys check


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
        require_userns_remap=True,
        database_url=POSTGRES_URL,
        seccomp_profile_path=str(profile),
        host_capacity_cpu_millicores=HOST_CPU_MILLICORES,
        host_capacity_memory_mib=HOST_MEMORY_MIB,
        audit_chain_key=AUDIT_CHAIN_KEY,
        audit_signing_key=AUDIT_SIGNING_KEY,
    )
    return replace(base, **changes)


def by_name(results: list[CheckResult]) -> dict[str, CheckResult]:
    return {result.name: result for result in results}


def test_healthy_prod_host_passes_every_check(tmp_path: Path) -> None:
    results = admin_doctor.evaluate(prod_settings(tmp_path), make_report())

    assert [r.status for r in results] == [Status.PASS] * len(results)
    assert not admin_doctor.has_failure(results)


def test_missing_disk_quota_fails_in_prod(tmp_path: Path) -> None:
    report = make_report(
        storage_driver="vfs", backing_filesystem="ext4", disk_quota_supported=False
    )

    checks = by_name(admin_doctor.evaluate(prod_settings(tmp_path), report))

    assert checks["storage and disk quota"].status is Status.FAIL
    assert "vfs" in checks["storage and disk quota"].detail


def test_unregistered_default_tier_runtime_fails_in_prod(tmp_path: Path) -> None:
    settings = prod_settings(tmp_path, container_runtime="kata")
    report = make_report(configured_runtime="kata")

    checks = by_name(admin_doctor.evaluate(settings, report))

    assert checks["runtimes"].status is Status.FAIL


def test_registered_tier_map_runtimes_pass(tmp_path: Path) -> None:
    pairs = ((DEFAULT_TIER, "runc"), ("gvisor", "runsc"))
    settings = prod_settings(tmp_path, isolation_runtimes=pairs)

    checks = by_name(admin_doctor.evaluate(settings, make_report()))

    assert checks["runtimes"].status is Status.PASS
    assert checks["default runtime"].status is Status.PASS


def test_extra_tier_without_registered_runtime_warns(tmp_path: Path) -> None:
    pairs = ((DEFAULT_TIER, "runc"), ("gvisor", "runsc"))
    settings = prod_settings(tmp_path, isolation_runtimes=pairs)
    report = make_report(runtimes=("runc",))

    checks = by_name(admin_doctor.evaluate(settings, report))

    assert checks["runtimes"].status is Status.WARN
    assert "runsc" in checks["runtimes"].detail


def test_default_runtime_used_by_no_tier_warns(tmp_path: Path) -> None:
    settings = prod_settings(tmp_path, container_runtime="runsc")
    report = make_report(configured_runtime="runsc")

    checks = by_name(admin_doctor.evaluate(settings, report))

    assert checks["default runtime"].status is Status.WARN
    assert checks["runtimes"].status is Status.PASS


def test_missing_userns_remap_warns_in_prod_unless_required(tmp_path: Path) -> None:
    report = make_report(userns_remap=False)
    relaxed = prod_settings(tmp_path, require_userns_remap=False)
    strict = prod_settings(tmp_path, require_userns_remap=True)

    relaxed_checks = by_name(admin_doctor.evaluate(relaxed, report))
    strict_checks = by_name(admin_doctor.evaluate(strict, report))

    assert relaxed_checks["userns remap"].status is Status.WARN
    assert relaxed_checks["require userns remap"].status is Status.WARN
    assert strict_checks["userns remap"].status is Status.FAIL


def test_unacknowledged_egress_fails_in_prod_and_warns_in_dev(tmp_path: Path) -> None:
    prod = prod_settings(tmp_path, egress_acknowledged=False)
    dev = replace(prod, environment="dev")

    prod_checks = by_name(admin_doctor.evaluate(prod, make_report()))
    dev_checks = by_name(admin_doctor.evaluate(dev, make_report()))

    assert prod_checks["egress acknowledged"].status is Status.FAIL
    assert dev_checks["egress acknowledged"].status is Status.WARN


def test_dev_environment_only_warns(tmp_path: Path) -> None:
    dev = replace(prod_settings(tmp_path), environment="dev", webhook_secret_key="")
    report = make_report(disk_quota_supported=False, userns_remap=False)

    results = admin_doctor.evaluate(dev, report)

    assert not admin_doctor.has_failure(results)
    assert by_name(results)["environment"].status is Status.WARN
    assert by_name(results)["storage and disk quota"].status is Status.WARN
    assert by_name(results)["webhook secret"].status is Status.WARN


def test_empty_webhook_secret_fails_in_prod(tmp_path: Path) -> None:
    settings = prod_settings(tmp_path, webhook_secret_key="")

    checks = by_name(admin_doctor.evaluate(settings, make_report()))

    assert checks["webhook secret"].status is Status.FAIL


def test_seccomp_profile_must_be_readable_json(tmp_path: Path) -> None:
    missing = prod_settings(tmp_path, seccomp_profile_path=str(tmp_path / "absent.json"))
    unset = prod_settings(tmp_path, seccomp_profile_path="")

    missing_check = by_name(admin_doctor.evaluate(missing, make_report()))["seccomp profile"]
    unset_check = by_name(admin_doctor.evaluate(unset, make_report()))["seccomp profile"]

    assert missing_check.status is Status.FAIL
    assert "unreadable" in missing_check.detail
    assert unset_check.status is Status.PASS


def test_cgroup_parent_slice_with_cgroupfs_driver_warns(tmp_path: Path) -> None:
    settings = prod_settings(tmp_path, cgroup_parent="sandfort.slice")

    on_systemd = by_name(admin_doctor.evaluate(settings, make_report()))
    on_cgroupfs = by_name(admin_doctor.evaluate(settings, make_report(cgroup_driver="cgroupfs")))

    assert on_systemd["cgroup parent"].status is Status.PASS
    assert on_cgroupfs["cgroup parent"].status is Status.WARN


def test_unreported_cgroup_driver_warns(tmp_path: Path) -> None:
    checks = by_name(admin_doctor.evaluate(prod_settings(tmp_path), make_report(cgroup_driver="")))

    assert checks["cgroup driver"].status is Status.WARN


def test_userns_opt_out_tier_warns(tmp_path: Path) -> None:
    pairs = ((DEFAULT_TIER, "runc"), ("microvm", "kata"))
    settings = prod_settings(tmp_path, isolation_runtimes=pairs)

    checks = by_name(admin_doctor.evaluate(settings, make_report(runtimes=("runc", "kata"))))

    assert checks["userns opt-out tiers"].status is Status.WARN
    assert "microvm" in checks["userns opt-out tiers"].detail


def test_sqlite_in_prod_warns(tmp_path: Path) -> None:
    settings = prod_settings(tmp_path, database_url="sqlite+aiosqlite:///./sandfort.db")

    checks = by_name(admin_doctor.evaluate(settings, make_report()))

    assert checks["database"].status is Status.WARN
    assert "postgresql" in checks["database"].detail


def test_unreachable_daemon_fails(tmp_path: Path) -> None:
    results = admin_doctor.evaluate(prod_settings(tmp_path), None, "cannot probe: refused")

    checks = by_name(results)
    assert checks["docker daemon"].status is Status.FAIL
    assert checks["docker daemon"].detail == "cannot probe: refused"
    assert "storage and disk quota" not in checks


def test_daemon_without_version_fails(tmp_path: Path) -> None:
    report = make_report(daemon_version="unknown")

    checks = by_name(admin_doctor.evaluate(prod_settings(tmp_path), report))

    assert checks["docker daemon"].status is Status.FAIL


class _GateDriver:
    def __init__(self, gaps: list[str]) -> None:
        self._gaps = gaps

    async def isolation_gaps(self) -> list[str]:
        return self._gaps


def _gate_refuses(settings: Settings, report: DockerCapabilities) -> bool:
    driver = _GateDriver(missing_isolation(report, settings=settings))
    try:
        asyncio.run(check_isolation(driver, settings))
    except IsolationUnavailableError:
        return True
    return False


AGREEMENT_CASES: list[tuple[str, dict[str, Any], dict[str, Any]]] = [
    ("healthy-prod", {}, {}),
    ("prod-no-quota", {}, {"disk_quota_supported": False}),
    ("prod-no-remap-required", {}, {"userns_remap": False}),
    ("prod-no-remap-optional", {"require_userns_remap": False}, {"userns_remap": False}),
    ("prod-egress-unacknowledged", {"egress_acknowledged": False}, {}),
    ("prod-runtime-missing", {"container_runtime": "kata"}, {"configured_runtime": "kata"}),
    ("dev-no-quota", {"environment": "dev"}, {"disk_quota_supported": False}),
    (
        "dev-no-quota-enforced",
        {"environment": "dev", "enforce_disk_quota": True},
        {"disk_quota_supported": False},
    ),
    ("dev-no-remap", {"environment": "dev"}, {"userns_remap": False}),
]


@pytest.mark.parametrize(
    ("settings_changes", "report_changes"),
    [case[1:] for case in AGREEMENT_CASES],
    ids=[case[0] for case in AGREEMENT_CASES],
)
def test_doctor_fails_exactly_when_the_startup_gate_refuses(
    tmp_path: Path, settings_changes: dict[str, Any], report_changes: dict[str, Any]
) -> None:
    settings = prod_settings(tmp_path, **settings_changes)
    report = make_report(**report_changes)

    doctor_fails = admin_doctor.has_failure(admin_doctor.evaluate(settings, report))

    assert doctor_fails == _gate_refuses(settings, report)


def test_text_output_has_one_line_per_check_and_a_summary(tmp_path: Path) -> None:
    results = admin_doctor.evaluate(prod_settings(tmp_path, webhook_secret_key=""), make_report())

    lines = admin_doctor.render_text(results, gate_line=True).splitlines()

    assert len(lines) == len(results) + 2  # the checks, the summary and the prod verdict
    assert any(
        line.startswith("FAIL webhook secret: SANDFORT_WEBHOOK_SECRET_KEY is empty")
        for line in lines
    )
    assert lines[0].startswith("PASS environment:")
    assert lines[-2] == f"summary: {len(results) - 1} pass, 0 warn, 1 fail"
    assert lines[-1] == "the start gate would refuse: 1 failing check(s)"


def test_json_output_is_an_object_with_a_list_of_checks(tmp_path: Path) -> None:
    results = admin_doctor.evaluate(prod_settings(tmp_path), make_report())

    parsed = json.loads(admin_doctor.render_json(results))

    assert isinstance(parsed, dict)
    assert {"name", "status", "detail"} == set(parsed["checks"][0])
    assert [item["name"] for item in parsed["checks"]] == [r.name for r in results]
    assert "verdict" in parsed


def _patch_probe(monkeypatch: pytest.MonkeyPatch, outcome: DockerCapabilities | Exception) -> None:
    async def fake_fetch(settings: Settings) -> DockerCapabilities:
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(admin_doctor, "fetch_report", fake_fetch)
    monkeypatch.setenv("SANDFORT_ENVIRONMENT", "dev")


def test_cli_exits_zero_without_a_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_probe(monkeypatch, make_report())

    result = RUNNER.invoke(admin_cli.app, ["doctor"])

    assert result.exit_code == 0, result.output
    assert "PASS docker daemon: version 27.0.1, api 1.46" in result.output
    assert "summary:" in result.output


def test_cli_json_flag_prints_a_list(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_probe(monkeypatch, make_report())

    result = RUNNER.invoke(admin_cli.app, ["doctor", "--json"])

    assert result.exit_code == 0, result.output
    checks = json.loads(result.stdout)["checks"]
    assert {item["status"] for item in checks} <= {"PASS", "WARN", "FAIL"}
    assert any(item["name"] == "docker daemon" for item in checks)


def test_cli_exits_one_when_the_daemon_cannot_be_probed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_probe(monkeypatch, DriverError("cannot connect to the Docker daemon: refused"))

    result = RUNNER.invoke(admin_cli.app, ["doctor"])

    assert result.exit_code == 1
    assert "FAIL docker daemon: cannot probe the docker daemon" in result.output


def test_cli_exits_one_on_invalid_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_probe(monkeypatch, make_report())
    monkeypatch.setenv("SANDFORT_ENVIRONMENT", "staging")

    result = RUNNER.invoke(admin_cli.app, ["doctor"])

    assert result.exit_code == 1
    assert "SANDFORT_ENVIRONMENT must be one of" in result.output
    assert "summary:" not in result.output
