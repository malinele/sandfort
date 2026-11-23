"""Round 59: doctor shows every finding the start gate acts on, and the configuration rows.

A fake ``DockerCapabilities`` stands in for the daemon, so no docker is needed. The catch-all
test injects a synthetic gate finding that no named check knows and expects its own row.
"""

import base64
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet

from sandfort import admin_doctor
from sandfort.admin_doctor import CheckResult, Status
from sandfort.config import Settings
from sandfort.drivers.docker.capabilities import DockerCapabilities
from sandfort.preflight import FERNET_KEY_COMMAND

POSTGRES_URL = "postgresql+asyncpg://sandfort:secret@db.internal/sandfort"
ROOT_ROW = "root on shared kernel"
ROOT_PREFIX = "root on a shared kernel"
CAPACITY_ROW = "host capacity"
OVERRIDE_ENV = "SANDFORT_ALLOW_ROOT_SHARED_KERNEL"
UNBOUNDED_ENV = "SANDFORT_ALLOW_UNBOUNDED_HOST"
SYNTHETIC = "synthetic gap: a finding no named check consumes"
CPU_MILLICORES = 4000
MEMORY_MIB = 8192
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
        host_capacity_cpu_millicores=CPU_MILLICORES,
        host_capacity_memory_mib=MEMORY_MIB,
        allow_root_shared_kernel=False,
        audit_chain_key=AUDIT_CHAIN_KEY,
        audit_signing_key=AUDIT_SIGNING_KEY,
    )
    return replace(base, **changes)


def by_name(results: list[CheckResult]) -> dict[str, CheckResult]:
    return {result.name: result for result in results}


def shared_kernel_report() -> DockerCapabilities:
    """Remapping is off and the default tiers run on runc: container root is host root."""
    return make_report(userns_remap=False)


def add_synthetic_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    real = admin_doctor.gate_findings
    monkeypatch.setattr(
        admin_doctor, "gate_findings", lambda *args, **kwargs: [*real(*args, **kwargs), SYNTHETIC]
    )


def test_healthy_prod_passes_every_row_including_root_and_capacity(tmp_path: Path) -> None:
    results = admin_doctor.evaluate(prod_settings(tmp_path), make_report())

    checks = by_name(results)
    assert [r.status for r in results] == [Status.PASS] * len(results)
    assert ROOT_ROW in checks
    assert CAPACITY_ROW in checks


def test_root_on_shared_kernel_fails_in_prod(tmp_path: Path) -> None:
    settings = prod_settings(tmp_path, require_userns_remap=False)

    checks = by_name(admin_doctor.evaluate(settings, shared_kernel_report()))

    assert checks[ROOT_ROW].status is Status.FAIL
    assert checks[ROOT_ROW].detail.startswith(ROOT_PREFIX)
    assert OVERRIDE_ENV in checks[ROOT_ROW].detail
    assert checks["userns remap"].status is Status.WARN


def test_root_on_shared_kernel_passes_naming_the_override_when_allowed(tmp_path: Path) -> None:
    settings = prod_settings(tmp_path, require_userns_remap=False, allow_root_shared_kernel=True)

    checks = by_name(admin_doctor.evaluate(settings, shared_kernel_report()))

    assert checks[ROOT_ROW].status is Status.PASS
    assert OVERRIDE_ENV in checks[ROOT_ROW].detail


def test_root_row_passes_when_no_tier_runs_root_on_the_host(tmp_path: Path) -> None:
    checks = by_name(admin_doctor.evaluate(prod_settings(tmp_path), make_report()))

    assert checks[ROOT_ROW].status is Status.PASS
    assert OVERRIDE_ENV not in checks[ROOT_ROW].detail


def test_root_row_only_warns_outside_prod(tmp_path: Path) -> None:
    dev = replace(prod_settings(tmp_path, require_userns_remap=False), environment="dev")

    checks = by_name(admin_doctor.evaluate(dev, shared_kernel_report()))

    assert checks[ROOT_ROW].status is Status.WARN


def test_unmatched_gate_finding_becomes_its_own_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    add_synthetic_finding(monkeypatch)
    prod = prod_settings(tmp_path)

    prod_row = by_name(admin_doctor.evaluate(prod, make_report()))["synthetic gap"]
    dev = replace(prod, environment="dev")
    dev_row = by_name(admin_doctor.evaluate(dev, make_report()))["synthetic gap"]

    assert prod_row.status is Status.FAIL
    assert prod_row.detail == SYNTHETIC
    assert dev_row.status is Status.WARN


def test_gate_finding_without_a_named_check_is_reported_once(tmp_path: Path) -> None:
    settings = prod_settings(tmp_path, min_runc_version="1.1.12")
    report = make_report(runc_version="1.0.0")

    results = admin_doctor.evaluate(settings, report)

    runc_rows = [r for r in results if r.name == "runc version"]
    assert len(runc_rows) == 1
    assert runc_rows[0].status is Status.FAIL


def test_named_findings_are_consumed_and_never_repeated(tmp_path: Path) -> None:
    settings = prod_settings(
        tmp_path, egress_acknowledged=False, container_runtime="kata", min_runc_version="1.1.12"
    )
    report = make_report(
        userns_remap=False,
        disk_quota_supported=False,
        configured_runtime="kata",
        runc_version="1.0.0",
    )

    results = admin_doctor.evaluate(settings, report)

    names = [result.name for result in results]
    assert len(names) == len(set(names))
    for catch_all_name in (
        "user-namespace remapping",
        "host egress enforcement",
        "disk quota support (storage-opt size)",
        "container runtime 'kata'",
        ROOT_PREFIX,
    ):
        assert catch_all_name not in names
    assert sum(1 for r in results if r.detail.startswith(ROOT_PREFIX)) <= 1


def test_a_synthetic_finding_is_in_one_row_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    add_synthetic_finding(monkeypatch)
    settings = prod_settings(tmp_path, require_userns_remap=False)

    results = admin_doctor.evaluate(settings, shared_kernel_report())

    assert sum(1 for r in results if SYNTHETIC in r.detail) == 1
    assert sum(1 for r in results if r.detail.startswith(ROOT_PREFIX)) == 1


def test_host_capacity_row_in_the_three_states(tmp_path: Path) -> None:
    prod = prod_settings(tmp_path)
    unconfigured = replace(prod, host_capacity_cpu_millicores=0, host_capacity_memory_mib=0)
    dev = replace(unconfigured, environment="dev")

    configured_row = by_name(admin_doctor.evaluate(prod, make_report()))[CAPACITY_ROW]
    prod_row = by_name(admin_doctor.evaluate(unconfigured, make_report()))[CAPACITY_ROW]
    dev_row = by_name(admin_doctor.evaluate(dev, make_report()))[CAPACITY_ROW]

    assert configured_row.status is Status.PASS
    assert str(CPU_MILLICORES) in configured_row.detail
    assert str(MEMORY_MIB) in configured_row.detail
    assert prod_row.status is Status.FAIL
    assert "SANDFORT_HOST_CAPACITY_CPU_MILLICORES" in prod_row.detail
    assert dev_row.status is Status.WARN


def test_host_capacity_override_is_named(tmp_path: Path) -> None:
    settings = prod_settings(
        tmp_path,
        host_capacity_cpu_millicores=0,
        host_capacity_memory_mib=0,
        allow_unbounded_host=True,
    )

    row = by_name(admin_doctor.evaluate(settings, make_report()))[CAPACITY_ROW]

    assert row.status is Status.PASS
    assert UNBOUNDED_ENV in row.detail


def test_half_configured_capacity_fails_in_prod(tmp_path: Path) -> None:
    settings = prod_settings(tmp_path, host_capacity_memory_mib=0)

    row = by_name(admin_doctor.evaluate(settings, make_report()))[CAPACITY_ROW]

    assert row.status is Status.FAIL


def test_webhook_row_detail_carries_the_key_generation_command(tmp_path: Path) -> None:
    settings = prod_settings(tmp_path, webhook_secret_key="")

    row = by_name(admin_doctor.evaluate(settings, make_report()))["webhook secret"]

    assert row.status is Status.FAIL
    assert "SANDFORT_WEBHOOK_SECRET_KEY" in row.detail
    assert FERNET_KEY_COMMAND in row.detail


def test_webhook_row_outside_prod_warns_without_failing(tmp_path: Path) -> None:
    dev = replace(prod_settings(tmp_path), environment="dev", webhook_secret_key="")

    row = by_name(admin_doctor.evaluate(dev, make_report()))["webhook secret"]

    assert row.status is Status.WARN


def test_final_line_says_the_gate_would_start(tmp_path: Path) -> None:
    results = admin_doctor.evaluate(prod_settings(tmp_path), make_report())

    lines = admin_doctor.render_text(results, gate_line=True).splitlines()

    assert lines[-2].startswith("summary:")
    assert lines[-1] == "the start gate would start"


def test_final_line_counts_the_refusing_findings(tmp_path: Path) -> None:
    settings = prod_settings(tmp_path, webhook_secret_key="", require_userns_remap=False)
    results = admin_doctor.evaluate(settings, shared_kernel_report())
    fails = sum(1 for r in results if r.status is Status.FAIL)

    lines = admin_doctor.render_text(results, gate_line=True).splitlines()

    assert fails == 2  # the webhook key and root on a shared kernel
    assert lines[-1] == f"the start gate would refuse: {fails} failing check(s)"


def test_text_without_the_gate_line_ends_at_the_summary(tmp_path: Path) -> None:
    results = admin_doctor.evaluate(prod_settings(tmp_path), make_report())

    lines = admin_doctor.render_text(results).splitlines()

    assert lines[-1].startswith("summary:")


def test_run_doctor_prints_the_whole_list_when_prod_config_is_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_fetch(settings: Settings) -> tuple[DockerCapabilities, list[str] | None]:
        return make_report(), None

    monkeypatch.setattr(admin_doctor, "fetch_host", fake_fetch)
    settings = prod_settings(
        tmp_path,
        webhook_secret_key="",
        host_capacity_cpu_millicores=0,
        host_capacity_memory_mib=0,
    )
    printed: list[str] = []

    code = admin_doctor.run_doctor(settings, as_json=False, echo=lambda text: printed.append(text))

    output = printed[0]
    assert code == 1
    assert "FAIL webhook secret:" in output
    assert "FAIL host capacity:" in output
    assert "PASS docker daemon:" in output
    assert output.splitlines()[-1] == "the start gate would refuse: 2 failing check(s)"
