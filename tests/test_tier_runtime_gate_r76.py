"""Round 76: prod refuses isolation tiers mapped to an empty runtime unless acknowledged.

A tier map entry such as ``container=`` runs on whatever the daemon default runtime is. The
prod preflight lists that, ``SANDFORT_ALLOW_DEFAULT_RUNTIME_TIER=true`` accepts it, and the
doctor shows a ``tier runtimes`` row that equals the gate's verdict. The family check
(``gvisor`` off ``runsc``, ``microvm`` off ``kata``) runs first, so a blank gvisor or microvm
runtime surfaces as that error and never as the blank-tier message.
"""

import base64
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet

from sandfort import admin_doctor
from sandfort.admin_doctor_rows import TIER_RUNTIMES_ROW, Status, tier_runtime_row
from sandfort.config import DEFAULT_ALLOW_DEFAULT_RUNTIME_TIER, Settings
from sandfort.domain.isolation import TierRuntimes
from sandfort.drivers.docker.capabilities import DockerCapabilities
from sandfort.preflight import (
    DEFAULT_RUNTIME_TIER_MESSAGE,
    ConfigurationError,
    check_preflight,
    prod_findings,
    tier_runtime_findings,
)

KEY = Fernet.generate_key().decode()
CHAIN_KEY = "c" * 40
SIGNING_KEY = base64.urlsafe_b64encode(b"s" * 32).decode()
CAPACITY = {"host_capacity_cpu_millicores": 4000, "host_capacity_memory_mib": 8192}
ACK_ENV = "SANDFORT_ALLOW_DEFAULT_RUNTIME_TIER"
BLANK_CONTAINER: TierRuntimes = (("container", ""), ("gvisor", "runsc"), ("microvm", "kata"))
NAMED: TierRuntimes = (("container", "runc"), ("gvisor", "runsc"), ("microvm", "kata"))
ALL_BLANK: TierRuntimes = (("container", ""), ("gvisor", ""), ("microvm", ""))
GVISOR_ON_KATA: TierRuntimes = (("container", "runc"), ("gvisor", "kata"))
BLANK_GVISOR_FINDING = (
    "isolation tier 'gvisor' needs a runtime whose name starts with 'runsc', got runtime ''"
    " ('' = the daemon default); fix SANDFORT_ISOLATION_RUNTIMES"
    " (or SANDFORT_CONTAINER_RUNTIME when no tier map is set)"
)
GVISOR_ON_KATA_FINDING = BLANK_GVISOR_FINDING.replace("runtime ''", "runtime 'kata'")
EXPECTED_BLANK = DEFAULT_RUNTIME_TIER_MESSAGE.format(tiers=["container"])


def prod(**changes: Any) -> Settings:
    """Prod settings ready in every respect except what a test changes."""
    base: dict[str, Any] = {
        "webhook_secret_key": KEY,
        "audit_chain_key": CHAIN_KEY,
        "allow_default_runtime_tier": False,
        **CAPACITY,
    }
    return Settings(environment="prod", **{**base, **changes})


# --- the finder -------------------------------------------------------------------------


def test_outside_prod_a_blank_tier_is_not_a_finding() -> None:
    for environment in ("dev", "test"):
        settings = Settings(
            environment=environment,
            isolation_runtimes=BLANK_CONTAINER,
            allow_default_runtime_tier=False,
        )

        assert tier_runtime_findings(settings) == []


def test_prod_without_a_tier_map_is_not_a_finding() -> None:
    assert tier_runtime_findings(prod()) == []
    assert tier_runtime_findings(prod(container_runtime="")) == []
    assert tier_runtime_findings(prod(container_runtime="runc")) == []


def test_a_blank_container_tier_in_the_map_is_one_finding() -> None:
    settings = prod(isolation_runtimes=BLANK_CONTAINER)

    assert tier_runtime_findings(settings) == [EXPECTED_BLANK]
    assert "SANDFORT_ISOLATION_RUNTIMES" in EXPECTED_BLANK
    assert ACK_ENV in EXPECTED_BLANK
    assert "\n" not in EXPECTED_BLANK


def test_the_finding_is_part_of_prod_findings_and_the_start_error() -> None:
    settings = prod(isolation_runtimes=BLANK_CONTAINER)

    assert prod_findings(settings) == [EXPECTED_BLANK]
    with pytest.raises(ConfigurationError) as raised:
        check_preflight(settings)
    assert raised.value.findings == (EXPECTED_BLANK,)
    assert EXPECTED_BLANK in str(raised.value)


def test_acknowledging_the_default_runtime_clears_the_finding() -> None:
    settings = prod(isolation_runtimes=BLANK_CONTAINER, allow_default_runtime_tier=True)

    assert tier_runtime_findings(settings) == []
    assert prod_findings(settings) == []
    check_preflight(settings)  # does not raise


def test_a_map_naming_every_runtime_is_not_a_finding() -> None:
    settings = prod(isolation_runtimes=NAMED)

    assert tier_runtime_findings(settings) == []
    check_preflight(settings)  # does not raise


def test_a_whitespace_runtime_counts_as_blank() -> None:
    settings = prod(isolation_runtimes=(("container", "  "), ("gvisor", "runsc")))

    assert tier_runtime_findings(settings) == [EXPECTED_BLANK]


def test_a_family_violation_surfaces_as_the_finding_even_when_acknowledged() -> None:
    for acknowledged in (False, True):
        settings = prod(isolation_runtimes=GVISOR_ON_KATA, allow_default_runtime_tier=acknowledged)

        assert tier_runtime_findings(settings) == [GVISOR_ON_KATA_FINDING]


def test_an_all_blank_map_reports_the_family_check_not_the_blank_tier_message() -> None:
    settings = prod(isolation_runtimes=ALL_BLANK)

    findings = tier_runtime_findings(settings)

    assert findings == [BLANK_GVISOR_FINDING]
    assert findings != [EXPECTED_BLANK]


def test_the_finding_is_listed_next_to_the_other_prod_findings() -> None:
    unready = replace(
        Settings(environment="prod", isolation_runtimes=BLANK_CONTAINER),
        allow_default_runtime_tier=False,
    )

    findings = prod_findings(unready)

    assert EXPECTED_BLANK in findings
    assert len(findings) > 1


# --- Settings.from_env ------------------------------------------------------------------


def test_the_field_default_accepts_and_the_env_default_does_not() -> None:
    assert Settings().allow_default_runtime_tier is True
    assert DEFAULT_ALLOW_DEFAULT_RUNTIME_TIER is False
    assert Settings.from_env({}).allow_default_runtime_tier is False


def test_from_env_reads_the_acknowledgement() -> None:
    assert Settings.from_env({ACK_ENV: "true"}).allow_default_runtime_tier is True
    assert Settings.from_env({ACK_ENV: "false"}).allow_default_runtime_tier is False


def test_from_env_rejects_a_garbage_acknowledgement_naming_the_variable() -> None:
    with pytest.raises(ValueError, match=ACK_ENV):
        Settings.from_env({ACK_ENV: "maybe"})


def test_a_prod_environment_with_a_blank_tier_is_refused_until_acknowledged() -> None:
    environ = {
        "SANDFORT_ENVIRONMENT": "prod",
        "SANDFORT_AUDIT_CHAIN_KEY": CHAIN_KEY,
        "SANDFORT_WEBHOOK_SECRET_KEY": KEY,
        "SANDFORT_HOST_CAPACITY_CPU_MILLICORES": "4000",
        "SANDFORT_HOST_CAPACITY_MEMORY_MIB": "8192",
        "SANDFORT_ISOLATION_RUNTIMES": "container=,gvisor=runsc,microvm=kata",
    }

    refused = Settings.from_env(environ)
    accepted = Settings.from_env({**environ, ACK_ENV: "true"})

    assert prod_findings(refused) == [EXPECTED_BLANK]
    assert prod_findings(accepted) == []


# --- the doctor row ---------------------------------------------------------------------


def test_the_row_fails_with_the_finders_message() -> None:
    row = tier_runtime_row(prod(isolation_runtimes=BLANK_CONTAINER))

    assert row.name == TIER_RUNTIMES_ROW == "tier runtimes"
    assert row.status is Status.FAIL
    assert row.detail == EXPECTED_BLANK


def test_the_row_fails_with_the_family_message_for_an_all_blank_map() -> None:
    row = tier_runtime_row(prod(isolation_runtimes=ALL_BLANK))

    assert row.status is Status.FAIL
    assert row.detail == BLANK_GVISOR_FINDING


def test_the_row_passes_naming_the_acknowledgement() -> None:
    settings = prod(isolation_runtimes=BLANK_CONTAINER, allow_default_runtime_tier=True)
    row = tier_runtime_row(settings)

    assert row.status is Status.PASS
    assert row.detail == (
        f"tiers ['container'] run on the daemon default runtime; accepted by {ACK_ENV}"
    )


def test_the_row_lists_an_explicit_map_when_nothing_is_blank() -> None:
    row = tier_runtime_row(prod(isolation_runtimes=(("container", "runc"), ("gvisor", "runsc"))))

    assert row.status is Status.PASS
    assert row.detail == "tiers: container=runc, gvisor=runsc"


def test_the_row_in_single_runtime_mode() -> None:
    for settings in (prod(), prod(container_runtime="runc"), Settings(environment="dev")):
        row = tier_runtime_row(settings)

        assert row.status is Status.PASS
        assert row.detail == "single-runtime mode: no tier map"


def test_the_row_never_fails_outside_prod() -> None:
    dev = Settings(environment="dev", isolation_runtimes=BLANK_CONTAINER)

    assert tier_runtime_row(dev).status is Status.PASS


# --- doctor against the gate ------------------------------------------------------------


def doctor_settings(tmp_path: Path, **changes: Any) -> Settings:
    profile = tmp_path / "seccomp.json"
    profile.write_text("{}", encoding="utf-8")
    return prod(
        egress_acknowledged=True,
        require_userns_remap=True,
        database_url="postgresql+asyncpg://sandfort:secret@db.internal/sandfort",
        seccomp_profile_path=str(profile),
        allow_root_shared_kernel=False,
        audit_signing_key=SIGNING_KEY,
        **changes,
    )


def report() -> DockerCapabilities:
    return DockerCapabilities(
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


def tier_row(settings: Settings) -> tuple[Status, str]:
    rows = [r for r in admin_doctor.evaluate(settings, report()) if r.name == TIER_RUNTIMES_ROW]
    assert len(rows) == 1
    return rows[0].status, rows[0].detail


def test_the_doctor_fails_exactly_where_the_gate_refuses(tmp_path: Path) -> None:
    tiers: TierRuntimes = (("container", ""), ("gvisor", "runsc"))
    refused = doctor_settings(tmp_path, isolation_runtimes=tiers)
    accepted = replace(refused, allow_default_runtime_tier=True)

    refused_status, refused_detail = tier_row(refused)
    accepted_status, _ = tier_row(accepted)

    assert tier_runtime_findings(refused) == [refused_detail]
    assert refused_status is Status.FAIL
    assert tier_runtime_findings(accepted) == []
    assert accepted_status is Status.PASS


def test_a_healthy_prod_doctor_without_a_map_stays_all_pass(tmp_path: Path) -> None:
    results = admin_doctor.evaluate(doctor_settings(tmp_path), report())

    assert [r.status for r in results] == [Status.PASS] * len(results)
    assert TIER_RUNTIMES_ROW in [r.name for r in results]
