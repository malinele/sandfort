"""Round 61: the audit signing key needs the audit chain key.

A signing key without a chain key signed nothing: ``/v1/status`` still published its public key,
startup was silent and every export ended in an unsigned summary. Now ``Settings.from_env``
refuses the combination in prod and warns once in dev, ``/v1/status`` publishes the public key
only when heads are signed, and the doctor has one ``audit keys`` row.
"""

import base64
import hashlib
import json
import logging
from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sandfort.main as server_main
from sandfort import admin_doctor
from sandfort.admin_doctor import CheckResult, Status
from sandfort.admin_doctor_rows import audit_keys_row
from sandfort.api.routes import health
from sandfort.config import SIGNING_WITHOUT_CHAIN_KEY, Settings
from sandfort.drivers.docker.capabilities import DockerCapabilities
from sandfort.preflight import ConfigurationError, check_preflight, prod_findings
from sandfort.services.audit_chain import ChainPolicy

CHAIN_ENV = "SANDFORT_AUDIT_CHAIN_KEY"
SIGN_ENV = "SANDFORT_AUDIT_SIGNING_KEY"
ENV_NAME = "SANDFORT_ENVIRONMENT"
CHAIN_KEY = "c" * 40
SEED = b"s" * 32
SIGNING_KEY = base64.urlsafe_b64encode(SEED).decode()
ROW = "audit keys"
NEEDS_CHAIN = "signing needs the chain key"
FINGERPRINT_CHARS = 16
CONFIG_LOGGER = "sandfort.config"
BAD_SIGNING_KEY = "not-a-key-SECRETVALUE"
WEBHOOK_KEY = base64.urlsafe_b64encode(b"w" * 32).decode()
REFUSES = "the start gate would refuse: 1 failing check(s)"
STARTS = "the start gate would start"


def public_bytes() -> bytes:
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


PUBLIC_TEXT = base64.urlsafe_b64encode(public_bytes()).decode()
FINGERPRINT = hashlib.sha256(public_bytes()).hexdigest()[:FINGERPRINT_CHARS]


def load(environment: str, **keys: str) -> Settings:
    source = {ENV_NAME: environment, **keys}
    return Settings.from_env(source)


def status_settings(**changes: Any) -> Settings:
    base = Settings(
        driver="fake", database_url="sqlite+aiosqlite:///:memory:", api_key_pepper="test-pepper"
    )
    return replace(base, **changes)


def doctor_row(settings: Settings) -> CheckResult:
    results = admin_doctor.evaluate(settings, None, "no daemon in this test")
    rows = [result for result in results if result.name == ROW]
    assert len(rows) == 1
    return rows[0]


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(CHAIN_ENV, raising=False)
    monkeypatch.delenv(SIGN_ENV, raising=False)


# --- Settings.from_env ----------------------------------------------------------------------


def test_prod_refuses_a_signing_key_without_the_chain_key() -> None:
    with pytest.raises(ValueError, match=NEEDS_CHAIN) as caught:
        load("prod", **{SIGN_ENV: SIGNING_KEY})

    assert CHAIN_ENV in str(caught.value)
    assert SIGN_ENV in str(caught.value)
    assert SIGNING_KEY not in str(caught.value)


def test_prod_refuses_a_blank_chain_key_next_to_a_signing_key() -> None:
    with pytest.raises(ValueError, match=NEEDS_CHAIN):
        load("prod", **{SIGN_ENV: SIGNING_KEY, CHAIN_ENV: "   "})


def test_prod_accepts_both_keys() -> None:
    settings = load("prod", **{SIGN_ENV: SIGNING_KEY, CHAIN_ENV: CHAIN_KEY})

    assert settings.audit_signing_key == SIGNING_KEY
    assert settings.audit_chain_key == CHAIN_KEY


def test_prod_accepts_the_chain_key_alone() -> None:
    settings = load("prod", **{CHAIN_ENV: CHAIN_KEY})

    assert settings.audit_signing_key == ""


def test_prod_accepts_neither_key_as_before(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger=CONFIG_LOGGER):
        settings = load("prod")

    assert settings.audit_chain_key == ""
    assert not [r for r in caplog.records if NEEDS_CHAIN in r.getMessage()]


def test_dev_warns_once_and_continues(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger=CONFIG_LOGGER):
        settings = load("dev", **{SIGN_ENV: SIGNING_KEY})

    warned = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warned) == 1
    message = warned[0].getMessage()
    assert NEEDS_CHAIN in message
    assert CHAIN_ENV in message
    assert SIGN_ENV in message
    assert SIGNING_KEY not in message
    assert settings.audit_signing_key == SIGNING_KEY


def test_the_default_environment_also_warns_and_continues(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=CONFIG_LOGGER):
        settings = Settings.from_env({SIGN_ENV: SIGNING_KEY})

    assert len([r for r in caplog.records if NEEDS_CHAIN in r.getMessage()]) == 1
    assert settings.audit_signer() is not None


@pytest.mark.parametrize(
    "keys",
    [
        {SIGN_ENV: SIGNING_KEY, CHAIN_ENV: CHAIN_KEY},
        {CHAIN_ENV: CHAIN_KEY},
        {},
    ],
    ids=["both", "chain-only", "neither"],
)
def test_dev_is_silent_without_the_bad_combination(
    caplog: pytest.LogCaptureFixture, keys: dict[str, str]
) -> None:
    with caplog.at_level(logging.WARNING, logger=CONFIG_LOGGER):
        load("dev", **keys)

    assert not [r for r in caplog.records if NEEDS_CHAIN in r.getMessage()]


# --- GET /v1/status -------------------------------------------------------------------------


def test_status_publishes_the_key_when_both_keys_are_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    settings = status_settings(audit_signing_key=SIGNING_KEY, audit_chain_key=CHAIN_KEY)

    assert health.status_payload(settings)["audit_public_key"] == PUBLIC_TEXT


def test_status_publishes_nothing_for_a_signing_key_alone() -> None:
    settings = status_settings(audit_signing_key=SIGNING_KEY)

    assert health.status_payload(settings)["audit_public_key"] is None


def test_status_publishes_nothing_for_the_chain_key_alone() -> None:
    settings = status_settings(audit_chain_key=CHAIN_KEY)

    assert health.status_payload(settings)["audit_public_key"] is None


def test_status_publishes_nothing_without_either_key() -> None:
    assert health.status_payload(status_settings())["audit_public_key"] is None


def test_status_ignores_a_chain_key_that_only_the_settings_carry() -> None:
    # The export route reads the environment, so it would not sign here: status must not publish.
    settings = status_settings(audit_signing_key=SIGNING_KEY, audit_chain_key=CHAIN_KEY)

    assert health.status_payload(settings)["audit_public_key"] is None


def test_status_publishes_exactly_when_the_export_route_signs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = status_settings(audit_signing_key=SIGNING_KEY)
    for chain_in_env in (False, True):
        if chain_in_env:
            monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
        export_signs = ChainPolicy.from_env().key is not None
        published = health.status_payload(settings)["audit_public_key"] is not None
        assert published is export_signs


def test_status_counts_the_chain_key_of_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The REST export reads the chain key from the process environment, so status follows it.
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    settings = status_settings(audit_signing_key=SIGNING_KEY)

    assert health.status_payload(settings)["audit_public_key"] == PUBLIC_TEXT


def test_status_ignores_an_unusable_chain_key_in_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(CHAIN_ENV, "too short")
    settings = status_settings(audit_signing_key=SIGNING_KEY)

    assert health.status_payload(settings)["audit_public_key"] is None


# --- doctor row -----------------------------------------------------------------------------


@pytest.mark.parametrize("environment", ["prod", "dev"])
def test_doctor_passes_with_both_keys_and_names_the_fingerprint(environment: str) -> None:
    settings = Settings(
        environment=environment, audit_chain_key=CHAIN_KEY, audit_signing_key=SIGNING_KEY
    )

    row = doctor_row(settings)

    assert row.status is Status.PASS
    assert FINGERPRINT in row.detail


@pytest.mark.parametrize("environment", ["prod", "dev"])
def test_doctor_row_never_prints_key_material(environment: str) -> None:
    settings = Settings(
        environment=environment, audit_chain_key=CHAIN_KEY, audit_signing_key=SIGNING_KEY
    )

    row = doctor_row(settings)

    for secret in (SIGNING_KEY, CHAIN_KEY, PUBLIC_TEXT):
        assert secret not in row.detail


@pytest.mark.parametrize("environment", ["prod", "dev"])
def test_doctor_warns_when_only_the_chain_key_is_set(environment: str) -> None:
    row = doctor_row(Settings(environment=environment, audit_chain_key=CHAIN_KEY))

    assert row.status is Status.WARN
    assert "HMAC-chained but unsigned" in row.detail
    assert SIGN_ENV in row.detail
    assert CHAIN_KEY not in row.detail


@pytest.mark.parametrize(
    ("environment", "expected"),
    [("prod", Status.FAIL), ("dev", Status.WARN), ("test", Status.WARN)],
)
def test_doctor_row_for_a_signing_key_alone_fails_only_where_the_start_refuses(
    environment: str, expected: Status
) -> None:
    row = doctor_row(Settings(environment=environment, audit_signing_key=SIGNING_KEY))

    assert row.status is expected
    assert row.detail == SIGNING_WITHOUT_CHAIN_KEY
    assert NEEDS_CHAIN in row.detail
    assert CHAIN_ENV in row.detail
    assert SIGN_ENV in row.detail
    assert SIGNING_KEY not in row.detail


@pytest.mark.parametrize("environment", ["prod", "dev"])
def test_doctor_warns_when_neither_key_is_set(environment: str) -> None:
    row = doctor_row(Settings(environment=environment))

    assert row.status is Status.WARN
    assert CHAIN_ENV in row.detail
    assert SIGN_ENV in row.detail


def test_prod_with_neither_key_only_warns_in_the_audit_keys_row() -> None:
    results = admin_doctor.evaluate(Settings(environment="prod"), None, "no daemon")
    keys = [r for r in results if r.name == ROW]

    assert [r.status for r in keys] == [Status.WARN]


def test_the_row_function_and_the_doctor_agree() -> None:
    settings = Settings(audit_chain_key=CHAIN_KEY, audit_signing_key=SIGNING_KEY)

    assert doctor_row(settings) == audit_keys_row(settings)


def test_the_row_is_listed_once_among_the_configuration_rows() -> None:
    results = admin_doctor.evaluate(Settings(environment="prod"), None, "no daemon")
    names = [r.name for r in results]

    assert names.count(ROW) == 1
    assert names.index("webhook secret") < names.index(ROW) < names.index("host capacity")


# --- doctor verdict, exit code and --json ---------------------------------------------------


def healthy_report() -> DockerCapabilities:
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


def doctor_settings(environment: str, **changes: Any) -> Settings:
    base = Settings(
        environment=environment,
        driver="docker",
        egress_acknowledged=True,
        webhook_secret_key=WEBHOOK_KEY,
        require_userns_remap=True,
        database_url="postgresql+asyncpg://sandfort:secret@db.internal/sandfort",
        host_capacity_cpu_millicores=4000,
        host_capacity_memory_mib=8192,
        audit_chain_key=CHAIN_KEY,
        audit_signing_key=SIGNING_KEY,
    )
    return replace(base, **changes)


def run_doctor(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, *, as_json: bool
) -> tuple[int, str]:
    async def fake_fetch(_settings: Settings) -> tuple[DockerCapabilities, list[str] | None]:
        return healthy_report(), None

    monkeypatch.setattr(admin_doctor, "fetch_host", fake_fetch)
    lines: list[str] = []
    code = admin_doctor.run_doctor(settings, as_json=as_json, echo=lines.append)
    return code, "\n".join(lines)


def audit_row_of(payload: dict[str, Any]) -> dict[str, str]:
    rows = [check for check in payload["checks"] if check["name"] == ROW]
    assert len(rows) == 1
    return rows[0]


def test_prod_baseline_with_both_keys_would_start(monkeypatch: pytest.MonkeyPatch) -> None:
    code, out = run_doctor(monkeypatch, doctor_settings("prod"), as_json=False)

    assert code == 0
    assert out.splitlines()[-1] == STARTS


def test_prod_signing_key_alone_makes_the_verdict_refuse_in_text_and_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = doctor_settings("prod", audit_chain_key="")

    code, out = run_doctor(monkeypatch, settings, as_json=False)

    assert code == 1
    assert out.splitlines()[-1] == REFUSES
    assert f"FAIL {ROW}: {SIGNING_WITHOUT_CHAIN_KEY}" in out


def test_prod_signing_key_alone_makes_the_json_verdict_refuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = doctor_settings("prod", audit_chain_key="")

    code, out = run_doctor(monkeypatch, settings, as_json=True)

    payload = json.loads(out)
    assert code == 1
    assert payload["verdict"] == REFUSES
    assert audit_row_of(payload) == {
        "name": ROW,
        "status": "FAIL",
        "detail": SIGNING_WITHOUT_CHAIN_KEY,
    }


@pytest.mark.parametrize("environment", ["dev", "test"])
def test_outside_prod_signing_key_alone_warns_and_the_json_verdict_still_starts(
    monkeypatch: pytest.MonkeyPatch, environment: str
) -> None:
    settings = doctor_settings(environment, audit_chain_key="")

    code, out = run_doctor(monkeypatch, settings, as_json=True)

    payload = json.loads(out)
    assert code == 0
    assert payload["verdict"] == STARTS
    assert audit_row_of(payload) == {
        "name": ROW,
        "status": "WARN",
        "detail": SIGNING_WITHOUT_CHAIN_KEY,
    }


@pytest.mark.parametrize("environment", ["dev", "test"])
def test_outside_prod_the_text_output_has_a_warn_row_and_exit_code_zero(
    monkeypatch: pytest.MonkeyPatch, environment: str
) -> None:
    settings = doctor_settings(environment, audit_chain_key="")

    code, out = run_doctor(monkeypatch, settings, as_json=False)

    assert code == 0
    assert f"WARN {ROW}: {SIGNING_WITHOUT_CHAIN_KEY}" in out
    assert "0 fail" in out


# --- branches of the row --------------------------------------------------------------------


@pytest.mark.parametrize("environment", ["prod", "dev"])
def test_doctor_fails_for_a_malformed_signing_key_without_printing_it(environment: str) -> None:
    settings = Settings(environment=environment, audit_chain_key=CHAIN_KEY)
    object.__setattr__(settings, "audit_signing_key", BAD_SIGNING_KEY)

    row = doctor_row(settings)

    assert row.status is Status.FAIL
    assert SIGN_ENV in row.detail
    assert BAD_SIGNING_KEY not in row.detail
    assert CHAIN_KEY not in row.detail


@pytest.mark.parametrize("environment", ["prod", "dev"])
@pytest.mark.parametrize("chain", [CHAIN_KEY, ""], ids=["chain-set", "chain-unset"])
def test_a_whitespace_only_signing_key_is_treated_as_unset(environment: str, chain: str) -> None:
    settings = Settings(environment=environment, audit_chain_key=chain, audit_signing_key=" \t ")

    row = doctor_row(settings)

    assert row.status is Status.WARN
    assert NEEDS_CHAIN not in row.detail
    assert settings.audit_signer() is None


def test_the_pass_detail_names_a_real_fingerprint() -> None:
    settings = Settings(audit_chain_key=CHAIN_KEY, audit_signing_key=SIGNING_KEY)

    detail = doctor_row(settings).detail

    assert detail.endswith(FINGERPRINT)
    assert "unknown" not in detail


# --- prod preflight for code-built settings -------------------------------------------------

PROD_READY = {
    "environment": "prod",
    "webhook_secret_key": WEBHOOK_KEY,
    "host_capacity_cpu_millicores": 4000,
    "host_capacity_memory_mib": 8192,
}


def test_code_built_prod_settings_with_a_signing_key_alone_fail_the_preflight() -> None:
    settings = Settings(**PROD_READY, audit_signing_key=SIGNING_KEY)

    assert prod_findings(settings) == [SIGNING_WITHOUT_CHAIN_KEY]
    with pytest.raises(ConfigurationError) as raised:
        check_preflight(settings)
    assert raised.value.findings == (SIGNING_WITHOUT_CHAIN_KEY,)
    assert SIGNING_KEY not in str(raised.value)


def test_replaced_prod_settings_with_a_blank_chain_key_fail_the_preflight() -> None:
    both = Settings(**PROD_READY, audit_chain_key=CHAIN_KEY, audit_signing_key=SIGNING_KEY)
    check_preflight(both)

    with pytest.raises(ConfigurationError, match=NEEDS_CHAIN):
        check_preflight(replace(both, audit_chain_key="   "))


def test_the_preflight_lists_the_signing_finding_next_to_the_others() -> None:
    settings = Settings(environment="prod", audit_signing_key=SIGNING_KEY)

    findings = prod_findings(settings)

    assert len(findings) == 3
    assert SIGNING_WITHOUT_CHAIN_KEY in findings


@pytest.mark.parametrize("changes", [{"audit_chain_key": CHAIN_KEY}, {}], ids=["chain", "none"])
def test_the_preflight_accepts_the_other_key_combinations(changes: dict[str, str]) -> None:
    check_preflight(Settings(**PROD_READY, **changes))


def test_the_preflight_ignores_a_whitespace_only_signing_key() -> None:
    check_preflight(Settings(**PROD_READY, audit_signing_key="   "))


@pytest.mark.parametrize("environment", ["dev", "test"])
def test_the_preflight_has_no_audit_finding_outside_prod(environment: str) -> None:
    settings = Settings(environment=environment, audit_signing_key=SIGNING_KEY)

    assert prod_findings(settings) == []


def test_doctor_fail_and_the_preflight_refusal_agree_for_code_built_settings() -> None:
    settings = Settings(**PROD_READY, audit_signing_key=SIGNING_KEY)

    assert doctor_row(settings).status is Status.FAIL
    assert prod_findings(settings)
    fixed = replace(settings, audit_chain_key=CHAIN_KEY)
    assert doctor_row(fixed).status is Status.PASS
    assert prod_findings(fixed) == []


# --- the server entry point -----------------------------------------------------------------


def test_the_entry_point_exits_2_without_a_traceback_for_prod_signing_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(ENV_NAME, "prod")
    monkeypatch.setenv("SANDFORT_WEBHOOK_SECRET_KEY", WEBHOOK_KEY)
    monkeypatch.setenv(SIGN_ENV, SIGNING_KEY)
    started: list[Any] = []
    monkeypatch.setattr(server_main.uvicorn, "run", lambda app, **kwargs: started.append(app))

    with pytest.raises(SystemExit) as raised:
        server_main.main([])

    err = capsys.readouterr().err
    assert raised.value.code == 2
    assert started == []
    assert err.startswith("error: ")
    assert NEEDS_CHAIN in err
    assert "Traceback" not in err
    assert SIGNING_KEY not in err
