"""Round 59: the prod start preflight reports every configuration blocker in one run.

Before, a prod start on an unprepared host failed in three steps (the fernet key in
``Settings.from_env``, host capacity in the lifespan, then the isolation gate), each as a
traceback. The configuration findings now surface together and the entry point prints them as
``error:`` lines with exit code 2.
"""

import logging
import shlex
import subprocess
import sys
from collections.abc import Sequence
from typing import Any

import pytest
from cryptography.fernet import Fernet

import sandfort.main as server_main
from sandfort.api.app import (
    EGRESS_OVERRIDE_HINT,
    IsolationUnavailableError,
    check_host_capacity,
    check_isolation,
    check_prod_configuration,
    create_app,
    create_worker_app,
    egress_gaps,
)
from sandfort.config import Settings
from sandfort.preflight import (
    FERNET_KEY_COMMAND,
    UNGUARDED_HOST_MESSAGE,
    ConfigurationError,
    check_preflight,
    prod_findings,
)

KEY = Fernet.generate_key().decode()
CAPACITY = {"host_capacity_cpu_millicores": 4000, "host_capacity_memory_mib": 8192}
OVERRIDE = "SANDFORT_EGRESS_ACKNOWLEDGED=true"
METADATA = "169.254.169.254:80"
SERVABLE = {"driver": "fake", "api_key_pepper": "test-pepper", "allow_unbounded_host": True}


def prod(**changes: Any) -> Settings:
    return Settings(environment="prod", **changes)


# --- the findings -----------------------------------------------------------------------


def test_both_configuration_findings_are_returned_together() -> None:
    findings = prod_findings(prod())

    assert len(findings) == 2
    assert "SANDFORT_WEBHOOK_SECRET_KEY" in findings[0]
    assert findings[1] == UNGUARDED_HOST_MESSAGE
    assert all("\n" not in finding for finding in findings)


def test_there_are_no_findings_outside_prod() -> None:
    assert prod_findings(Settings(environment="dev")) == []
    check_preflight(Settings(environment="dev"))  # does not raise


def test_there_are_no_findings_with_the_key_set_and_capacity_configured() -> None:
    settings = prod(webhook_secret_key=KEY, **CAPACITY)

    assert prod_findings(settings) == []
    check_preflight(settings)  # does not raise


def test_a_blank_key_is_still_missing() -> None:
    [finding] = prod_findings(prod(webhook_secret_key="  ", **CAPACITY))

    assert "SANDFORT_WEBHOOK_SECRET_KEY" in finding


def test_allow_unbounded_host_suppresses_only_the_capacity_finding() -> None:
    [finding] = prod_findings(prod(allow_unbounded_host=True))

    assert "SANDFORT_WEBHOOK_SECRET_KEY" in finding
    assert prod_findings(prod(allow_unbounded_host=True, webhook_secret_key=KEY)) == []


def test_the_capacity_finding_alone_when_only_the_cpu_is_set() -> None:
    settings = prod(webhook_secret_key=KEY, host_capacity_cpu_millicores=4000)

    assert prod_findings(settings) == [UNGUARDED_HOST_MESSAGE]


def test_the_webhook_finding_gives_a_command_that_generates_a_fernet_key() -> None:
    [finding, _] = prod_findings(prod())

    assert "urlsafe base64 fernet key" in finding
    assert FERNET_KEY_COMMAND in finding
    assert "Fernet.generate_key().decode()" in FERNET_KEY_COMMAND
    command = shlex.split(FERNET_KEY_COMMAND)
    command[0] = sys.executable
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=60)
    Fernet(result.stdout.strip().encode())  # a valid key: does not raise


def test_the_error_carries_every_finding_one_line_each() -> None:
    with pytest.raises(ConfigurationError) as raised:
        check_preflight(prod())

    assert isinstance(raised.value, ValueError)
    assert raised.value.findings == tuple(prod_findings(prod()))
    assert str(raised.value).splitlines() == list(raised.value.findings)


# --- Settings.from_env ------------------------------------------------------------------


def test_from_env_in_prod_without_the_key_no_longer_raises() -> None:
    settings = Settings.from_env({"SANDFORT_ENVIRONMENT": "prod"})

    assert settings.webhook_secret_key == ""
    with pytest.raises(ConfigurationError) as raised:
        check_preflight(settings)
    assert len(raised.value.findings) == 2


def test_from_env_still_validates_the_format_of_a_set_key() -> None:
    with pytest.raises(ValueError, match="SANDFORT_WEBHOOK_SECRET_KEY must be a urlsafe"):
        Settings.from_env({"SANDFORT_ENVIRONMENT": "prod", "SANDFORT_WEBHOOK_SECRET_KEY": "x"})


# --- the host capacity gate -------------------------------------------------------------


def test_check_host_capacity_raises_the_isolation_error_with_the_same_text() -> None:
    with pytest.raises(IsolationUnavailableError) as raised:
        check_host_capacity(prod())
    assert str(raised.value) == UNGUARDED_HOST_MESSAGE
    check_host_capacity(prod(**CAPACITY))  # does not raise


# --- the entry points -------------------------------------------------------------------

CLEARED = (
    "SANDFORT_WEBHOOK_SECRET_KEY",
    "SANDFORT_HOST_CAPACITY_CPU_MILLICORES",
    "SANDFORT_HOST_CAPACITY_MEMORY_MIB",
    "SANDFORT_ALLOW_UNBOUNDED_HOST",
    "SANDFORT_ROLE",
    "SANDFORT_PROXY_ENABLED",
)


def unprepared_host(monkeypatch: pytest.MonkeyPatch, environment: str = "prod") -> list[Any]:
    for name in CLEARED:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SANDFORT_ENVIRONMENT", environment)
    started: list[Any] = []
    monkeypatch.setattr(server_main.uvicorn, "run", lambda app, **kwargs: started.append(app))
    monkeypatch.setattr(server_main, "build_app", lambda settings: started.append(settings))
    return started


def test_the_entry_point_prints_every_finding_and_exits_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    started = unprepared_host(monkeypatch)

    with pytest.raises(SystemExit) as raised:
        server_main.main([])

    lines = capsys.readouterr().err.splitlines()
    assert raised.value.code == 2
    assert started == []
    assert len(lines) == 2
    assert all(line.startswith("error: ") for line in lines)
    assert "SANDFORT_WEBHOOK_SECRET_KEY" in lines[0]
    assert "host capacity" in lines[1]
    assert not any("Traceback" in line for line in lines)


def test_the_entry_point_reports_a_settings_error_the_same_way(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    started = unprepared_host(monkeypatch, environment="staging")

    with pytest.raises(SystemExit) as raised:
        server_main.main([])

    lines = capsys.readouterr().err.splitlines()
    assert raised.value.code == 2
    assert started == []
    assert len(lines) == 1
    assert lines[0].startswith("error: ")
    assert "SANDFORT_ENVIRONMENT" in lines[0]


def test_the_entry_point_starts_a_prepared_prod_host(monkeypatch: pytest.MonkeyPatch) -> None:
    started = unprepared_host(monkeypatch)
    monkeypatch.setenv("SANDFORT_WEBHOOK_SECRET_KEY", KEY)
    monkeypatch.setenv("SANDFORT_ALLOW_UNBOUNDED_HOST", "true")

    server_main.main([])

    assert len(started) == 2  # the application was built, then handed to uvicorn


def test_create_app_runs_the_preflight_before_wiring(monkeypatch: pytest.MonkeyPatch) -> None:
    started = unprepared_host(monkeypatch)

    with pytest.raises(ConfigurationError) as raised:
        server_main.create_app(prod())

    assert len(raised.value.findings) == 2
    assert started == []  # nothing was wired


def test_create_app_reads_the_environment_when_given_no_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unprepared_host(monkeypatch)

    with pytest.raises(ConfigurationError):
        server_main.create_app()


# --- the isolation gate reports every finding -------------------------------------------


class GapsDriver:
    def __init__(self, gaps: Sequence[str] = ()) -> None:
        self.gaps = list(gaps)

    async def isolation_gaps(self) -> list[str]:
        return list(self.gaps)


class ReachableRunner:
    """A canary runner for which every probed target connects."""

    async def prune(self) -> None:
        return None

    async def gateway(self, network: str) -> str:
        return "172.20.0.1"

    async def reachable(self, network: str, image: str, targets: Sequence[str]) -> frozenset[str]:
        return frozenset(targets)


async def test_the_gate_message_names_the_egress_override_for_probe_findings() -> None:
    with pytest.raises(IsolationUnavailableError) as raised:
        await check_isolation(GapsDriver(), prod(), canary=ReachableRunner())

    assert "egress probe" in str(raised.value)
    assert OVERRIDE in str(raised.value)


async def test_the_refusal_lists_every_finding_and_logs_one_summary_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    driver = GapsDriver(["gap one", "gap two"])

    with (
        caplog.at_level(logging.ERROR, logger="sandfort.api.app"),
        pytest.raises(IsolationUnavailableError) as raised,
    ):
        await check_isolation(driver, prod(), canary=ReachableRunner())

    message = str(raised.value)
    assert "gap one" in message
    assert "gap two" in message
    assert message.count(METADATA) == 2  # the probe finding of each managed network
    logged = [record.getMessage() for record in caplog.records if record.levelno == logging.ERROR]
    assert len(logged) == 1  # one summary line, the findings are not repeated in the log
    assert "4 finding(s)" in logged[0]
    assert "gap one" not in logged[0]


async def test_the_override_hint_is_appended_to_probe_findings_only_in_prod() -> None:
    dev = Settings(environment="dev", egress_probe=True)

    dev_gaps = await egress_gaps(GapsDriver(), dev, ReachableRunner())
    assert dev_gaps
    assert not any(OVERRIDE in gap for gap in dev_gaps)
    prod_gaps = await egress_gaps(GapsDriver(), prod(), ReachableRunner())
    assert prod_gaps
    assert all(gap.endswith(EGRESS_OVERRIDE_HINT) for gap in prod_gaps)


async def test_the_no_probe_acknowledgement_finding_carries_the_same_hint_in_prod() -> None:
    gaps = await egress_gaps(object(), prod(egress_probe=False))

    assert len(gaps) == 1
    assert gaps[0].endswith(EGRESS_OVERRIDE_HINT)
    assert await egress_gaps(object(), Settings(environment="dev", egress_probe=False)) == []


# --- the serve lifespan covers every entry point ----------------------------------------


def test_check_prod_configuration_lists_every_finding_in_the_isolation_error() -> None:
    with pytest.raises(IsolationUnavailableError) as raised:
        check_prod_configuration(prod())

    message = str(raised.value)
    assert "SANDFORT_WEBHOOK_SECRET_KEY" in message
    assert UNGUARDED_HOST_MESSAGE in message
    check_prod_configuration(prod(webhook_secret_key=KEY, **CAPACITY))  # does not raise
    check_prod_configuration(Settings(environment="dev"))  # does not raise


async def test_a_directly_built_prod_app_refuses_to_serve_without_the_key() -> None:
    application = create_app(prod(**SERVABLE))

    with pytest.raises(IsolationUnavailableError, match="SANDFORT_WEBHOOK_SECRET_KEY"):
        async with application.router.lifespan_context(application):
            pass


async def test_a_directly_built_worker_app_refuses_to_serve_without_the_key() -> None:
    application = create_worker_app(prod(**SERVABLE))

    with pytest.raises(IsolationUnavailableError, match="SANDFORT_WEBHOOK_SECRET_KEY"):
        async with application.router.lifespan_context(application):
            pass


async def test_a_passing_gate_logs_no_error(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR, logger="sandfort.api.app"):
        await check_isolation(GapsDriver(), Settings(environment="dev"))

    assert caplog.records == []
