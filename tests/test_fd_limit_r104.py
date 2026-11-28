"""Round 104: the server raises its soft open-file limit and warns when previews cannot fit."""

import logging
import resource
from typing import Any

import pytest

import sandfort.fd_limit as fd_limit
import sandfort.main as server_main
from sandfort.config import Settings
from sandfort.fd_limit import (
    DESCRIPTORS_PER_PREVIEW,
    MAX_SOFT_LIMIT,
    RESERVED_DESCRIPTORS,
    OpenFileLimit,
    preview_descriptor_need,
    raise_open_file_limit,
)

LOGGER = "sandfort.fd_limit"


class FakeLimits:
    """``getrlimit``/``setrlimit`` over one in-memory ``RLIMIT_NOFILE`` pair."""

    def __init__(self, soft: int, hard: int, *, refuse: BaseException | None = None) -> None:
        self.soft = soft
        self.hard = hard
        self.refuse = refuse
        self.calls: list[tuple[int, int]] = []

    def getrlimit(self, which: int) -> tuple[int, int]:
        assert which == resource.RLIMIT_NOFILE
        return (self.soft, self.hard)

    def setrlimit(self, which: int, limits: tuple[int, int]) -> None:
        assert which == resource.RLIMIT_NOFILE
        self.calls.append(limits)
        if self.refuse is not None:
            raise self.refuse
        self.soft, self.hard = limits


def _install(monkeypatch: pytest.MonkeyPatch, fake: FakeLimits) -> None:
    monkeypatch.setattr(fd_limit.resource, "getrlimit", fake.getrlimit)
    monkeypatch.setattr(fd_limit.resource, "setrlimit", fake.setrlimit)


def _warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.levelno == logging.WARNING]


# --- preview_descriptor_need ------------------------------------------------------------------


def test_the_documented_constants_hold() -> None:
    assert MAX_SOFT_LIMIT == 1048576  # CHANGELOG and docs/operations.md name this number
    assert RESERVED_DESCRIPTORS == 1024


def test_need_counts_two_descriptors_per_preview_plus_keepalive_and_reserve() -> None:
    assert DESCRIPTORS_PER_PREVIEW == 2
    assert preview_descriptor_need(4096, 768) == 2 * 4096 + 768 + RESERVED_DESCRIPTORS


def test_need_is_none_without_a_process_cap() -> None:
    assert preview_descriptor_need(0, 768) is None
    assert preview_descriptor_need(-1, 768) is None


def test_need_ignores_a_negative_keepalive() -> None:
    assert preview_descriptor_need(10, -5) == 20 + RESERVED_DESCRIPTORS


def test_default_caps_do_not_fit_dockers_default_soft_limit() -> None:
    defaults = Settings()
    need = preview_descriptor_need(
        defaults.preview_max_concurrent, defaults.preview_max_concurrent_per_sandbox
    )

    assert need is not None
    assert need > 1024  # the soft limit Docker gives a container
    assert need <= 524288  # the hard limit under Docker's systemd unit


# --- raise_open_file_limit --------------------------------------------------------------------


def test_soft_limit_is_raised_to_the_hard_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeLimits(1024, 524288)
    _install(monkeypatch, fake)

    result = raise_open_file_limit()

    assert fake.calls == [(524288, 524288)]
    assert result == OpenFileLimit(soft=524288, hard=524288, previous_soft=1024)


def test_an_unlimited_hard_limit_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeLimits(1024, resource.RLIM_INFINITY)
    _install(monkeypatch, fake)

    result = raise_open_file_limit()

    assert fake.calls == [(MAX_SOFT_LIMIT, resource.RLIM_INFINITY)]
    assert result.soft == MAX_SOFT_LIMIT


def test_a_hard_limit_above_the_cap_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeLimits(1024, MAX_SOFT_LIMIT * 4)
    _install(monkeypatch, fake)

    raise_open_file_limit()

    assert fake.calls == [(MAX_SOFT_LIMIT, MAX_SOFT_LIMIT * 4)]


def test_a_soft_limit_at_the_hard_limit_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeLimits(65536, 65536)
    _install(monkeypatch, fake)

    result = raise_open_file_limit()

    assert fake.calls == []
    assert result == OpenFileLimit(soft=65536, hard=65536, previous_soft=65536)


def test_a_soft_limit_above_the_cap_is_never_lowered(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeLimits(MAX_SOFT_LIMIT * 2, resource.RLIM_INFINITY)
    _install(monkeypatch, fake)

    raise_open_file_limit()

    assert fake.calls == []


@pytest.mark.parametrize("refusal", [ValueError("exceeds maximum"), OSError("not permitted")])
def test_a_refused_raise_keeps_the_limit_and_logs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, refusal: BaseException
) -> None:
    fake = FakeLimits(256, resource.RLIM_INFINITY, refuse=refusal)
    _install(monkeypatch, fake)

    with caplog.at_level(logging.INFO, logger=LOGGER):
        result = raise_open_file_limit()

    assert result == OpenFileLimit(soft=256, hard=resource.RLIM_INFINITY, previous_soft=256)
    assert any("kept at 256" in record.getMessage() for record in caplog.records)


def test_a_raise_is_logged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _install(monkeypatch, FakeLimits(1024, 524288))

    with caplog.at_level(logging.INFO, logger=LOGGER):
        raise_open_file_limit()

    assert any("raised from 1024 to 524288" in record.getMessage() for record in caplog.records)


def test_warns_when_the_limit_stays_below_the_need(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _install(monkeypatch, FakeLimits(1024, 4096))

    with caplog.at_level(logging.INFO, logger=LOGGER):
        raise_open_file_limit(10000)

    warnings = _warnings(caplog)
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "4096" in message and "10000" in message
    assert "SANDFORT_PREVIEW_MAX_CONCURRENT" in message


def test_no_warning_when_the_raised_limit_fits(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _install(monkeypatch, FakeLimits(1024, 524288))

    with caplog.at_level(logging.INFO, logger=LOGGER):
        raise_open_file_limit(10000)

    assert not _warnings(caplog)


def test_no_warning_exactly_at_the_need(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _install(monkeypatch, FakeLimits(10000, 10000))

    with caplog.at_level(logging.INFO, logger=LOGGER):
        raise_open_file_limit(10000)

    assert not _warnings(caplog)


def test_no_need_never_warns(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _install(monkeypatch, FakeLimits(64, 64))

    with caplog.at_level(logging.INFO, logger=LOGGER):
        raise_open_file_limit(None)

    assert not _warnings(caplog)


# --- sandfort-server calls it for every role --------------------------------------------------


def _record_raise(monkeypatch: pytest.MonkeyPatch) -> list[int | None]:
    needs: list[int | None] = []

    def record(need: int | None = None) -> OpenFileLimit:
        needs.append(need)
        return OpenFileLimit(soft=1, hard=1, previous_soft=1)

    monkeypatch.setattr(server_main, "raise_open_file_limit", record)
    return needs


def test_api_role_without_proxy_raises_with_no_preview_need(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    needs = _record_raise(monkeypatch)
    monkeypatch.setattr(server_main.uvicorn, "run", lambda app, **kwargs: None)
    monkeypatch.setattr(server_main, "create_app", lambda settings=None: object())
    monkeypatch.setenv("SANDFORT_ROLE", "api")
    monkeypatch.setenv("SANDFORT_PROXY_ENABLED", "false")

    server_main.main([])

    assert needs == [None]


def test_worker_role_raises_with_no_preview_need(monkeypatch: pytest.MonkeyPatch) -> None:
    needs = _record_raise(monkeypatch)
    monkeypatch.setattr(server_main.uvicorn, "run", lambda app, **kwargs: None)
    monkeypatch.setattr(server_main, "build_worker_app", lambda settings: object())
    monkeypatch.setenv("SANDFORT_ROLE", "worker")
    monkeypatch.setenv("SANDFORT_PROXY_ENABLED", "true")

    server_main.main([])

    assert needs == [None]


def test_api_with_proxy_raises_with_the_preview_need_before_serving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[Any] = []

    def record(need: int | None = None) -> OpenFileLimit:
        events.append(("raise", need))
        return OpenFileLimit(soft=1, hard=1, previous_soft=1)

    monkeypatch.setattr(server_main, "raise_open_file_limit", record)
    monkeypatch.setattr(server_main, "create_app", lambda settings=None: "app")
    monkeypatch.setattr(
        server_main, "_serve_with_proxy", lambda app, settings: events.append(("serve", app))
    )
    monkeypatch.setenv("SANDFORT_ROLE", "all")
    monkeypatch.setenv("SANDFORT_PROXY_ENABLED", "true")
    monkeypatch.setenv("SANDFORT_PREVIEW_MAX_CONCURRENT", "100")
    monkeypatch.setenv("SANDFORT_PREVIEW_MAX_CONCURRENT_PER_SANDBOX", "30")

    server_main.main([])

    assert events == [("raise", 2 * 100 + 30 + RESERVED_DESCRIPTORS), ("serve", "app")]


def test_proxy_without_a_per_sandbox_cap_counts_the_default_keepalive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    needs = _record_raise(monkeypatch)
    monkeypatch.setattr(server_main, "create_app", lambda settings=None: "app")
    monkeypatch.setattr(server_main, "_serve_with_proxy", lambda app, settings: None)
    monkeypatch.setenv("SANDFORT_ROLE", "api")
    monkeypatch.setenv("SANDFORT_PROXY_ENABLED", "true")
    monkeypatch.setenv("SANDFORT_PREVIEW_MAX_CONCURRENT", "100")
    monkeypatch.setenv("SANDFORT_PREVIEW_MAX_CONCURRENT_PER_SANDBOX", "0")

    server_main.main([])

    assert needs == [2 * 100 + server_main.MAX_KEEPALIVE + RESERVED_DESCRIPTORS]


def test_proxy_without_a_process_cap_has_no_need(monkeypatch: pytest.MonkeyPatch) -> None:
    needs = _record_raise(monkeypatch)
    monkeypatch.setattr(server_main, "create_app", lambda settings=None: "app")
    monkeypatch.setattr(server_main, "_serve_with_proxy", lambda app, settings: None)
    monkeypatch.setenv("SANDFORT_ROLE", "api")
    monkeypatch.setenv("SANDFORT_PROXY_ENABLED", "true")
    monkeypatch.setenv("SANDFORT_PREVIEW_MAX_CONCURRENT", "0")

    server_main.main([])

    assert needs == [None]
