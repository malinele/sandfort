"""r63: command ``stop_cause``, the full status, exec idempotency keys and list commands."""

import asyncio
import dataclasses
import json
import sys
from collections.abc import Callable
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, get_args

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import sandfort_sdk  # noqa: E402
from sandfort_cli import exec_cmd  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    COMMAND_STOP_CAUSE_SANDBOX_STOPPED,
    SANDBOX_STOP_CAUSE_REQUESTED,
    AsyncSandbox,
    CommandInfo,
    CommandStopCause,
    LogPage,
    Sandbox,
    SandboxInfo,
    StatusInfo,
    StopCause,
    is_known_command_stop_cause,
)
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402
from sandfort_sdk.exceptions import InvalidResponseError  # noqa: E402
from sandfort_sdk.models import ExecResult  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
TIMEOUT_S = 30.0
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
HEADER = "Idempotency-Key"
REPLAYED = "Idempotent-Replayed"
RUNNER = CliRunner()
CREATED = "2026-11-10T12:00:00Z"
EXEC_DATA = {
    "exit_code": 0,
    "stdout": "hi\n",
    "stderr": "",
    "timed_out": False,
    "truncated": False,
    "duration_ms": 3,
}
Handler = Callable[[httpx.Request], httpx.Response]


def envelope(data: Any, headers: dict[str, str] | None = None, status: int = 200) -> httpx.Response:
    body = {"success": True, "data": data, "error": None, "meta": None}
    return httpx.Response(status, json=body, headers=headers or {})


def sandbox_info() -> SandboxInfo:
    return SandboxInfo.from_payload(
        {
            "id": SID,
            "name": "demo",
            "state": "started",
            "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
            "network": {"block_all": False},
        }
    )


def sync_sandbox(handler: Handler, *, max_retries: int = 2) -> Sandbox:
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, max_retries=max_retries, sleep=lambda _: None)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return Sandbox(sandbox_info(), transport)


async def async_sandbox(handler: Handler) -> AsyncSandbox:
    async def no_sleep(_: float) -> None:
        return None

    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, max_retries=2, sleep=no_sleep)
    await transport._http.aclose()
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return AsyncSandbox(sandbox_info(), transport)


# --- 1. command stop_cause ----------------------------------------------------------------


def command_payload(**extra: Any) -> dict[str, Any]:
    return {"id": "cmd_1", "state": "killed", "created_at": CREATED, **extra}


def test_command_info_parses_stop_cause() -> None:
    info = CommandInfo.from_payload(command_payload(stop_cause="sandbox_stopped"))
    assert info.stop_cause == COMMAND_STOP_CAUSE_SANDBOX_STOPPED == "sandbox_stopped"


def test_command_info_stop_cause_defaults_to_none_and_keeps_unknown_values() -> None:
    assert CommandInfo.from_payload(command_payload()).stop_cause is None
    assert CommandInfo.from_payload(command_payload(stop_cause=None)).stop_cause is None
    future = CommandInfo.from_payload(command_payload(stop_cause="future_cause"))
    assert future.stop_cause == "future_cause"
    assert not is_known_command_stop_cause(future.stop_cause)


def test_command_info_rejects_a_non_string_stop_cause() -> None:
    with pytest.raises(InvalidResponseError):
        CommandInfo.from_payload(command_payload(stop_cause=3))


def test_log_page_parses_stop_cause() -> None:
    page = {"events": [], "next_offset": 0, "truncated": False, "complete": True}
    assert LogPage.from_payload(page).stop_cause is None
    stopped = LogPage.from_payload({**page, "stop_cause": "sandbox_stopped"})
    assert stopped.stop_cause == COMMAND_STOP_CAUSE_SANDBOX_STOPPED


def test_command_stop_cause_is_a_distinct_exported_type() -> None:
    assert get_args(CommandStopCause) == ("sandbox_stopped",)
    assert CommandStopCause != StopCause
    assert "sandbox_stopped" not in get_args(StopCause)
    assert SANDBOX_STOP_CAUSE_REQUESTED in get_args(StopCause)
    for name in ("CommandStopCause", "COMMAND_STOP_CAUSE_SANDBOX_STOPPED"):
        assert name in sandfort_sdk.__all__
    assert is_known_command_stop_cause("sandbox_stopped")
    assert not is_known_command_stop_cause("requested")
    assert not is_known_command_stop_cause(None)


def test_follow_exit_event_carries_stop_cause() -> None:
    from sandfort_sdk.process import SseFrame, log_event_from_frame

    frame = SseFrame(
        "exit",
        json.dumps({"exit_code": None, "state": "killed", "stop_cause": "sandbox_stopped"}),
        "7",
    )
    event = log_event_from_frame(frame)
    assert event is not None
    assert event.stop_cause == "sandbox_stopped"


# --- 2. status ----------------------------------------------------------------------------

STATUS = {
    "status": "ok",
    "version": "1.2.3",
    "build_sha": "abc123",
    "started_at": CREATED,
    "notice": None,
}


def test_status_info_parses_the_new_fields() -> None:
    info = StatusInfo.from_payload(
        {
            **STATUS,
            "image_sha": "abc123",
            "build_matches_image": True,
            "audit_public_key": "pubkey_b64",
            "audit_key_fingerprint": "fp:01",
        }
    )
    assert info.image_sha == "abc123"
    assert info.build_matches_image is True
    assert info.audit_public_key == "pubkey_b64"
    assert info.audit_key_fingerprint == "fp:01"
    assert info.started_at == datetime(2026, 11, 10, 12, 0, tzinfo=UTC)


def test_status_info_new_fields_are_none_when_absent_or_null() -> None:
    for payload in (STATUS, {**STATUS, "image_sha": None, "build_matches_image": None}):
        info = StatusInfo.from_payload(payload)
        assert info.image_sha is None
        assert info.build_matches_image is None
        assert info.audit_public_key is None
        assert info.audit_key_fingerprint is None


def test_status_info_build_matches_image_false_is_kept() -> None:
    info = StatusInfo.from_payload({**STATUS, "image_sha": "zzz", "build_matches_image": False})
    assert info.build_matches_image is False


def test_status_info_rejects_a_wrongly_typed_build_matches_image() -> None:
    with pytest.raises(InvalidResponseError):
        StatusInfo.from_payload({**STATUS, "build_matches_image": "yes"})


def test_client_status_reads_the_new_fields() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return envelope({**STATUS, "image_sha": "abc123", "build_matches_image": True})

    sandbox = sync_sandbox(handler)
    reply = sandbox._transport.request("GET", "/v1/status")
    assert StatusInfo.from_payload(reply.data).image_sha == "abc123"


# --- 3. exec idempotency ------------------------------------------------------------------


def test_exec_sends_the_idempotency_key_and_reports_a_replay() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return envelope(EXEC_DATA, {REPLAYED: "true"} if len(seen) > 1 else None)

    sandbox = sync_sandbox(handler)
    first = sandbox.process_exec(argv=["echo", "hi"], idempotency_key="job-1")
    again = sandbox.process.exec(argv=["echo", "hi"], idempotency_key="job-1")

    assert [r.headers[HEADER] for r in seen] == ["job-1", "job-1"]
    assert first.replayed is False
    assert again.replayed is True
    assert again.stdout == "hi\n"


def test_exec_without_a_key_sends_no_header_and_is_not_replayed() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return envelope(EXEC_DATA)

    result = sync_sandbox(handler).process_exec("echo hi")
    assert HEADER not in seen[0].headers
    assert result.replayed is False


def test_exec_with_a_key_is_resent_after_a_503_and_without_one_it_is_not() -> None:
    calls: list[int] = []

    def flaky(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            error = {"code": "UNAVAILABLE", "message": "try later"}
            return httpx.Response(503, json={"success": False, "data": None, "error": error})
        return envelope(EXEC_DATA)

    result = sync_sandbox(flaky).process_exec(argv=["true"], idempotency_key="k-retry")
    assert result.ok
    assert len(calls) == 2

    calls.clear()
    with pytest.raises(sandfort_sdk.ApiError):
        sync_sandbox(flaky).process_exec(argv=["true"])
    assert len(calls) == 1


@pytest.mark.parametrize(
    "key",
    ["", "x" * 256, "bad\nkey", "tab\tkey", "café", " lead", "trail ", "\x7f"],
)
def test_exec_rejects_an_invalid_key_before_any_request(key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request may be sent")

    with pytest.raises(ValueError, match="idempotency_key"):
        sync_sandbox(handler).process_exec(argv=["true"], idempotency_key=key)


@pytest.mark.parametrize("key", ["a", "x" * 255, "job 42/step-1:run#7", "~!"])
def test_exec_accepts_printable_ascii_keys_of_1_to_255(key: str) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return envelope(EXEC_DATA)

    sync_sandbox(handler).process_exec(argv=["true"], idempotency_key=key)
    assert seen[0].headers[HEADER] == key


def test_async_exec_sends_the_key_and_reports_a_replay() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return envelope(EXEC_DATA, {REPLAYED.lower(): "True"})

    async def scenario() -> ExecResult:
        sandbox = await async_sandbox(handler)
        try:
            with pytest.raises(ValueError, match="idempotency_key"):
                await sandbox.process_exec(argv=["true"], idempotency_key="")
            return await sandbox.process_exec(argv=["true"], idempotency_key="a-1")
        finally:
            await sandbox._transport.aclose()

    result = asyncio.run(scenario())
    assert seen[0].headers[HEADER] == "a-1"
    assert result.replayed is True


def test_exec_result_replayed_is_never_read_from_the_body() -> None:
    assert ExecResult.from_payload({**EXEC_DATA, "replayed": True}).replayed is False


# --- exec with a list command --------------------------------------------------------------


def test_exec_command_given_as_a_list_is_sent_as_argv() -> None:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return envelope(EXEC_DATA)

    sandbox = sync_sandbox(handler)
    sandbox.process_exec(["ls", "-l", "/tmp"])
    sandbox.process.exec(("echo", "a b"))
    assert bodies[0]["argv"] == ["ls", "-l", "/tmp"]
    assert "command" not in bodies[0]
    assert bodies[1]["argv"] == ["echo", "a b"]


def test_async_exec_command_given_as_a_list_is_sent_as_argv() -> None:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return envelope(EXEC_DATA)

    async def scenario() -> None:
        sandbox = await async_sandbox(handler)
        try:
            await sandbox.process_exec(["ls", "-l"])
        finally:
            await sandbox._transport.aclose()

    asyncio.run(scenario())
    assert bodies[0]["argv"] == ["ls", "-l"]


@pytest.mark.parametrize(
    ("command", "argv"),
    [([], None), (["ls"], ["ls"]), ([1, 2], None), ("ls", ["ls"]), (None, None)],
)
def test_exec_list_command_misuse_is_a_local_value_error(command: Any, argv: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request may be sent")

    with pytest.raises(ValueError):
        sync_sandbox(handler).process_exec(command, argv=argv)


def test_exec_string_command_is_still_sent_as_command() -> None:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return envelope(EXEC_DATA)

    sync_sandbox(handler).process_exec("echo hi")
    assert bodies[0] == {"command": "echo hi", "timeout_s": 60}


# --- CLI ----------------------------------------------------------------------------------


class FakeSandbox:
    def __init__(self, replayed: bool = False) -> None:
        self.calls: list[dict[str, Any]] = []
        self.replayed = replayed

    def process_exec(self, command: Any = None, **kwargs: Any) -> ExecResult:
        self.calls.append(kwargs)
        result = ExecResult.from_payload(EXEC_DATA, "req_1")
        return dataclasses.replace(result, replayed=self.replayed)


@pytest.fixture
def install(monkeypatch: pytest.MonkeyPatch) -> Callable[[FakeSandbox], FakeSandbox]:
    def apply(sandbox: FakeSandbox) -> FakeSandbox:
        @contextmanager
        def opened() -> Any:
            yield SimpleNamespace(get=lambda sandbox_id: sandbox)

        monkeypatch.setattr(exec_cmd, "open_client", opened)
        return sandbox

    return apply


def run(*args: str, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + list(args))


def test_cli_exec_passes_the_idempotency_key(install: Callable[..., FakeSandbox]) -> None:
    sandbox = install(FakeSandbox())

    result = run("exec", "--idempotency-key", "job-9", SID, "--", "echo", "hi")

    assert result.exit_code == 0, result.output
    assert sandbox.calls[0]["idempotency_key"] == "job-9"
    assert exec_cmd.REPLAYED_NOTE not in result.stderr


def test_cli_exec_without_the_option_passes_no_key(install: Callable[..., FakeSandbox]) -> None:
    sandbox = install(FakeSandbox())
    run("exec", SID, "--", "echo", "hi")
    assert sandbox.calls[0]["idempotency_key"] is None


def test_cli_exec_notes_a_replay_on_stderr_and_in_json(
    install: Callable[..., FakeSandbox],
) -> None:
    install(FakeSandbox(replayed=True))

    plain = run("exec", "--idempotency-key", "k", SID, "--", "echo", "hi")
    as_json = run("exec", "--idempotency-key", "k", SID, "--", "echo", "hi", as_json=True)

    assert exec_cmd.REPLAYED_NOTE in plain.stderr
    assert plain.stdout == "hi\n"
    assert json.loads(as_json.stdout)["replayed"] is True


@pytest.mark.parametrize("key", ["", "x" * 256, "bad\nkey", " lead"])
def test_cli_exec_rejects_an_invalid_key_as_a_usage_error(
    install: Callable[..., FakeSandbox], key: str
) -> None:
    sandbox = install(FakeSandbox())

    result = run("exec", "--idempotency-key", key, SID, "--", "echo", "hi")

    assert result.exit_code == 2
    assert "--idempotency-key" in result.output
    assert sandbox.calls == []
