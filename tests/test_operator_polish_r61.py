"""Round 61: self-host operator polish.

1. The host isolation gate refusal is rendered like the preflight: exit code 3, the findings and
   the override as plain lines on stderr, no traceback (the exception is logged at DEBUG only).
2. ``bootstrap`` prints the org id, the key id and the key prefix on stderr; stdout stays exactly
   the key and the key is never printed twice.
3. With the chain key set, a newest row that is unkeyed is always a ``hash_mismatch`` and
   ``audit-verify`` says "audit chain broken" (exit 3). There is no calm verdict: the rows alone
   cannot tell a key enabled after the last event from keyed rows deleted by a database writer,
   and the output never advises writing an event to clear the finding.
4. The refusal lines split findings on the one separator the gate joins them with.
5. ``create-org`` prints the org id, the key id and the key prefix on stderr like ``bootstrap``.
"""

import asyncio
import logging
import re
import sqlite3
from collections.abc import Sequence
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from typer.testing import CliRunner

import sandfort.main as server_main
from sandfort import admin_cli
from sandfort.api.app import IsolationUnavailableError, check_isolation, create_app
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.repositories.ports import ChainedAuditEvent
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType, AuditEvent
from sandfort.domain.org import Org
from sandfort.ids import new_org_id
from sandfort.services.audit import AuditRecorder
from sandfort.services.audit_chain import (
    ChainPolicy,
    ChainVerifier,
    FindingKind,
    keyed_link_hash,
    unkeyed_link_hash,
    verify_chain,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 9, 0, tzinfo=UTC)
KEY = Fernet.generate_key().decode()
AUDIT_CHAIN_KEY = "a-test-audit-chain-key-32-bytes!!"  # prod refuses to start without one
CAPACITY = {"host_capacity_cpu_millicores": 4000, "host_capacity_memory_mib": 8192}
HINT_TEXT = "SANDFORT_EGRESS_ACKNOWLEDGED=true turns egress probe findings into warnings"
FAKE_TRACEBACK = "Traceback (most recent call last):\n" + "  File x, line 1\n" * 130
RUNNER = CliRunner()

# --- 1. the isolation gate refusal ------------------------------------------------------


def prod(**changes: Any) -> Settings:
    return Settings(environment="prod", **changes)


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


async def real_refusal() -> IsolationUnavailableError:
    driver = GapsDriver(["gap one", "gap two"])
    with pytest.raises(IsolationUnavailableError) as raised:
        await check_isolation(driver, prod(), canary=ReachableRunner())
    return raised.value


def failing_app(error: BaseException) -> Any:
    """An ASGI app whose lifespan reports a startup failure with a traceback, then raises."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send({"type": "lifespan.startup.failed", "message": FAKE_TRACEBACK})
        raise error

    return app


async def drive_lifespan(app: Any) -> tuple[list[dict[str, Any]], BaseException | None]:
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "lifespan.startup"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    try:
        await app({"type": "lifespan"}, receive, send)
    except BaseException as error:
        return sent, error
    return sent, None


async def test_the_refusal_is_plain_lines_with_the_override_once(
    capsys: pytest.CaptureFixture[str],
) -> None:
    app = server_main.with_plain_refusal(failing_app(await real_refusal()))

    sent, raised = await drive_lifespan(app)

    lines = capsys.readouterr().err.splitlines()
    assert lines[0] == "error: host lacks required isolation capabilities"
    assert "error: gap one" in lines
    assert "error: gap two" in lines
    assert len(lines) == 6  # the reason, four findings, one override line
    assert [line for line in lines if line.startswith("override: ")] == [f"override: {HINT_TEXT}"]
    assert all(line.startswith(("error: ", "override: ")) for line in lines)
    assert not any("(SANDFORT_EGRESS" in line for line in lines)
    assert "Traceback" not in "\n".join(lines)
    assert raised is None
    assert [message["type"] for message in sent] == ["lifespan.startup.failed"]
    assert not sent[0].get("message")  # uvicorn logs nothing for an empty message


async def test_a_single_unprefixed_refusal_is_one_error_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    refusal = IsolationUnavailableError("driver FakeDriver cannot run in prod: no self-check")
    app = server_main.with_plain_refusal(failing_app(refusal))

    await drive_lifespan(app)

    assert capsys.readouterr().err.splitlines() == [
        "error: driver FakeDriver cannot run in prod: no self-check"
    ]


async def test_the_exception_is_logged_at_debug_only(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    app = server_main.with_plain_refusal(failing_app(await real_refusal()))

    with caplog.at_level(logging.DEBUG, logger="sandfort.main"):
        await drive_lifespan(app)

    records = [record for record in caplog.records if record.name == "sandfort.main"]
    assert [record.levelno for record in records] == [logging.DEBUG]
    assert records[0].exc_info is not None
    capsys.readouterr()


async def test_other_startup_failures_keep_their_message_and_propagate(
    capsys: pytest.CaptureFixture[str],
) -> None:
    app = server_main.with_plain_refusal(failing_app(RuntimeError("boom")))

    sent, raised = await drive_lifespan(app)

    assert isinstance(raised, RuntimeError)
    assert sent == [{"type": "lifespan.startup.failed", "message": FAKE_TRACEBACK}]
    assert capsys.readouterr().err == ""


async def test_non_lifespan_scopes_pass_through_untouched() -> None:
    seen: list[str] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    await server_main.with_plain_refusal(inner)({"type": "http"}, None, None)

    assert seen == ["http"]


def test_uvicorn_exits_3_with_plain_lines_for_a_refused_prod_start(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = prod(
        driver="fake",
        api_key_pepper="test-pepper",
        webhook_secret_key=KEY,
        audit_chain_key=AUDIT_CHAIN_KEY,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'gate.db'}",
        **CAPACITY,
    )
    app = server_main.with_plain_refusal(create_app(settings))
    config = uvicorn.Config(app, host="127.0.0.1", port=0, lifespan="on", log_config=None)

    with pytest.raises(SystemExit) as raised:
        uvicorn.Server(config).run()

    err = capsys.readouterr().err
    refused = [line for line in err.splitlines() if line.startswith("error: ")]
    assert raised.value.code == server_main.ISOLATION_EXIT_CODE
    assert any("cannot run in prod" in line for line in refused)
    assert "Traceback" not in err


def test_the_entry_point_hands_uvicorn_the_guarded_app(monkeypatch: pytest.MonkeyPatch) -> None:
    handed: list[Any] = []
    monkeypatch.setenv("SANDFORT_ENVIRONMENT", "dev")
    monkeypatch.setenv("SANDFORT_ROLE", "all")
    monkeypatch.delenv("SANDFORT_PROXY_ENABLED", raising=False)
    sentinel = object()
    monkeypatch.setattr(server_main, "build_app", lambda settings: sentinel)
    monkeypatch.setattr(server_main.uvicorn, "run", lambda app, **kwargs: handed.append(app))

    server_main.main([])

    assert len(handed) == 1
    assert handed[0] is not sentinel
    assert callable(handed[0])


def test_the_proxy_serving_path_hands_the_api_server_the_guarded_app(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    refusal = asyncio.run(real_refusal())
    servers: list[Any] = []

    async def capture(*started: Any) -> None:
        servers.extend(started)

    proxy_sentinel = object()
    monkeypatch.setenv("SANDFORT_ENVIRONMENT", "dev")
    monkeypatch.setenv("SANDFORT_ROLE", "all")
    monkeypatch.setenv("SANDFORT_PROXY_ENABLED", "true")
    monkeypatch.setattr(server_main, "build_app", lambda settings: failing_app(refusal))
    # configure_logging would bind a global handler to the captured (soon closed) stderr
    monkeypatch.setattr(server_main, "configure_logging", lambda level: None)
    monkeypatch.setattr(server_main, "_serve_together", capture)
    monkeypatch.setattr(server_main, "create_proxy_app", lambda s, *, api_app: proxy_sentinel)

    server_main.main([])

    assert len(servers) == 2
    api_app, proxy_app = servers[0].config.app, servers[1].config.app
    assert proxy_app is proxy_sentinel  # only the API server carries the refusal wrapper
    sent, raised = asyncio.run(drive_lifespan(api_app))
    lines = capsys.readouterr().err.splitlines()
    assert lines[0] == "error: host lacks required isolation capabilities"
    assert "error: gap one" in lines
    assert "Traceback" not in "\n".join(lines)
    assert raised is None
    assert not sent[0].get("message")


async def test_the_refusal_split_uses_the_separator_the_gate_joins_with() -> None:
    refusal = await real_refusal()
    reason = "host lacks required isolation capabilities"

    assert str(refusal).startswith(f"{reason}: ")
    findings = str(refusal).removeprefix(f"{reason}: ").split(server_main.FINDING_SEPARATOR)
    assert findings[:2] == ["gap one", "gap two"]
    assert len(findings) == 4  # two gaps and two probe findings, each exactly once
    assert len(server_main.refusal_lines(str(refusal))) == 6  # the same count as printed lines


# --- 2. bootstrap prints the identifiers on stderr --------------------------------------


@pytest.fixture
def db_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    path = tmp_path / "polish.db"
    url = f"sqlite+aiosqlite:///{path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    monkeypatch.setenv("SANDFORT_DATABASE_URL", url)
    monkeypatch.setenv("SANDFORT_API_KEY_PEPPER", "test-pepper")
    monkeypatch.delenv("SANDFORT_AUDIT_CHAIN_KEY", raising=False)
    return path


def test_bootstrap_stdout_is_exactly_the_key(db_path: Path) -> None:
    result = RUNNER.invoke(admin_cli.app, ["bootstrap", "--org-name", "Acme", "--org-slug", "acme"])

    assert result.exit_code == 0, result.output
    key = result.stdout.strip()
    assert re.fullmatch(r"sf_live_[a-z0-9]{8}_[A-Za-z0-9_-]{43}", key)
    assert result.stdout == key + "\n"


def test_bootstrap_stderr_names_the_org_the_key_id_and_the_prefix(db_path: Path) -> None:
    result = RUNNER.invoke(admin_cli.app, ["bootstrap", "--org-name", "Acme", "--org-slug", "acme"])

    assert result.exit_code == 0, result.output
    key = result.stdout.strip()
    with closing(sqlite3.connect(db_path)) as connection:
        [(org_id, key_id, prefix)] = connection.execute(
            "SELECT o.id, k.id, k.prefix FROM api_keys k JOIN organizations o ON o.id = k.org_id"
        ).fetchall()
    lines = result.stderr.splitlines()
    assert f"org id: {org_id}" in lines
    assert f"key id: {key_id}" in lines
    assert f"key prefix: {prefix}" in lines
    assert prefix in key
    assert key not in result.stderr  # the plaintext key is never printed twice
    assert "Store this key now; it cannot be shown again." in result.stderr
    assert all(len(line) <= 100 for line in lines)


def test_a_failed_bootstrap_prints_no_identifiers(db_path: Path) -> None:
    args = ["bootstrap", "--org-name", "Acme", "--org-slug", "acme"]
    assert RUNNER.invoke(admin_cli.app, args).exit_code == 0

    again = RUNNER.invoke(admin_cli.app, args)

    assert again.exit_code == 1
    assert again.stdout == ""
    assert "org id:" not in again.stderr
    assert "key id:" not in again.stderr


CREATE_BETA = ["create-org", "--org-name", "Beta", "--org-slug", "beta"]


def test_create_org_stdout_is_exactly_the_key(db_path: Path) -> None:
    result = RUNNER.invoke(admin_cli.app, CREATE_BETA)

    assert result.exit_code == 0, result.output
    key = result.stdout.strip()
    assert re.fullmatch(r"sf_live_[a-z0-9]{8}_[A-Za-z0-9_-]{43}", key)
    assert result.stdout == key + "\n"


def test_create_org_stderr_names_the_org_the_key_id_and_the_prefix(db_path: Path) -> None:
    result = RUNNER.invoke(admin_cli.app, CREATE_BETA)

    assert result.exit_code == 0, result.output
    key = result.stdout.strip()
    with closing(sqlite3.connect(db_path)) as connection:
        [(org_id, key_id, prefix)] = connection.execute(
            "SELECT o.id, k.id, k.prefix FROM api_keys k JOIN organizations o ON o.id = k.org_id"
        ).fetchall()
    lines = result.stderr.splitlines()
    assert f"org id: {org_id}" in lines
    assert f"key id: {key_id}" in lines
    assert f"key prefix: {prefix}" in lines
    assert key not in result.stderr
    assert "Store this key now; it cannot be shown again." in result.stderr
    assert all(len(line) <= 100 for line in lines)


def test_a_failed_create_org_prints_no_identifiers(db_path: Path) -> None:
    assert RUNNER.invoke(admin_cli.app, CREATE_BETA).exit_code == 0

    again = RUNNER.invoke(admin_cli.app, CREATE_BETA)

    assert again.exit_code == 1
    assert again.stdout == ""
    assert "org id:" not in again.stderr
    assert "key id:" not in again.stderr


# --- 3. audit-verify with an unkeyed newest row under a set chain key -------------------

UNKEYED_NEWEST_TEXT = (
    "newest row is unkeyed while the chain key is set: either the key was enabled after the "
    "last event, or keyed rows were deleted; the two cannot be told apart from the rows alone; "
    "compare against an earlier export with --head"
)
CHAIN_ENV = "SANDFORT_AUDIT_CHAIN_KEY"
CHAIN_KEY = "c" * 40
CHAIN_BYTES = b"k" * 32
ORG = "org_polish"


def make_event(index: int) -> AuditEvent:
    return AuditEvent(
        id=f"aud_{index:020d}",
        org_id=ORG,
        actor_type=ActorType.SYSTEM,
        action=f"test.step{index}",
        details={"n": index},
        occurred_at=NOW,
    )


def build_chain(keys: list[bytes | None]) -> list[ChainedAuditEvent]:
    rows: list[ChainedAuditEvent] = []
    prev: str | None = None
    for index, key in enumerate(keys):
        event = make_event(index)
        entry = unkeyed_link_hash(prev, event) if key is None else keyed_link_hash(key, prev, event)
        rows.append(ChainedAuditEvent(event=event, prev_hash=prev, entry_hash=entry))
        prev = entry
    return rows


def test_the_calm_finding_kind_is_gone() -> None:
    assert "no_keyed_row_yet" not in {kind.value for kind in FindingKind}
    assert not hasattr(FindingKind, "NO_KEYED_ROW_YET")


def test_an_unkeyed_newest_row_under_a_set_key_is_an_honest_hash_mismatch() -> None:
    rows = build_chain([None, None, None])

    findings = list(verify_chain(rows, ChainPolicy(key=CHAIN_BYTES)))

    assert [item.kind for item in findings] == [FindingKind.HASH_MISMATCH]
    assert findings[0].row_id == rows[-1].event.id
    assert findings[0].detail == UNKEYED_NEWEST_TEXT
    assert "hash_mismatch" in findings[0].render()
    assert "write one event" not in findings[0].render()
    assert "verify again" not in findings[0].render()


@pytest.mark.parametrize("keys", [[CHAIN_BYTES, None], [None, CHAIN_BYTES, CHAIN_BYTES, None]])
def test_an_unkeyed_newest_row_after_keyed_rows_stays_a_hash_mismatch(
    keys: list[bytes | None],
) -> None:
    rows = build_chain(keys)

    findings = list(verify_chain(rows, ChainPolicy(key=CHAIN_BYTES)))

    assert [(item.kind, item.row_id) for item in findings] == [
        (FindingKind.HASH_MISMATCH, rows[-1].event.id)
    ]


@pytest.mark.parametrize("bound", [None, 5])
def test_the_verifier_reports_it_in_both_modes_and_still_fails(bound: int | None) -> None:
    rows = build_chain([None, None])
    verifier = ChainVerifier(max_findings=bound, policy=ChainPolicy(key=CHAIN_BYTES))
    for row in rows:
        verifier.check(row)

    verdict = verifier.verdict()

    assert not verdict.ok
    assert [item.kind for item in verdict.findings] == [FindingKind.HASH_MISMATCH]
    assert verdict.findings[0].detail == UNKEYED_NEWEST_TEXT


def test_a_chain_ending_in_a_keyed_row_accepts_its_unkeyed_prefix() -> None:
    rows = build_chain([None, None, CHAIN_BYTES])

    assert list(verify_chain(rows, ChainPolicy(key=CHAIN_BYTES))) == []


async def record_events(
    url: str, count: int, org_id: str | None = None, slug: str = "school"
) -> str:
    """Append ``count`` audit rows (chained under the environment's key at this moment)."""
    engine = create_engine(Settings(database_url=url))
    try:
        factory = create_session_factory(engine)
        if org_id is None:
            org = Org(id=new_org_id(), name=slug.title(), slug=slug, created_at=NOW)
            async with UnitOfWork(factory) as uow:
                await uow.orgs.add(org)
                await uow.commit()
            org_id = org.id
        for index in range(count):
            async with UnitOfWork(factory) as uow:
                await AuditRecorder(FrozenClock(NOW)).record(
                    uow,
                    org_id=org_id,
                    actor_type=ActorType.SYSTEM,
                    actor_id=None,
                    action=f"test.step{index}",
                    target_type="thing",
                    target_id=f"thing-{index}",
                    details={"n": index},
                )
                await uow.commit()
    finally:
        await engine.dispose()
    return org_id


def verify() -> tuple[int, str]:
    result = RUNNER.invoke(admin_cli.app, ["audit-verify"])
    return result.exit_code, result.output


def delete_newest_rows(db_path: Path, count: int) -> None:
    """What a database writer can do: drop the newest ``count`` audit rows."""
    with closing(sqlite3.connect(db_path)) as connection:
        ids = [row[0] for row in connection.execute("SELECT id FROM audit_events ORDER BY id")]
        doomed = [(row_id,) for row_id in ids[-count:]]
        connection.executemany("DELETE FROM audit_events WHERE id = ?", doomed)
        connection.commit()


def test_cli_reports_an_unkeyed_newest_row_as_a_broken_chain(
    db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = f"sqlite+aiosqlite:///{db_path}"
    asyncio.run(record_events(url, 3))  # written before the key existed
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)

    code, output = verify()

    assert code == admin_cli.EXIT_CHAIN_MISMATCH
    assert "hash_mismatch" in output
    assert UNKEYED_NEWEST_TEXT in output
    assert "audit chain broken: 1 finding(s) in 3 rows" in output
    assert "no_keyed_row_yet" not in output
    assert "write one event" not in output
    assert "not fully verified" not in output


def test_deleting_every_keyed_row_after_the_key_was_enabled_still_fails(
    db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = f"sqlite+aiosqlite:///{db_path}"
    org_id = asyncio.run(record_events(url, 2))  # before the key
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    asyncio.run(record_events(url, 2, org_id))  # keyed rows
    assert verify()[0] == 0
    delete_newest_rows(db_path, 2)  # the writer removes every keyed row

    code, output = verify()

    assert code == admin_cli.EXIT_CHAIN_MISMATCH
    assert "hash_mismatch" in output
    assert "audit chain broken" in output
    assert "no_keyed_row_yet" not in output
    assert "write one event" not in output


def test_the_mixed_case_one_clean_org_and_one_broken_org_prints_broken(
    db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = f"sqlite+aiosqlite:///{db_path}"
    clean = asyncio.run(record_events(url, 1, slug="clean"))
    broken = asyncio.run(record_events(url, 2, slug="broken"))
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    asyncio.run(record_events(url, 1, clean))  # the clean org gets a keyed row

    code, output = verify()

    assert code == admin_cli.EXIT_CHAIN_MISMATCH
    assert f"{broken} " in output
    assert f"{clean} " not in output
    assert "audit chain broken: 1 finding(s) in 4 rows" in output
    assert "ok:" not in output


def test_cli_keeps_hash_mismatch_for_an_unkeyed_row_after_keyed_ones(
    db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = f"sqlite+aiosqlite:///{db_path}"
    org_id = asyncio.run(record_events(url, 1))
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    asyncio.run(record_events(url, 1, org_id))
    monkeypatch.delenv(CHAIN_ENV)
    asyncio.run(record_events(url, 1, org_id))  # unkeyed again
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)

    code, output = verify()

    assert code == admin_cli.EXIT_CHAIN_MISMATCH
    assert "hash_mismatch" in output
    assert "no_keyed_row_yet" not in output
    assert "audit chain broken" in output
