"""Round 54: a sandbox row with an unreadable labels escape must not break label-filtered lists.

Rows written before the round-53 input guard can hold a lone UTF-16 surrogate (or NUL) as a
``\\u`` escape in the stored labels JSON. Postgres refuses to turn such an escape into text, so
the per-key extraction of a label filter aborted the whole query (500 for every labelled list
of the org). The repository wraps the extraction in a ``CASE`` keyed on a regex test of the raw
JSON text; ``sandfort-admin repair-labels`` rewrites the stored labels.

Daemon-free: a migrated SQLite file; poisoned rows are written below the API with ``sqlite3``.
Sync tests, as the admin CLI runs its own event loop.
"""

import asyncio
import json
import re
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import event, select
from sqlalchemy.dialects import postgresql, sqlite
from typer.testing import CliRunner

from sandfort import admin_cli
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.models.sandboxes import SandboxRow
from sandfort.db.repositories import sandboxes as sandboxes_module
from sandfort.db.repositories.sandboxes import (
    UNREADABLE_LABELS,
    SqlSandboxRepository,
    label_match,
)
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.ids import SANDBOX, new_id

ROOT = Path(__file__).resolve().parents[1]
PEPPER = "test-pepper"
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
BASE_MS = 1_700_000_000_000
RUNNER = CliRunner()
TEAM = {"team": "a"}
# Raw JSON text as an older server stored it: ``\ud800`` is a lone high surrogate escape.
POISONED_TEXT = '{"team": "a", "note": "x\\ud800y"}'
NUL_TEXT = '{"team": "a", "k\\u0000": "v"}'
EMOJI = "\U0001f600"  # stored as the valid pair \ud83d\ude00


def _sandbox_id(offset: int) -> str:
    return new_id(SANDBOX, now_ms=BASE_MS + offset)


@pytest.fixture
def db_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    path = tmp_path / "labels.db"
    url = f"sqlite+aiosqlite:///{path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    monkeypatch.setenv("SANDFORT_DATABASE_URL", url)
    monkeypatch.setenv("SANDFORT_API_KEY_PEPPER", PEPPER)
    return path


def _settings(db_path: Path) -> Settings:
    return Settings(
        driver="fake", database_url=f"sqlite+aiosqlite:///{db_path}", api_key_pepper=PEPPER
    )


def _rows(db_path: Path, sql: str, *params: Any) -> list[tuple[Any, ...]]:
    with closing(sqlite3.connect(db_path)) as connection:
        return list(connection.execute(sql, params))


def _write(db_path: Path, sql: str, *params: Any) -> None:
    with closing(sqlite3.connect(db_path)) as connection:
        connection.execute(sql, params)
        connection.commit()


def _new_org(db_path: Path, slug: str) -> str:
    """Create an org through the CLI plus a second key, so the org has an audit row."""
    result = RUNNER.invoke(admin_cli.app, ["create-org", "--org-name", slug, "--org-slug", slug])
    assert result.exit_code == 0, result.output
    key = RUNNER.invoke(admin_cli.app, ["create-key", "--org-slug", slug, "--name", "extra"])
    assert key.exit_code == 0, key.output
    [(org_id,)] = _rows(db_path, "SELECT id FROM organizations WHERE slug = ?", slug)
    return str(org_id)


def _seed(db_path: Path, org_id: str, labelled: Mapping[str, Mapping[str, str]]) -> None:
    async def run() -> None:
        engine = create_engine(_settings(db_path))
        try:
            async with create_session_factory(engine)() as session, session.begin():
                repo = SqlSandboxRepository(session)
                for sandbox_id, labels in labelled.items():
                    await repo.add(
                        Sandbox(
                            id=sandbox_id,
                            org_id=org_id,
                            name=f"name-{sandbox_id}",
                            state=SandboxState.STOPPED,
                            image_ref="alpine:3.20",
                            driver="fake",
                            labels=dict(labels),
                            created_at=NOW,
                            updated_at=NOW,
                        )
                    )
        finally:
            await engine.dispose()

    asyncio.run(run())


def _poison(db_path: Path, sandbox_id: str, raw: str = POISONED_TEXT) -> None:
    _write(db_path, "UPDATE sandboxes SET labels = ? WHERE id = ?", raw, sandbox_id)


def _query(
    db_path: Path, org_id: str, labels: Mapping[str, str]
) -> tuple[list[str], list[str], int]:
    """Ids from ``list`` and ``list_live`` (desc) and the ``count_in_scope`` result."""

    async def run() -> tuple[list[str], list[str], int]:
        engine = create_engine(_settings(db_path))
        try:
            async with create_session_factory(engine)() as session, session.begin():
                repo = SqlSandboxRepository(session)
                listed = await repo.list(org_id, labels=labels)
                live = await repo.list_live(org_id, labels=labels, order="desc")
                count = await repo.count_in_scope(org_id, labels)
        finally:
            await engine.dispose()
        return [s.id for s in listed], [s.id for s in live], count

    return asyncio.run(run())


@pytest.fixture
def org_with_poison(db_path: Path) -> tuple[str, list[str], str]:
    """An org with three clean ``team=a`` rows (one emoji, one backslash) and one poisoned row."""
    org_id = _new_org(db_path, "acme")
    clean = [_sandbox_id(0), _sandbox_id(2), _sandbox_id(3)]
    poisoned = _sandbox_id(1)
    _seed(
        db_path,
        org_id,
        {
            clean[0]: TEAM,
            poisoned: TEAM,
            clean[1]: {**TEAM, "mood": EMOJI},
            clean[2]: {**TEAM, "path": "C:\\ud800"},  # an escaped backslash, not an escape
        },
    )
    _poison(db_path, poisoned)
    return org_id, clean, poisoned


# --- the guard in the query ------------------------------------------------------------------


def test_poisoned_row_does_not_break_list_and_is_excluded(
    db_path: Path, org_with_poison: tuple[str, list[str], str]
) -> None:
    org_id, clean, poisoned = org_with_poison

    listed, live, count = _query(db_path, org_id, TEAM)

    assert listed == clean
    assert live == list(reversed(clean))
    assert count == len(clean)
    assert poisoned not in listed


def test_nul_escape_row_is_excluded_too(db_path: Path) -> None:
    org_id = _new_org(db_path, "acme")
    good, bad = _sandbox_id(0), _sandbox_id(1)
    _seed(db_path, org_id, {good: TEAM, bad: TEAM})
    _poison(db_path, bad, NUL_TEXT)

    listed, _, count = _query(db_path, org_id, TEAM)

    assert listed == [good]
    assert count == 1


def test_unfiltered_list_still_returns_the_poisoned_row(
    db_path: Path, org_with_poison: tuple[str, list[str], str]
) -> None:
    org_id, clean, poisoned = org_with_poison

    listed, _, _ = _query(db_path, org_id, {})

    assert sorted(listed) == sorted([*clean, poisoned])


def test_cursor_and_limit_semantics_unchanged(
    db_path: Path, org_with_poison: tuple[str, list[str], str]
) -> None:
    org_id, clean, _ = org_with_poison

    async def run() -> tuple[list[str], list[str]]:
        engine = create_engine(_settings(db_path))
        try:
            async with create_session_factory(engine)() as session, session.begin():
                repo = SqlSandboxRepository(session)
                first = await repo.list(org_id, labels=TEAM, limit=1)
                rest = await repo.list(org_id, labels=TEAM, cursor=first[0].id, limit=10)
        finally:
            await engine.dispose()
        return [s.id for s in first], [s.id for s in rest]

    first, rest = asyncio.run(run())

    assert first == clean[:1]
    assert rest == clean[1:]


def test_postgres_statement_carries_the_case_guard() -> None:
    stmt = select(SandboxRow.id).where(label_match({"team": "a", "env": "prod"}))

    compiled = str(stmt.compile(dialect=postgresql.dialect()))

    assert re.search(r"CASE WHEN \(?CAST\(sandboxes\.labels AS TEXT\) ~ ", compiled), compiled
    assert "THEN false ELSE" in compiled, compiled
    assert compiled.count("->>") == 2, compiled
    # Every extraction sits inside the CASE, after the guard.
    assert compiled.index("->>") > compiled.index("CASE WHEN"), compiled
    assert compiled.rindex("->>") < compiled.rindex("END"), compiled


def test_sqlite_statement_carries_the_case_guard() -> None:
    stmt = select(SandboxRow.id).where(label_match(TEAM))

    compiled = str(stmt.compile(dialect=sqlite.dialect()))

    assert "CASE WHEN" in compiled, compiled
    assert "REGEXP" in compiled, compiled


@pytest.mark.parametrize(
    ("labels", "unreadable"),
    [
        ({"a": "b"}, False),
        ({"a": EMOJI}, False),
        ({"a": "\u00e9\u0100\ud7ff\ue000\u0001"}, False),
        ({"a": "\\ud800"}, False),  # literal backslash text
        ({"a": "\\\\udc00"}, False),
        ({"a": "\ud800"}, True),
        ({"a": "\udc00"}, True),
        ({"\ud83d": "x"}, True),
        ({"a": "x\x00"}, True),
        ({"a": "\\\ud800"}, True),  # escaped backslash, then a real lone surrogate
        ({"a": "\ud800\ud800\udc00"}, True),  # a lone high before a valid pair
        ({"a": "\udc00\ud800"}, True),  # low then high is not a pair
    ],
)
def test_pattern_flags_only_unreadable_escapes(labels: dict[str, str], unreadable: bool) -> None:
    raw = json.dumps(labels)  # SQLAlchemy's default serializer: ASCII with \u escapes

    assert bool(re.search(UNREADABLE_LABELS, raw)) is unreadable


# --- repair-labels ---------------------------------------------------------------------------


def _audit_rows(db_path: Path) -> Sequence[tuple[Any, ...]]:
    return _rows(db_path, "SELECT * FROM audit_events ORDER BY id")


def _labels_text(db_path: Path, sandbox_id: str) -> str:
    [(raw,)] = _rows(db_path, "SELECT labels FROM sandboxes WHERE id = ?", sandbox_id)
    return str(raw)


def _version(db_path: Path, sandbox_id: str) -> int:
    [(version,)] = _rows(db_path, "SELECT version FROM sandboxes WHERE id = ?", sandbox_id)
    return int(version)


def test_repair_rewrites_poisoned_row_and_reports_count(
    db_path: Path, org_with_poison: tuple[str, list[str], str]
) -> None:
    org_id, clean, poisoned = org_with_poison
    audit_before = _audit_rows(db_path)
    clean_before = [_labels_text(db_path, sandbox_id) for sandbox_id in clean]

    result = RUNNER.invoke(admin_cli.app, ["repair-labels", "--org", org_id])

    assert result.exit_code == 0, result.output
    assert result.stdout.splitlines() == [poisoned, "repaired labels of 1 sandbox row(s)"]
    assert json.loads(_labels_text(db_path, poisoned)) == {"team": "a", "note": "x\ufffdy"}
    assert [_labels_text(db_path, sandbox_id) for sandbox_id in clean] == clean_before
    assert audit_before
    assert _audit_rows(db_path) == audit_before
    listed, _, count = _query(db_path, org_id, TEAM)
    assert sorted(listed) == sorted([*clean, poisoned])
    assert count == len(clean) + 1


def test_repair_dry_run_reports_without_writing(
    db_path: Path, org_with_poison: tuple[str, list[str], str]
) -> None:
    _, _, poisoned = org_with_poison
    audit_before = _audit_rows(db_path)
    version_before = _version(db_path, poisoned)

    result = RUNNER.invoke(admin_cli.app, ["repair-labels", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert result.stdout.splitlines() == [poisoned, "would repair labels of 1 sandbox row(s)"]
    assert _labels_text(db_path, poisoned) == POISONED_TEXT
    assert _version(db_path, poisoned) == version_before
    assert _audit_rows(db_path) == audit_before


def test_repair_all_orgs_covers_nul_keys_and_bumps_version(db_path: Path) -> None:
    acme = _new_org(db_path, "acme")
    other = _new_org(db_path, "other")
    first, second = _sandbox_id(0), _sandbox_id(1)
    _seed(db_path, acme, {first: TEAM})
    _seed(db_path, other, {second: TEAM})
    _poison(db_path, first)
    _poison(db_path, second, NUL_TEXT)
    audit_before = _audit_rows(db_path)
    version_before = _version(db_path, second)

    result = RUNNER.invoke(admin_cli.app, ["repair-labels"])

    assert result.exit_code == 0, result.output
    assert result.stdout.splitlines() == [first, second, "repaired labels of 2 sandbox row(s)"]
    assert json.loads(_labels_text(db_path, second)) == {"team": "a", "k\ufffd": "v"}
    assert _version(db_path, second) == version_before + 1
    assert _audit_rows(db_path) == audit_before
    again = RUNNER.invoke(admin_cli.app, ["repair-labels"])
    assert again.stdout.splitlines() == ["repaired labels of 0 sandbox row(s)"]


def test_repair_scoped_to_one_org_leaves_others(db_path: Path) -> None:
    acme = _new_org(db_path, "acme")
    other = _new_org(db_path, "other")
    mine, theirs = _sandbox_id(0), _sandbox_id(1)
    _seed(db_path, acme, {mine: TEAM})
    _seed(db_path, other, {theirs: TEAM})
    _poison(db_path, mine)
    _poison(db_path, theirs)

    result = RUNNER.invoke(admin_cli.app, ["repair-labels", "--org", acme])

    assert result.exit_code == 0, result.output
    assert result.stdout.splitlines() == [mine, "repaired labels of 1 sandbox row(s)"]
    assert _labels_text(db_path, theirs) == POISONED_TEXT


def test_repair_unknown_org_exits_1(db_path: Path) -> None:
    result = RUNNER.invoke(admin_cli.app, ["repair-labels", "--org", "org_missing"])

    assert result.exit_code == 1
    assert "not found" in result.output


def test_repaired_labels_keeps_colliding_keys() -> None:
    lone_key = "k" + chr(0xD800)

    fixed = admin_cli.repaired_labels({"k\ufffd": "1", lone_key: "2"})

    assert fixed == {"k\ufffd": "1", "k\ufffd\ufffd": "2"}
    assert admin_cli.repaired_labels({"a": EMOJI}) is None


def test_repaired_key_never_renames_a_later_genuine_key() -> None:
    fixed = admin_cli.repaired_labels({"k" + chr(0xD800): "repaired", "k\ufffd": "genuine"})

    assert fixed == {"k\ufffd\ufffd": "repaired", "k\ufffd": "genuine"}


class _Clock:
    """A hand-driven stand-in for the repository's monotonic clock."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    """A fresh diagnostic state and a controllable clock for the rate limit."""
    fake = _Clock()
    monkeypatch.setattr(sandboxes_module, "_monotonic", fake)
    monkeypatch.setattr(sandboxes_module, "_unreadable_checked_at", {})
    return fake


def _lists_with_counter(
    db_path: Path, org_id: str, runs: int, before_run: Callable[[int], None] | None = None
) -> int:
    """Run ``runs`` filtered lists; return how many COUNT statements (the diagnostic) executed."""
    counted: list[str] = []

    def record(_conn: Any, _cur: Any, statement: str, *_rest: Any) -> None:
        if "count(" in statement.lower():
            counted.append(statement)

    async def run() -> None:
        engine = create_engine(_settings(db_path))
        event.listen(engine.sync_engine, "before_cursor_execute", record)
        try:
            for index in range(runs):
                if before_run is not None:
                    before_run(index)
                async with create_session_factory(engine)() as session, session.begin():
                    await SqlSandboxRepository(session).list(org_id, labels=TEAM)
        finally:
            await engine.dispose()

    asyncio.run(run())
    return len(counted)


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]


def test_guard_exclusion_warns_once_with_org_count_and_repair_command(
    db_path: Path,
    org_with_poison: tuple[str, list[str], str],
    clock: _Clock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    org_id, _, _ = org_with_poison
    with caplog.at_level("WARNING", logger="sandfort.db.repositories.sandboxes"):
        _query(db_path, org_id, TEAM)  # list, list_live and count_in_scope in one interval

    [warning] = _warnings(caplog)
    assert f"1 row(s) of org {org_id}" in warning
    assert f"sandfort-admin repair-labels --org {org_id}" in warning


def test_two_consecutive_filtered_lists_run_the_diagnostic_once(
    db_path: Path, org_with_poison: tuple[str, list[str], str], clock: _Clock
) -> None:
    org_id, _, _ = org_with_poison

    assert _lists_with_counter(db_path, org_id, runs=2) == 1


def test_diagnostic_runs_again_after_the_interval_elapses(
    db_path: Path,
    org_with_poison: tuple[str, list[str], str],
    clock: _Clock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    org_id, _, _ = org_with_poison
    interval = sandboxes_module.UNREADABLE_CHECK_INTERVAL_S

    def advance(index: int) -> None:
        if index == 2:  # one second short of the interval: still no run
            clock.now += interval - 1
        if index == 3:  # now past it
            clock.now += 2

    with caplog.at_level("WARNING", logger="sandfort.db.repositories.sandboxes"):
        ran = _lists_with_counter(db_path, org_id, runs=4, before_run=advance)

    assert ran == 2  # the first list, then the first list after the interval
    assert len(_warnings(caplog)) == 2


def test_diagnostic_is_tracked_per_org(
    db_path: Path, org_with_poison: tuple[str, list[str], str], clock: _Clock
) -> None:
    org_id, _, _ = org_with_poison
    other = _new_org(db_path, "other")

    assert _lists_with_counter(db_path, org_id, runs=1) == 1
    assert _lists_with_counter(db_path, other, runs=1) == 1
    assert _lists_with_counter(db_path, org_id, runs=1) == 0


def test_unfiltered_list_never_runs_the_diagnostic(
    db_path: Path, org_with_poison: tuple[str, list[str], str], clock: _Clock
) -> None:
    org_id, _, _ = org_with_poison

    async def run() -> None:
        engine = create_engine(_settings(db_path))
        try:
            async with create_session_factory(engine)() as session, session.begin():
                await SqlSandboxRepository(session).list(org_id)
        finally:
            await engine.dispose()

    asyncio.run(run())

    assert sandboxes_module._unreadable_checked_at == {}
