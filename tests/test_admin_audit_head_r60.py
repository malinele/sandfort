"""Admin ``audit-verify --head FILE --public-key KEY`` checks each head's Ed25519 signature (r60).

Through the admin CLI on a temp SQLite database: rows are recorded with the chain key set, the
operator ``audit-export`` writes the signed head, and ``audit-verify`` reads it back. A head
whose signature does not verify with ``--public-key`` (another key, a tampered signature, an
unsigned head) is a ``head_invalid`` finding and exits 3.
"""

import asyncio
import base64
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from typer.testing import CliRunner

from sandfort import admin_cli
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType
from sandfort.domain.org import Org
from sandfort.ids import new_org_id
from sandfort.services.audit import AuditRecorder

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 9, 0, tzinfo=UTC)
CHAIN_ENV = "SANDFORT_AUDIT_CHAIN_KEY"
SIGN_ENV = "SANDFORT_AUDIT_SIGNING_KEY"
CHAIN_KEY = "c" * 40
ROWS = 3
EXIT_MISMATCH = 3
EXIT_USAGE = 2
HEAD_INVALID = "head_invalid"
RUNNER = CliRunner()


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode()


def raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )


def public_text(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64(raw)


@asynccontextmanager
async def open_factory(url: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_engine(Settings(database_url=url))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


async def _seed(url: str) -> None:
    org = Org(id=new_org_id(), name="School", slug="school", created_at=NOW)
    recorder = AuditRecorder(FrozenClock(NOW))
    async with open_factory(url) as factory:
        async with UnitOfWork(factory) as uow:
            await uow.orgs.add(org)
            await uow.commit()
        for index in range(ROWS):
            async with UnitOfWork(factory) as uow:
                await recorder.record(
                    uow,
                    org_id=org.id,
                    actor_type=ActorType.SYSTEM,
                    actor_id=None,
                    action=f"test.step{index}",
                    target_type="thing",
                    target_id=f"thing-{index}",
                    details={"n": index},
                )
                await uow.commit()


@pytest.fixture
def signer(monkeypatch: pytest.MonkeyPatch) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(SIGN_ENV, b64(raw_private(key)))
    return key


@pytest.fixture
def database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'head.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    monkeypatch.setenv("SANDFORT_DATABASE_URL", url)
    monkeypatch.setenv(CHAIN_ENV, CHAIN_KEY)
    asyncio.run(_seed(url))
    return url


def export_to(path: Path) -> Path:
    result = RUNNER.invoke(admin_cli.app, ["audit-export", "--output", str(path)])
    assert result.exit_code == 0, result.output
    return path


def verify(*args: str) -> tuple[int, str]:
    result = RUNNER.invoke(admin_cli.app, ["audit-verify", *args])
    return result.exit_code, result.output


def head_of(path: Path) -> dict[str, object]:
    record: dict[str, object] = json.loads(path.read_text().splitlines()[-1])
    assert record["type"] == "audit_head"
    return record


def test_matching_public_key_verifies(
    database: str, signer: Ed25519PrivateKey, tmp_path: Path
) -> None:
    path = export_to(tmp_path / "audit.ndjson")
    assert head_of(path)["public_key"] == public_text(signer)

    code, output = verify("--head", str(path), "--public-key", public_text(signer))

    assert code == 0, output
    assert f"ok: {ROWS} audit rows verified" in output


def test_unpadded_public_key_is_accepted(
    database: str, signer: Ed25519PrivateKey, tmp_path: Path
) -> None:
    path = export_to(tmp_path / "audit.ndjson")

    code, output = verify("--head", str(path), "--public-key", public_text(signer).rstrip("="))

    assert code == 0, output


def test_mismatching_public_key_is_a_finding(
    database: str, signer: Ed25519PrivateKey, tmp_path: Path
) -> None:
    path = export_to(tmp_path / "audit.ndjson")
    other = public_text(Ed25519PrivateKey.generate())

    code, output = verify("--head", str(path), "--public-key", other)

    assert code == EXIT_MISMATCH, output
    assert HEAD_INVALID in output
    assert "audit chain broken: 1 finding(s)" in output


def test_tampered_signature_is_a_finding_only_with_the_public_key(
    database: str, signer: Ed25519PrivateKey, tmp_path: Path
) -> None:
    path = export_to(tmp_path / "audit.ndjson")
    *rows, trailer = path.read_text().splitlines()
    record = json.loads(trailer)
    record["signature"] = b64(bytes(64))
    tampered = json.dumps(record, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join([*rows, tampered]) + "\n")

    without_key, output = verify("--head", str(path))
    assert without_key == 0, output

    code, output = verify("--head", str(path), "--public-key", public_text(signer))

    assert code == EXIT_MISMATCH, output
    assert HEAD_INVALID in output


def test_unsigned_head_with_a_public_key_is_a_finding(
    database: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(SIGN_ENV, raising=False)
    path = export_to(tmp_path / "audit.ndjson")
    assert "signature" not in head_of(path)

    code, output = verify(
        "--head", str(path), "--public-key", public_text(Ed25519PrivateKey.generate())
    )

    assert code == EXIT_MISMATCH, output
    assert HEAD_INVALID in output
    assert "not signed" in output


def test_public_key_without_head_is_a_usage_error(
    database: str, signer: Ed25519PrivateKey
) -> None:
    code, output = verify("--public-key", public_text(signer))

    assert code == EXIT_USAGE, output
    assert "--head" in output


def test_malformed_public_key_is_a_usage_error(
    database: str, signer: Ed25519PrivateKey, tmp_path: Path
) -> None:
    path = export_to(tmp_path / "audit.ndjson")

    code, output = verify("--head", str(path), "--public-key", "not-a-key")

    assert code == EXIT_USAGE, output
    assert "Traceback" not in output
