"""GAP-06: ``sandfort-admin create-org --no-platform-admin`` issues a tenant-safe key.

A platform-admin key passes the platform check on ``PUT /v1/org/quota``, so a tenant handed one
could change its own quota. The default stays platform-admin; ``bootstrap`` is unchanged.
Sync tests: the admin CLI runs its own event loop.
"""

import asyncio
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from typer.testing import CliRunner, Result

from sandfort import admin_cli
from sandfort.api.app import create_app
from sandfort.config import Settings

ROOT = Path(__file__).resolve().parents[1]
PEPPER = "test-pepper"
KEY_PATTERN = re.compile(r"sf_live_[a-z0-9]{8}_[A-Za-z0-9_-]{43}")
QUOTA = "/v1/org/quota"
RUNNER = CliRunner()
CREATE_TENANT = ["create-org", "--org-name", "Tenant", "--org-slug", "tenant"]
CREATE_DEFAULT = ["create-org", "--org-name", "Default", "--org-slug", "default"]


@pytest.fixture
def db_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    path = tmp_path / "create-org.db"
    url = f"sqlite+aiosqlite:///{path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    monkeypatch.setenv("SANDFORT_DATABASE_URL", url)
    monkeypatch.setenv("SANDFORT_API_KEY_PEPPER", PEPPER)
    return path


def _rows(db_path: Path, sql: str, *params: Any) -> list[sqlite3.Row]:
    with closing(sqlite3.connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        return list(connection.execute(sql, params))


def _create_org(*args: str) -> Result:
    return RUNNER.invoke(admin_cli.app, list(args))


def _issued_key(result: Result) -> str:
    assert result.exit_code == 0, result.output
    [key] = KEY_PATTERN.findall(result.stdout)
    return key


def _is_platform_admin(db_path: Path, slug: str) -> int:
    [row] = _rows(
        db_path,
        "SELECT k.is_platform_admin FROM api_keys k "
        "JOIN organizations o ON o.id = k.org_id WHERE o.slug = ?",
        slug,
    )
    return int(row["is_platform_admin"])


def _put_quota(db_path: Path, key: str) -> httpx.Response:
    async def call() -> httpx.Response:
        settings = Settings(
            driver="fake", database_url=f"sqlite+aiosqlite:///{db_path}", api_key_pepper=PEPPER
        )
        app = create_app(settings)
        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
                return await http.put(
                    QUOTA, headers={"Authorization": f"Bearer {key}"}, json={"max_vcpus": 2}
                )
        finally:
            await app.state.engine.dispose()

    return asyncio.run(call())


def test_no_platform_admin_issues_a_non_platform_key_and_default_stays_platform(
    db_path: Path,
) -> None:
    _issued_key(_create_org(*CREATE_TENANT, "--no-platform-admin"))
    _issued_key(_create_org(*CREATE_DEFAULT))

    assert _is_platform_admin(db_path, "tenant") == 0
    assert _is_platform_admin(db_path, "default") == 1


def test_explicit_platform_admin_flag_matches_the_default(db_path: Path) -> None:
    _issued_key(_create_org(*CREATE_TENANT, "--platform-admin"))

    assert _is_platform_admin(db_path, "tenant") == 1


def test_put_quota_is_forbidden_for_the_no_platform_admin_key(db_path: Path) -> None:
    key = _issued_key(_create_org(*CREATE_TENANT, "--no-platform-admin"))

    response = _put_quota(db_path, key)

    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_put_quota_succeeds_for_the_default_create_org_key(db_path: Path) -> None:
    key = _issued_key(_create_org(*CREATE_DEFAULT))

    response = _put_quota(db_path, key)

    assert response.status_code == 200, response.text
    assert response.json()["data"]["limits"]["max_vcpus"] == 2
