"""Secrets pasted into a URL path never reach the append-only audit chain (review r63n)."""

import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from sqlalchemy import text

from sandfort.api.app import create_app
from sandfort.api.path_redaction import REDACTED, redact_path
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id
from sandfort.webhooks.signing import generate_secret

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SCOPES = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE, Scope.AUDIT_READ})


def test_api_key_in_a_segment_is_replaced_and_the_route_shape_kept() -> None:
    key = generate_api_key(PEPPER).key

    assert redact_path(f"/v1/sandboxes/sbx_{key}") == f"/v1/sandboxes/sbx_{REDACTED}"
    assert redact_path(f"/v1/sandboxes/{key}/toolbox/fs") == f"/v1/sandboxes/{REDACTED}/toolbox/fs"


@pytest.mark.parametrize("env", ["live", "test", "scim"])
def test_every_key_environment_prefix_is_covered(env: str) -> None:
    key = generate_api_key(PEPPER, env=env).key

    assert key not in redact_path(f"/v1/x/{key}")
    assert redact_path(f"/v1/x/{key}") == f"/v1/x/{REDACTED}"


def test_webhook_secret_is_replaced_even_when_its_base64_holds_slashes() -> None:
    secret = "whsec_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456/89+AbCdEfGh="

    assert redact_path(f"/v1/webhooks/{secret}") == f"/v1/webhooks/{REDACTED}"
    generated = generate_secret()
    assert redact_path(f"/v1/webhooks/{generated}/x").startswith(f"/v1/webhooks/{REDACTED}")
    assert generated.removeprefix("whsec_")[:12] not in redact_path(f"/v1/webhooks/{generated}")


def test_session_token_and_opaque_preview_token_are_replaced() -> None:
    session = "sfs_" + "A" * 20 + "." + "b" * 20
    preview = secrets.token_urlsafe(32)

    assert redact_path(f"/v1/a/{session}") == f"/v1/a/{REDACTED}"
    assert redact_path(f"/v1/sandboxes/{preview}/preview") == f"/v1/sandboxes/{REDACTED}/preview"


@pytest.mark.parametrize(
    "path",
    [
        "/v1/sandboxes",
        "/v1/sandboxes/sbx_0123456789ABCDEFGHJKMNPQR",
        "/v1/sandboxes/sbx_0123456789ABCDEFGHJKMNPQR/toolbox/fs/list",
        "/v1/images/" + "a" * 64,  # a hex digest is not a secret
        "/v1/sandboxes/sf_x_y",
    ],
)
def test_ordinary_paths_are_unchanged(path: str) -> None:
    assert redact_path(path) == path


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'redact.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(
        Settings(driver="fake", database_url=url, api_key_pepper=PEPPER, rate_limit_enabled=False)
    )
    try:
        yield application
    finally:
        await application.state.engine.dispose()


async def _seed(app: FastAPI) -> str:
    org = Org(id=new_org_id(), name="Acme", slug="acme", created_at=NOW)
    generated = generate_api_key(PEPPER)
    stored = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="ci",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(stored)
        await uow.commit()
    return generated.key


async def test_a_key_pasted_into_the_path_is_not_stored_in_the_audit_row(app: FastAPI) -> None:
    key = await _seed(app)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"Authorization": f"Bearer {key}"}
        denied = await client.get(f"/v1/sandboxes/sbx_{key}", headers=headers)
        listed = await client.get("/v1/audit-events", headers=headers, params={"limit": 100})

    assert denied.status_code in (404, 422), denied.text
    rows: list[dict[str, Any]] = listed.json()["data"]
    [row] = [r for r in rows if r["action"] == "request.denied"]
    assert row["details"]["path"] == f"/v1/sandboxes/sbx_{REDACTED}"
    async with app.state.engine.connect() as connection:
        stored = (await connection.execute(text("SELECT details FROM audit_events"))).all()
    assert key not in "".join(str(value) for value in stored)
    assert key.removeprefix("sf_") not in listed.text
