"""Every 409 CONFLICT answer carries a stable ``details.reason``."""

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sandfort.api.errors import error_response
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import Scope
from sandfort.drivers.docker.client import DISK_FULL_MESSAGE
from sandfort.drivers.errors import DriverConflict, DriverNotFound
from sandfort.errors import (
    CONCURRENT_UPDATE,
    CONFLICT_REASON,
    DISK_FULL,
    IN_USE,
    NAME_TAKEN,
    RUNTIME_CONFLICT,
    Conflict,
    InvalidState,
)
from test_api_sandboxes import BASE, add_org, migrated_app, seed_key, send

READ_WRITE = frozenset({Scope.SANDBOXES_READ, Scope.SANDBOXES_WRITE})


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    async with migrated_app(tmp_path) as application:
        yield application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


def mapped_error(exc: Exception) -> tuple[int, dict[str, Any]]:
    response = error_response(exc, request_id="req_test")
    error: dict[str, Any] = json.loads(bytes(response.body))["error"]
    return response.status_code, error


# --- the Conflict class -------------------------------------------------------------


def test_conflict_without_a_reason_gets_the_fallback_reason() -> None:
    error = Conflict("boom")

    assert error.reason == CONFLICT_REASON
    assert error.details == {"reason": "conflict"}


def test_conflict_reason_is_merged_with_the_other_details() -> None:
    error = Conflict("boom", reason=IN_USE, details={"sandbox_id": "sbx_1"})

    assert error.reason == "in_use"
    assert error.details == {"reason": "in_use", "sandbox_id": "sbx_1"}


def test_an_explicit_details_reason_is_kept() -> None:
    error = Conflict("boom", details={"reason": "custom"})

    assert error.reason == "custom"
    assert error.details == {"reason": "custom"}


def test_conflict_does_not_mutate_the_callers_details() -> None:
    details = {"path": "/x"}

    Conflict("boom", reason=IN_USE, details=details)

    assert details == {"path": "/x"}


def test_other_409_error_classes_keep_their_details() -> None:
    assert InvalidState("bad state").details == {}
    assert InvalidState("bad state", details={"state": "stopped"}).details == {
        "state": "stopped"
    }


# --- through the API ----------------------------------------------------------------


async def test_duplicate_sandbox_name_answers_name_taken(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    key = await seed_key(app, await add_org(app, "acme"), READ_WRITE)
    await send(client, "POST", BASE, key, status=201, json={"name": "dup"})

    body = await send(client, "POST", BASE, key, status=409, json={"name": "dup"})

    assert body["error"]["code"] == "CONFLICT"
    assert body["error"]["details"]["reason"] == NAME_TAKEN


async def test_stale_version_update_is_a_concurrent_update(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    org_id = await add_org(app, "acme")
    key = await seed_key(app, org_id, READ_WRITE)
    created = await send(client, "POST", BASE, key, status=201, json={"name": "v"})
    async with UnitOfWork(app.state.session_factory) as uow:
        sandbox = await uow.sandboxes.get(org_id, created["data"]["id"])
        assert sandbox is not None

        with pytest.raises(Conflict) as raised:
            await uow.sandboxes.update(
                org_id, sandbox, expected_version=sandbox.version + 1
            )

    assert raised.value.reason == CONCURRENT_UPDATE
    assert raised.value.details == {
        "reason": "concurrent_update",
        "expected_version": sandbox.version + 1,
    }
    status, error = mapped_error(raised.value)
    assert status == 409
    assert error["code"] == "CONFLICT"
    assert error["details"]["reason"] == CONCURRENT_UPDATE


# --- driver conflicts ---------------------------------------------------------------


def test_driver_disk_full_conflict_answers_disk_full() -> None:
    status, error = mapped_error(DriverConflict(DISK_FULL_MESSAGE, ref="sf-sbx_1"))

    assert status == 409
    assert error["code"] == "CONFLICT"
    assert error["message"] == DISK_FULL_MESSAGE
    assert error["details"] == {"reason": DISK_FULL}


def test_other_driver_conflict_answers_runtime_conflict() -> None:
    status, error = mapped_error(DriverConflict("container is already running"))

    assert status == 409
    assert error["code"] == "CONFLICT"
    assert error["details"] == {"reason": RUNTIME_CONFLICT}


def test_non_conflict_driver_errors_keep_empty_details() -> None:
    status, error = mapped_error(DriverNotFound("no such container"))

    assert status == 404
    assert error["details"] == {}
