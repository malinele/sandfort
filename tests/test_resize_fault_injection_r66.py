"""r66d: recovery after a mid-replace crash, and the controlled fault hook that exercises it.

The design partner's agreed fault-injection test of the resize replace path: an injected failure
answers 500 INTERNAL, the data stays intact, and a start succeeds once the fault is removed.
``fault_injection`` is a test hook (``SANDFORT_FAULT_INJECTION``); it is never for production and
shows in the public ``/v1/status`` notice and as a ``doctor`` FAIL.
"""

import logging
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sandfort import admin_doctor
from sandfort.admin_doctor import Status
from sandfort.config import (
    FAULT_RESIZE_COMMIT_FAIL,
    FAULT_RESIZE_CREATE_FAIL,
    Settings,
)
from sandfort.drivers.errors import DriverError
from sandfort.drivers.fake import FakeDriver
from test_resize import (
    GROWN_CPU,
    SANDBOXES,
    auth,
    key_for_new_org,
    make_app,
    resize,
    serve,
)
from test_resize_keeps_files_r66 import (
    CONTENT,
    PATH,
    read_file,
    sandbox_with_file,
    temp_image,
)

STATUS = "/v1/status"


def clear_faults(app: FastAPI) -> None:
    """What removing the environment variable and restarting does: no fault in any reader."""
    cleared = replace(app.state.settings, fault_injection=())
    app.state.settings = cleared
    app.state.sandbox_service._settings = cleared


@pytest.fixture
async def app_commit(tmp_path: Path) -> FastAPI:
    return make_app(tmp_path, fault_injection=(FAULT_RESIZE_COMMIT_FAIL,))


@pytest.fixture
async def app_create(tmp_path: Path) -> FastAPI:
    return make_app(tmp_path, fault_injection=(FAULT_RESIZE_CREATE_FAIL,))


async def prepared(app: FastAPI, http: httpx.AsyncClient) -> tuple[str, str, FakeDriver, str]:
    """A stopped sandbox holding PATH, resized: the next start replaces its container."""
    driver = app.state.driver
    assert isinstance(driver, FakeDriver)
    key = await key_for_new_org(app, "acme")
    sandbox_id = await sandbox_with_file(http, driver, key)
    [old] = await driver.list_managed()
    resized = await resize(http, key, sandbox_id, cpu_millicores=GROWN_CPU)
    assert resized.status_code == 200, resized.text
    return key, sandbox_id, driver, old.ref


async def test_commit_fault_is_500_internal_with_the_old_container_and_files_intact(
    app_commit: FastAPI,
) -> None:
    async with serve(app_commit) as http:
        key, sandbox_id, driver, old_ref = await prepared(app_commit, http)

        started = await http.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

        assert started.status_code == 500, started.text
        assert started.json()["error"]["code"] == "INTERNAL"
        [still] = await driver.list_managed()
        assert still.ref == old_ref
        await driver.start(still.ref)  # the fake reads archives of running containers only
        assert await read_file(driver, still.ref, PATH) == CONTENT
        await driver.stop(still.ref)
        assert not await driver.image_exists(temp_image(sandbox_id))  # raised instead of the commit

        clear_faults(app_commit)
        retried = await http.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

        assert retried.status_code == 200, retried.text
        [info] = await driver.list_managed()
        assert info.resources.cpu_millicores == GROWN_CPU
        assert await read_file(driver, info.ref, PATH) == CONTENT


async def test_create_fault_is_500_keeps_the_temp_image_and_the_retry_recovers_from_it(
    app_create: FastAPI, caplog: pytest.LogCaptureFixture
) -> None:
    async with serve(app_create) as http:
        key, sandbox_id, driver, _ = await prepared(app_create, http)

        with caplog.at_level(logging.WARNING):
            started = await http.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

        assert started.status_code == 500, started.text
        assert started.json()["error"]["code"] == "INTERNAL"
        assert await driver.list_managed() == []  # the old container is gone
        assert await driver.image_exists(temp_image(sandbox_id))  # its data lives here now
        assert any(
            record.levelno == logging.WARNING and "lives in the image" in record.getMessage()
            for record in caplog.records
        )
        row = await http.get(f"{SANDBOXES}/{sandbox_id}", headers=auth(key))
        assert row.json()["data"]["state"] == "stopped"

        clear_faults(app_create)
        retried = await http.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

        assert retried.status_code == 200, retried.text
        [info] = await driver.list_managed()
        assert info.resources.cpu_millicores == GROWN_CPU
        assert info.image == temp_image(sandbox_id)
        assert await read_file(driver, info.ref, PATH) == CONTENT


async def test_a_still_active_create_fault_fails_the_recovery_and_keeps_the_image(
    app_create: FastAPI,
) -> None:
    async with serve(app_create) as http:
        key, sandbox_id, driver, _ = await prepared(app_create, http)
        await http.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

        again = await http.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

        assert again.status_code == 500, again.text
        assert await driver.image_exists(temp_image(sandbox_id))
        assert await driver.list_managed() == []


async def test_a_real_driver_create_failure_also_keeps_the_temp_image(tmp_path: Path) -> None:
    app = make_app(tmp_path)
    async with serve(app) as http:
        key, sandbox_id, driver, _ = await prepared(app, http)
        original = driver.create

        async def refuse(spec: Any) -> Any:
            raise DriverError("create refused", ref=spec.name)

        driver.create = refuse  # type: ignore[method-assign]
        started = await http.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))
        assert started.status_code == 500, started.text
        assert await driver.image_exists(temp_image(sandbox_id))

        driver.create = original  # type: ignore[method-assign]
        retried = await http.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

        assert retried.status_code == 200, retried.text
        [info] = await driver.list_managed()
        assert await read_file(driver, info.ref, PATH) == CONTENT


async def test_a_vanished_container_without_a_resize_image_is_still_reported_by_the_start(
    tmp_path: Path,
) -> None:
    app = make_app(tmp_path)
    async with serve(app) as http:
        driver = app.state.driver
        key = await key_for_new_org(app, "acme")
        sandbox_id = await sandbox_with_file(http, driver, key)
        [info] = await driver.list_managed()
        await driver.destroy(info.ref, remove_volumes=False)

        started = await http.post(f"{SANDBOXES}/{sandbox_id}/start", headers=auth(key))

        assert started.json()["data"]["state"] == "error"  # the start itself reports it
        assert await driver.list_managed() == []  # nothing was invented from a missing image


# -- the status notice ------------------------------------------------------------------------


async def status_data(app: FastAPI) -> dict[str, Any]:
    async with serve(app) as http:
        response = await http.get(STATUS)
    assert response.status_code == 200
    data: dict[str, Any] = response.json()["data"]
    return data


async def test_status_notice_names_the_active_faults_without_a_notice_file(
    tmp_path: Path,
) -> None:
    app = make_app(tmp_path, fault_injection=(FAULT_RESIZE_COMMIT_FAIL, FAULT_RESIZE_CREATE_FAIL))

    data = await status_data(app)

    assert data["notice"]["message"] == (
        "fault injection active: resize_commit_fail, resize_create_fail"
    )
    assert data["status"] == "ok"


async def test_status_notice_is_appended_to_the_file_notice(tmp_path: Path) -> None:
    notice = tmp_path / "notice.txt"
    notice.write_text("degraded: upgrading the node\n", encoding="utf-8")
    app = make_app(
        tmp_path,
        fault_injection=(FAULT_RESIZE_COMMIT_FAIL,),
        status_notice_file=str(notice),
    )

    data = await status_data(app)

    assert data["status"] == "degraded"
    assert data["notice"]["message"] == (
        "upgrading the node; fault injection active: resize_commit_fail"
    )


async def test_status_notice_clears_with_the_setting(tmp_path: Path) -> None:
    app = make_app(tmp_path, fault_injection=(FAULT_RESIZE_CREATE_FAIL,))
    assert (await status_data(app))["notice"] is not None

    clear_faults(app)

    assert (await status_data(app))["notice"] is None


# -- configuration, startup warning and doctor -----------------------------------------------


def test_the_setting_is_read_from_the_environment_comma_separated() -> None:
    settings = Settings.from_env(
        {"SANDFORT_FAULT_INJECTION": " resize_commit_fail , resize_create_fail,"}
    )

    assert settings.fault_injection == (FAULT_RESIZE_COMMIT_FAIL, FAULT_RESIZE_CREATE_FAIL)
    assert Settings.from_env({}).fault_injection == ()


def test_an_unknown_fault_name_is_refused_at_load() -> None:
    with pytest.raises(ValueError, match="SANDFORT_FAULT_INJECTION"):
        Settings.from_env({"SANDFORT_FAULT_INJECTION": "resize_commit_fial"})


async def test_the_lifespan_warns_once_when_a_fault_is_set(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    app = make_app(tmp_path, fault_injection=(FAULT_RESIZE_COMMIT_FAIL,))

    with caplog.at_level(logging.WARNING):
        async with app.router.lifespan_context(app):
            pass

    warnings = [r for r in caplog.records if "fault injection" in r.getMessage()]
    assert len(warnings) == 1
    assert warnings[0].levelno == logging.WARNING
    assert FAULT_RESIZE_COMMIT_FAIL in warnings[0].getMessage()


async def test_the_lifespan_is_silent_without_a_fault(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    app = make_app(tmp_path)

    with caplog.at_level(logging.WARNING):
        async with app.router.lifespan_context(app):
            pass

    assert not [r for r in caplog.records if "fault injection" in r.getMessage()]


def test_doctor_fails_while_a_fault_is_set_and_passes_without() -> None:
    from test_admin_doctor_r58 import make_report

    faulty = Settings(fault_injection=(FAULT_RESIZE_CREATE_FAIL,))

    checks = {c.name: c for c in admin_doctor.evaluate(faulty, make_report())}
    clean = {c.name: c for c in admin_doctor.evaluate(Settings(), make_report())}

    assert checks["fault injection"].status is Status.FAIL
    assert FAULT_RESIZE_CREATE_FAIL in checks["fault injection"].detail
    assert clean["fault injection"].status is Status.PASS
    assert admin_doctor.has_failure(list(checks.values()))
