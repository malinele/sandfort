"""The registry allowlist comes from ``Settings`` at every call site; one egress wiring (r58).

An embedding that builds ``Settings(allowed_registries=...)`` directly, with no
``SANDFORT_ALLOWED_REGISTRIES`` in the environment, still gets the allowlist enforced on sandbox
create, snapshot register and image builds. ``install_services`` calls ``wire_egress`` once, so
the job handlers' lifecycle and the auto-stop scanner both carry the re-minting settings.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import FastAPI

from sandfort.api.wiring import (
    AUTOSTOP_SCANNER_ATTR,
    IMAGE_BUILD_SERVICE_ATTR,
    SNAPSHOT_SERVICE_ATTR,
    install_services,
)
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.errors import Unprocessable
from sandfort.services.image_policy import ALLOWED_REGISTRIES_ENV
from sandfort.services.sandbox_jobs import install_job_egress, job_lifecycle
from sandfort.services.sandboxes import CreateSandboxCommand, SandboxService
from sandfort.workers.handlers import JobContext

FOREIGN = "evil.example.com/team/base:1"
ALLOWED = ("ghcr.io",)
PEPPER = "test-pepper-r58-registry-settings-0123456789"
SECRET = "test-egress-secret-r58-wiring-0123456789"
ADDRESS = "10.0.0.1:3128"
CLOCK = FrozenClock(datetime(2026, 11, 10, tzinfo=UTC))


@pytest.fixture(autouse=True)
def _no_env_allowlist(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(ALLOWED_REGISTRIES_ENV, raising=False)
    install_job_egress(None)
    yield
    install_job_egress(None)


class _Snapshots:
    async def get_by_name(self, org_id: str, name: str) -> None:
        return None


class _Uow:
    def __init__(self) -> None:
        self.sandboxes: Any = SimpleNamespace()
        self.snapshots: Any = _Snapshots()

    async def __aenter__(self) -> "_Uow":
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None


class _RefusingDriver:
    name = "stub"

    def __getattr__(self, attr: str) -> Any:
        pytest.fail(f"the driver must not be reached ({attr})")


def _app(tmp_path: Path, **changes: Any) -> FastAPI:
    settings = Settings(
        driver="fake",
        api_key_pepper=PEPPER,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'sandfort.db'}",
        allowed_registries=ALLOWED,
        **changes,
    )
    app = FastAPI()
    install_services(app, settings)
    return app


async def test_create_with_a_foreign_image_is_refused_by_the_settings_allowlist() -> None:
    service = SandboxService(
        cast(Any, _Uow),
        cast(Any, _RefusingDriver()),
        Settings(allowed_registries=ALLOWED),
        CLOCK,
    )

    with pytest.raises(Unprocessable) as raised:
        await service.create("org_1", "usr_1", CreateSandboxCommand(snapshot=FOREIGN))

    assert "evil.example.com" in raised.value.message


async def test_snapshot_register_is_refused_by_the_settings_allowlist(tmp_path: Path) -> None:
    service = getattr(_app(tmp_path).state, SNAPSHOT_SERVICE_ATTR)

    with pytest.raises(Unprocessable) as raised:
        await service.register("org_1", None, FOREIGN)

    assert "evil.example.com" in raised.value.message


async def test_a_build_with_a_foreign_base_is_refused_by_the_settings_allowlist(
    tmp_path: Path,
) -> None:
    service = getattr(_app(tmp_path).state, IMAGE_BUILD_SERVICE_ATTR)

    with pytest.raises(Unprocessable) as raised:
        await service.build("org_1", None, {"base_image": FOREIGN, "files": []})

    assert "evil.example.com" in raised.value.message


def test_startup_wiring_gives_the_job_lifecycle_and_autostop_reminting(tmp_path: Path) -> None:
    app = _app(tmp_path, egress_proxy_address=ADDRESS, egress_secret=SECRET)
    context = JobContext(cast(Any, _Uow), cast(Any, _RefusingDriver()), CLOCK)

    job_egress = vars(job_lifecycle(context))["_egress"]
    scanner = getattr(app.state, AUTOSTOP_SCANNER_ATTR)
    scanner_egress = vars(vars(scanner)["_core"])["_egress"]

    assert job_egress is not None
    assert job_egress.proxy_address == ADDRESS
    assert job_egress.secret == SECRET
    assert scanner_egress == job_egress


def test_startup_wiring_without_an_egress_proxy_installs_none(tmp_path: Path) -> None:
    app = _app(tmp_path)
    context = JobContext(cast(Any, _Uow), cast(Any, _RefusingDriver()), CLOCK)
    scanner = getattr(app.state, AUTOSTOP_SCANNER_ATTR)

    assert vars(job_lifecycle(context))["_egress"] is None
    assert vars(vars(scanner)["_core"])["_egress"] is None
