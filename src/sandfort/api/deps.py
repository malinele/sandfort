"""FastAPI dependencies resolving settings, unit of work, driver and services from app state."""

from collections.abc import Callable
from typing import cast

from fastapi import Request

from sandfort.clock import SystemClock
from sandfort.config import Settings
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.drivers.base import SandboxDriver
from sandfort.errors import InternalError
from sandfort.services.audit import AuditRecorder
from sandfort.services.sandboxes import SandboxService

SETTINGS_ATTR = "settings"
UOW_FACTORY_ATTR = "uow_factory"
DRIVER_ATTR = "driver"
SANDBOX_SERVICE_ATTR = "sandbox_service"
AUDIT_RECORDER_ATTR = "audit_recorder"

_DEFAULT_RECORDER = AuditRecorder(SystemClock())


def _state(request: Request, name: str) -> object:
    value = getattr(request.app.state, name, None)
    if value is None:
        raise InternalError(f"{name} is not configured")
    return value


def get_settings(request: Request) -> Settings:
    value = _state(request, SETTINGS_ATTR)
    if not isinstance(value, Settings):
        raise InternalError("settings are misconfigured")
    return value


def get_uow(request: Request) -> UnitOfWorkPort:
    factory = cast(Callable[[], UnitOfWorkPort], _state(request, UOW_FACTORY_ATTR))
    return factory()


def get_driver(request: Request) -> SandboxDriver:
    return cast(SandboxDriver, _state(request, DRIVER_ATTR))


def get_sandbox_service(request: Request) -> SandboxService:
    value = _state(request, SANDBOX_SERVICE_ATTR)
    if not isinstance(value, SandboxService):
        raise InternalError("sandbox service is misconfigured")
    return value


def get_audit_recorder(request: Request) -> AuditRecorder:
    """The recorder on app state when wired, else a stateless system-clock recorder."""
    value = getattr(request.app.state, AUDIT_RECORDER_ATTR, None)
    return value if isinstance(value, AuditRecorder) else _DEFAULT_RECORDER
