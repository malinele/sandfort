"""Firecracker driver skeleton (WP 5.6): compute and exec delegated to a microVM agent.

Every method is one request/response against the agent (``agent_client``); no firecracker
binary is touched here. Declared capabilities are exactly compute and exec. The archive and
pty primitives the frozen ``ExecDriver`` protocol carries raise ``DriverUnsupported``, and
the driver implements none of the stream, session, logs, image, build, volume or inventory
protocols, so capability detection agrees with the declaration.
"""

import logging
from collections.abc import AsyncIterator, Mapping
from datetime import datetime
from typing import Any

import httpx

from sandfort.clock import Clock
from sandfort.config import Settings
from sandfort.domain.resources import ResourceSpec
from sandfort.drivers.base import (
    ExecEvent,
    ExecRequest,
    ExecResult,
    ExitEvent,
    InstanceInfo,
    InstanceState,
    OutputChunk,
    PtyHandle,
    PtyRequest,
    SandboxSpec,
)
from sandfort.drivers.errors import (
    DriverConflict,
    DriverError,
    DriverNotFound,
    DriverUnsupported,
)
from sandfort.drivers.firecracker.agent_client import (
    DEFAULT_TIMEOUT_S,
    AgentClient,
    decode_bytes,
    encode_bytes,
)
from sandfort.drivers.registry import Capability, DriverEntry

DRIVER_NAME = "firecracker"
CAPABILITIES: frozenset[Capability] = frozenset({Capability.COMPUTE, Capability.EXEC})
# The tenant-facing sentence for an agent vm payload that fails validation (details: server log).
MALFORMED_VM_MESSAGE = "the sandbox agent returned a malformed vm; details are in the server log"

logger = logging.getLogger(__name__)


def _text(vm: Mapping[str, Any], key: str) -> str:
    value = vm.get(key)
    if not isinstance(value, str) or not value:
        raise DriverError(f"agent vm field {key!r} must be a non-empty string")
    return value


def _int(body: Mapping[str, Any], key: str, default: int | None = None) -> int:
    value = body.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise DriverError(f"agent field {key!r} must be an integer")
    return value


def _labels(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise DriverError("agent vm field 'labels' must be an object")
    return {str(key): str(item) for key, item in value.items()}


def _info(vm: Mapping[str, Any]) -> InstanceInfo:
    """Validate one agent vm payload into ``InstanceInfo``."""
    try:
        state = InstanceState(_text(vm, "state"))
        created_at = datetime.fromisoformat(_text(vm, "created_at"))
        resources = ResourceSpec(
            cpu_millicores=_int(vm, "cpu_millicores"),
            memory_mib=_int(vm, "memory_mib"),
            disk_gib=_int(vm, "disk_gib"),
        )
    except ValueError as exc:  # also pydantic's ValidationError
        # The validation text can quote agent internals: server log only, never the tenant.
        logger.warning("the firecracker agent returned a malformed vm: %s", exc)
        raise DriverError(MALFORMED_VM_MESSAGE, daemon_text=str(exc)) from exc
    return InstanceInfo(
        ref=_text(vm, "id"),
        name=_text(vm, "name"),
        sandbox_id=_text(vm, "sandbox_id"),
        org_id=_text(vm, "org_id"),
        state=state,
        image=_text(vm, "image"),
        resources=resources,
        labels=_labels(vm.get("labels")),
        created_at=created_at,
    )


def _create_payload(spec: SandboxSpec) -> dict[str, Any]:
    return {
        "name": spec.name,
        "sandbox_id": spec.sandbox_id,
        "org_id": spec.org_id,
        "image": spec.image,
        "cpu_millicores": spec.resources.cpu_millicores,
        "memory_mib": spec.resources.memory_mib,
        "disk_gib": spec.resources.disk_gib,
        "env": dict(spec.env),
        "labels": dict(spec.labels),
    }


def _exec_payload(request: ExecRequest) -> dict[str, Any]:
    return {
        "argv": list(request.argv),
        "cwd": request.cwd,
        "env": dict(request.env),
        "stdin_b64": encode_bytes(request.stdin),
        "timeout_s": request.timeout_s,
        "max_output_bytes": request.max_output_bytes,
        "user": request.user,
    }


def _result(body: Mapping[str, Any], cap: int) -> ExecResult:
    """Validate an exec answer; the output cap is enforced here too, never trusted."""
    stdout = decode_bytes(body.get("stdout_b64"), "stdout_b64")
    stderr = decode_bytes(body.get("stderr_b64"), "stderr_b64")
    over_cap = len(stdout) > cap or len(stderr) > cap
    return ExecResult(
        exit_code=_int(body, "exit_code"),
        stdout=stdout[:cap],
        stderr=stderr[:cap],
        timed_out=body.get("timed_out") is True,
        truncated=body.get("truncated") is True or over_cap,
        duration_ms=_int(body, "duration_ms", 0),
    )


class FirecrackerDriver:
    """Compute and exec over the microVM agent at ``base_url``; close with ``aclose``."""

    def __init__(
        self,
        base_url: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        self._agent = AgentClient(base_url, transport=transport, timeout_s=timeout_s)

    @property
    def name(self) -> str:
        return DRIVER_NAME

    async def aclose(self) -> None:
        await self._agent.aclose()

    # -- compute -------------------------------------------------------------

    async def create(self, spec: SandboxSpec) -> InstanceInfo:
        """The agent adopts an existing vm of the same name; a foreign owner is a conflict."""
        info = _info(await self._agent.create_vm(_create_payload(spec)))
        if (info.sandbox_id, info.org_id) != (spec.sandbox_id, spec.org_id):
            message = f"vm name {spec.name!r} is taken by another sandbox"
            raise DriverConflict(message, ref=info.ref)
        return info

    async def start(self, ref: str) -> None:
        await self._agent.vm_action(ref, "start")

    async def stop(self, ref: str, *, timeout_s: float = 10.0) -> None:
        await self._agent.vm_action(ref, "stop")

    async def destroy(self, ref: str, *, remove_volumes: bool = True) -> None:
        """Delete ``ref``; a missing vm is already the desired outcome."""
        try:
            await self._agent.delete_vm(ref)
        except DriverNotFound:
            return

    async def inspect(self, ref: str) -> InstanceInfo:
        return _info(await self._agent.get_vm(ref))

    async def list_managed(self, *, org_id: str | None = None) -> list[InstanceInfo]:
        return [_info(vm) for vm in await self._agent.list_vms(org_id=org_id)]

    async def pause(self, ref: str) -> None:
        await self._agent.vm_action(ref, "pause")

    async def unpause(self, ref: str) -> None:
        await self._agent.vm_action(ref, "resume")

    # -- exec ----------------------------------------------------------------

    async def exec(self, ref: str, request: ExecRequest) -> ExecResult:
        if not request.argv:
            raise DriverError("exec needs a non-empty argv", ref=ref)
        payload = _exec_payload(request)
        body = await self._agent.exec(ref, payload, timeout_s=request.timeout_s)
        return _result(body, request.max_output_bytes)

    async def exec_stream(self, ref: str, request: ExecRequest) -> AsyncIterator[ExecEvent]:
        """The agent answers whole results, so the stream replays one buffered exec."""
        result = await self.exec(ref, request)
        if result.stdout:
            yield OutputChunk("stdout", result.stdout)
        if result.stderr:
            yield OutputChunk("stderr", result.stderr)
        yield ExitEvent(
            result.exit_code,
            timed_out=result.timed_out,
            truncated=result.truncated,
            sandbox_stopped=result.sandbox_stopped,
        )

    # -- ExecDriver members outside the declared capabilities ----------------

    async def put_archive(self, ref: str, dest_path: str, data: AsyncIterator[bytes]) -> None:
        raise DriverUnsupported("the firecracker skeleton has no archive support", ref=ref)

    def get_archive(self, ref: str, path: str) -> AsyncIterator[bytes]:
        raise DriverUnsupported("the firecracker skeleton has no archive support", ref=ref)

    async def open_pty(self, ref: str, request: PtyRequest) -> PtyHandle:
        raise DriverUnsupported("the firecracker skeleton has no pty support", ref=ref)


def driver_entry(
    base_url: str, *, transport: httpx.AsyncBaseTransport | None = None
) -> DriverEntry:
    """A registry entry for an agent at ``base_url``, for a plug-in's ``sandfort.drivers``."""

    def factory(settings: Settings, clock: Clock) -> object:
        return FirecrackerDriver(base_url, transport=transport)

    return DriverEntry(DRIVER_NAME, factory, CAPABILITIES)
