"""HTTP client for the microVM agent the firecracker driver delegates to (skeleton, WP 5.6).

Agent protocol (JSON over HTTP, every call plain request/response against ``base_url``):

- ``POST /vms`` body ``{name, sandbox_id, org_id, image, cpu_millicores, memory_mib,
  disk_gib, env, labels}``: create a VM, or return the existing one with that name.
- ``GET /vms?org_id=...``: ``{"vms": [vm, ...]}``. ``GET /vms/{id}``: one vm.
- ``POST /vms/{id}/{start|stop|pause|resume}``, ``DELETE /vms/{id}``: no body back.
- ``POST /vms/{id}/exec`` body ``{argv, cwd, env, stdin_b64, timeout_s, max_output_bytes,
  user}``: ``{exit_code, stdout_b64, stderr_b64, timed_out, truncated, duration_ms}``.

A vm is ``{id, name, sandbox_id, org_id, state, image, cpu_millicores, memory_mib,
disk_gib, labels, created_at}``. Status 404 maps to ``DriverNotFound``, 409 to
``DriverConflict``, 501 to ``DriverUnsupported``, 504 to ``DriverTimeout``; responses are
validated, never trusted.
"""

import base64
import binascii
import logging
from collections.abc import Mapping
from typing import Any

import httpx

from sandfort.drivers.errors import (
    DriverConflict,
    DriverError,
    DriverNotFound,
    DriverTimeout,
    DriverUnsupported,
)

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_S = 30.0
EXEC_TIMEOUT_MARGIN_S = 10.0
ERROR_TEXT_LIMIT = 200
AGENT_ERROR_MESSAGE = "the microVM agent reported an error; the details are in the server log"
AGENT_UNREACHABLE_MESSAGE = "the microVM agent request failed; the details are in the server log"
VM_ACTIONS = frozenset({"start", "stop", "pause", "resume"})

_STATUS_ERRORS: Mapping[int, type[DriverError]] = {
    404: DriverNotFound,
    409: DriverConflict,
    501: DriverUnsupported,
    504: DriverTimeout,
}


def encode_bytes(data: bytes | None) -> str | None:
    return None if data is None else base64.b64encode(data).decode("ascii")


def decode_bytes(value: object, field: str) -> bytes:
    if value is None:
        return b""
    if not isinstance(value, str):
        raise DriverError(f"agent field {field!r} must be base64 text")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DriverError(f"agent field {field!r} is not valid base64") from exc


def _error_message(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:ERROR_TEXT_LIMIT] or response.reason_phrase
    if isinstance(body, Mapping) and isinstance(body.get("error"), str):
        return str(body["error"])
    return response.reason_phrase


def _raise_for_status(response: httpx.Response, ref: str | None) -> None:
    if response.is_success:
        return
    error = _STATUS_ERRORS.get(response.status_code, DriverError)
    logger.warning(
        "agent answered %s (ref=%s): %s", response.status_code, ref, _error_message(response)
    )
    raise error(f"{AGENT_ERROR_MESSAGE} (status {response.status_code})", ref=ref)


def _json_object(response: httpx.Response, ref: str | None) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError as exc:
        raise DriverError("agent returned a non-JSON body", ref=ref) from exc
    if not isinstance(body, dict):
        raise DriverError("agent returned a non-object JSON body", ref=ref)
    return body


class AgentClient:
    """Thin async wrapper over the agent endpoints; owns its ``httpx.AsyncClient``."""

    def __init__(
        self,
        base_url: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        if not base_url:
            raise ValueError("the microVM agent needs a base url")
        self._timeout_s = timeout_s
        self._http = httpx.AsyncClient(base_url=base_url, transport=transport, timeout=timeout_s)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        ref: str | None = None,
        json: Mapping[str, Any] | None = None,
        params: Mapping[str, str] | None = None,
        timeout_s: float | None = None,
    ) -> httpx.Response:
        timeout = self._timeout_s if timeout_s is None else timeout_s
        try:
            response = await self._http.request(
                method, path, json=json, params=params, timeout=timeout
            )
        except httpx.TimeoutException as exc:
            raise DriverTimeout(f"agent {method} {path} timed out", ref=ref) from exc
        except httpx.HTTPError as exc:
            logger.warning("agent %s %s failed (ref=%s): %s", method, path, ref, exc)
            raise DriverError(AGENT_UNREACHABLE_MESSAGE, ref=ref) from exc
        _raise_for_status(response, ref)
        return response

    async def create_vm(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        name = str(payload.get("name", ""))
        response = await self._request("POST", "/vms", ref=name, json=payload)
        return _json_object(response, name)

    async def get_vm(self, vm_id: str) -> dict[str, Any]:
        response = await self._request("GET", f"/vms/{vm_id}", ref=vm_id)
        return _json_object(response, vm_id)

    async def list_vms(self, *, org_id: str | None = None) -> list[dict[str, Any]]:
        params = {"org_id": org_id} if org_id is not None else None
        body = _json_object(await self._request("GET", "/vms", params=params), None)
        vms = body.get("vms")
        if not isinstance(vms, list) or not all(isinstance(vm, dict) for vm in vms):
            raise DriverError("agent vm listing must be {'vms': [object, ...]}")
        return vms

    async def vm_action(self, vm_id: str, action: str) -> None:
        if action not in VM_ACTIONS:
            raise ValueError(f"unknown vm action {action!r}")
        await self._request("POST", f"/vms/{vm_id}/{action}", ref=vm_id)

    async def delete_vm(self, vm_id: str) -> None:
        await self._request("DELETE", f"/vms/{vm_id}", ref=vm_id)

    async def exec(
        self, vm_id: str, payload: Mapping[str, Any], *, timeout_s: float
    ) -> dict[str, Any]:
        """Run one command; the HTTP deadline outlives the command's own timeout."""
        response = await self._request(
            "POST",
            f"/vms/{vm_id}/exec",
            ref=vm_id,
            json=payload,
            timeout_s=timeout_s + EXEC_TIMEOUT_MARGIN_S,
        )
        return _json_object(response, vm_id)
