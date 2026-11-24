"""Shared pieces of the sandbox handles and of ``create_sandbox`` (no I/O).

``SandboxFields`` gives :class:`~sandfort_sdk.sandbox.Sandbox` and ``AsyncSandbox`` read-only
properties over their ``info`` record. The helpers here build the wait-timeout read bound of a
create, its error, and decide which delete errors a ``with`` block may ignore.
"""

import logging
import math
from datetime import datetime

from sandfort_sdk.exceptions import NotFound, SandboxTimeoutError
from sandfort_sdk.models import Resources, SandboxInfo, require_int_range

logger = logging.getLogger(__name__)

# Added to ``wait_timeout_s`` for the read timeout of a create that blocks until started.
CREATE_READ_MARGIN_S = 5.0

# The bounds of ``ResizeSandboxRequest`` (the server answers 422 outside them).
MIN_CPU_MILLICORES = 100
MAX_CPU_MILLICORES = 1_000_000
MIN_MEMORY_MIB = 64
MAX_MEMORY_MIB = 16_777_216
MIN_DISK_GIB = 1
MAX_DISK_GIB = 1_048_576


def resize_body(
    cpu_millicores: int | None, memory_mib: int | None, disk_gib: int | None
) -> dict[str, int]:
    """The resize request body: only the given fields, each checked against the server bounds.

    Raises ``ValueError`` before any request for a value that is not an ``int`` in range (a
    ``bool`` or a float such as ``5.0`` is refused) and when no field is given.
    """
    body: dict[str, int] = {}
    if cpu_millicores is not None:
        body["cpu_millicores"] = require_int_range(
            cpu_millicores, "cpu_millicores", MIN_CPU_MILLICORES, MAX_CPU_MILLICORES
        )
    if memory_mib is not None:
        body["memory_mib"] = require_int_range(
            memory_mib, "memory_mib", MIN_MEMORY_MIB, MAX_MEMORY_MIB
        )
    if disk_gib is not None:
        body["disk_gib"] = require_int_range(disk_gib, "disk_gib", MIN_DISK_GIB, MAX_DISK_GIB)
    if not body:
        raise ValueError("nothing to resize: pass cpu_millicores, memory_mib or disk_gib")
    return body


def check_wait_budget(wait: bool, wait_timeout_s: float | None) -> None:
    """Reject a wait budget that is not a finite number greater than 0.

    Only a requested wait is checked: without ``wait`` the budget is ignored, and ``None``
    (the default of ``start``) stands for the default budget.
    """
    if not wait or wait_timeout_s is None:
        return
    usable = (
        isinstance(wait_timeout_s, int | float)
        and not isinstance(wait_timeout_s, bool)
        and math.isfinite(wait_timeout_s)
        and wait_timeout_s > 0
    )
    if not usable:
        raise ValueError("wait_timeout_s must be a finite number greater than 0")


def create_read_timeout(wait: bool, wait_timeout_s: float) -> float | None:
    """Read timeout of the create POST: the wait budget plus a margin; ``None`` without waiting.

    A server without jobs mode holds the create request open until the sandbox is started, so
    the HTTP read must not outlive the wait budget the caller asked for.
    """
    return wait_timeout_s + CREATE_READ_MARGIN_S if wait else None


def create_timeout_error(
    name: str | None,
    idempotency_key: str | None,
    wait_timeout_s: float,
    deleted_id: str | None = None,
) -> SandboxTimeoutError:
    """The error of a create whose POST outlived ``wait_timeout_s``.

    ``deleted_id``: the sandbox the timeout cleanup deleted (the message says nothing is left
    and ``sandbox_id`` carries it; the error's ``deleted`` is True); ``None`` means the create
    may still land on the server.
    """
    label = f"sandbox '{name}'" if name else "a sandbox (no name was given)"
    if deleted_id is not None:
        return SandboxTimeoutError(
            f"creating {label} did not finish within {wait_timeout_s:g} s; the sandbox it made "
            f"({deleted_id}) was deleted, so nothing is left behind",
            sandbox_id=deleted_id,
            deleted=True,
        )
    message = (
        f"creating {label} did not finish within {wait_timeout_s:g} s; "
        "the create may still finish on the server"
    )
    if idempotency_key is not None:
        message += (
            f"; resending the same call with the idempotency key '{idempotency_key}' "
            "returns the sandbox"
        )
    return SandboxTimeoutError(message)


def with_create_request_id[H: "SandboxFields"](handle: H, request_id: str | None) -> H:
    """``handle`` with its :attr:`SandboxFields.request_id` set to the create reply's id."""
    handle._create_request_id = request_id
    return handle


def delete_error_is_ignored(error: Exception, propagating: bool, sandbox_id: str) -> bool:
    """True when a delete error at the end of a ``with`` block must not be raised.

    A :class:`NotFound` means the sandbox is gone already. Any other error is raised, unless
    an exception is already propagating out of the block: that one must not be masked, so the
    delete error is logged instead.
    """
    if isinstance(error, NotFound):
        return True
    if propagating:
        logger.warning("cannot delete sandbox %s on exit", sandbox_id, exc_info=error)
    return propagating


class SandboxFields:
    """Read-only views of the fields of ``info``; ``refresh`` and the actions replace ``info``."""

    info: SandboxInfo
    # Set once by ``create_sandbox`` (see :func:`with_create_request_id`); ``None`` elsewhere.
    _create_request_id: str | None = None

    @property
    def request_id(self) -> str | None:
        """The ``x-request-id`` of the create reply when ``create_sandbox`` returned this handle.

        ``None`` for a handle from ``get``, ``list_sandboxes`` or an action, or when the reply
        had no such header. ``refresh`` and the actions do not change it.
        """
        return self._create_request_id

    @property
    def id(self) -> str:
        """The sandbox id (``sbx_...``)."""
        return self.info.id

    @property
    def name(self) -> str:
        """The sandbox name, unique among the live sandboxes of the organization."""
        return self.info.name

    @property
    def state(self) -> str:
        """The state in the last record fetched (``refresh`` to update it)."""
        return self.info.state

    @property
    def isolation(self) -> str:
        """The isolation tier the sandbox runs on (``container``, ``gvisor`` or ``microvm``)."""
        return self.info.isolation

    @property
    def error_reason(self) -> str | None:
        """Why the sandbox is in the ``error`` state; ``None`` otherwise."""
        return self.info.error_reason

    @property
    def auto_stop_minutes(self) -> int:
        """The auto-stop interval in minutes, as the server reports it (the default is 15)."""
        return self.info.auto_stop_minutes

    @property
    def auto_delete_minutes(self) -> int:
        """The auto-delete interval in minutes, as the server reports it (the default is -1)."""
        return self.info.auto_delete_minutes

    @property
    def resources(self) -> Resources:
        """CPU millicores, memory (MiB) and disk (GiB) of the sandbox."""
        return self.info.resources

    @property
    def labels(self) -> dict[str, str]:
        """A copy of the user labels of the sandbox."""
        return dict(self.info.labels)

    @property
    def env(self) -> dict[str, str]:
        """A copy of the environment as the API returns it: names with masked values.

        The server never sends the values of the variables back; use :attr:`env_keys` when only
        the names matter.
        """
        return dict(self.info.env)

    @property
    def env_keys(self) -> tuple[str, ...]:
        """The names of the environment variables set on the sandbox."""
        return tuple(self.info.env)

    @property
    def block_network(self) -> bool:
        """True when the network policy blocks all network access."""
        return self.info.block_network

    @property
    def public(self) -> bool:
        """True when the preview proxy serves the sandbox without a preview token."""
        return self.info.public

    @property
    def job_id(self) -> str | None:
        """The id of the last lifecycle job the server reported; ``None`` if none."""
        return self.info.job_id

    @property
    def snapshot(self) -> str | None:
        """The snapshot the sandbox was created from; ``None`` while the server omits it."""
        return self.info.snapshot

    @property
    def error_code(self) -> str | None:
        """The machine-readable error code; ``None`` without an error (see ``error_codes``)."""
        return self.info.error_code

    @property
    def stop_cause(self) -> str | None:
        """Why the sandbox stopped; ``None`` unless stopping or stopped (see ``stop_causes``)."""
        return self.info.stop_cause

    @property
    def stopped_at(self) -> datetime | None:
        """When the sandbox stopped; ``None`` unless it is ``stopped`` or the server omits it."""
        return self.info.stopped_at

    @property
    def created_at(self) -> datetime | None:
        """When the sandbox was created; ``None`` while the server omits it."""
        return self.info.created_at

    @property
    def updated_at(self) -> datetime | None:
        """When the sandbox record last changed; ``None`` while the server omits it."""
        return self.info.updated_at
