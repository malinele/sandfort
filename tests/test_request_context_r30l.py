"""Round 30 hardening: client ip and user agent binding, nosniff on 500, per-cell tracebacks.

The request-context tests drive ``RequestIdMiddleware`` directly over a hand-built ASGI scope.
The nosniff test serves a route that raises through the real exception handlers. The kernel tests
run the uploaded kernel source in a clean subprocess, as ``test_r30e_messages`` does.
"""

import json
import subprocess
import sys
from typing import Any

import httpx
from fastapi import FastAPI
from starlette.types import Message, Receive, Scope, Send

from sandfort.api.errors import INTERNAL_MESSAGE, register_exception_handlers
from sandfort.api.middleware.request_id import (
    MAX_IP_LENGTH,
    MAX_USER_AGENT_LENGTH,
    RequestIdMiddleware,
    resolve_client_ip,
)
from sandfort.logging import current_client_ip, current_user_agent
from sandfort.toolbox import code_contexts

KERNEL_TIMEOUT_S = 60
MAX_CELLS = 100  # the kernel's MAX_CELLS
CELLS_RUN = 150

# --- 1) client ip and user agent ----------------------------------------------------------


async def bound_origin(
    *, client: tuple[str, int] | None, headers: dict[str, str]
) -> tuple[str | None, str | None]:
    """The (ip, user agent) the middleware binds while the wrapped app runs."""
    seen: list[tuple[str | None, str | None]] = []

    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append((current_client_ip(), current_user_agent()))
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        return None

    scope: dict[str, Any] = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": client,
    }
    await RequestIdMiddleware(inner)(scope, receive, send)
    return seen[0]


async def test_a_forged_forwarded_for_from_a_direct_client_does_not_change_the_ip() -> None:
    ip, _ = await bound_origin(
        client=("198.51.100.4", 5000), headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.2"}
    )

    assert ip == "198.51.100.4"


async def test_the_peer_from_the_scope_client_is_the_resolved_ip() -> None:
    ip, _ = await bound_origin(client=("192.0.2.77", 1234), headers={})

    assert ip == "192.0.2.77"


def test_a_missing_scope_client_resolves_to_no_ip() -> None:
    assert resolve_client_ip({"type": "http", "client": None}) is None
    assert resolve_client_ip({"type": "http"}) is None


async def test_a_600_character_user_agent_is_stored_as_512() -> None:
    _, agent = await bound_origin(client=("127.0.0.1", 1), headers={"User-Agent": "a" * 600})

    assert agent == "a" * MAX_USER_AGENT_LENGTH
    assert MAX_USER_AGENT_LENGTH == 512


async def test_a_short_user_agent_is_kept_unchanged() -> None:
    _, agent = await bound_origin(client=("127.0.0.1", 1), headers={"User-Agent": "sdk/1.0"})

    assert agent == "sdk/1.0"


async def test_a_60_character_ip_is_stored_as_none() -> None:
    ip, _ = await bound_origin(client=("1" * 60, 1), headers={})

    assert ip is None


async def test_an_ip_of_the_maximum_length_is_kept() -> None:
    peer = "f" * MAX_IP_LENGTH

    ip, _ = await bound_origin(client=(peer, 1), headers={})

    assert MAX_IP_LENGTH == 45
    assert ip == peer


# --- 2) nosniff on a 500 ------------------------------------------------------------------


async def test_an_unhandled_exception_answers_500_with_nosniff() -> None:
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("secret detail")

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/boom")

    assert response.status_code == 500
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.json()["error"]["message"] == INTERNAL_MESSAGE


async def test_a_handled_error_gains_nosniff() -> None:
    app = FastAPI()
    register_exception_handlers(app)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/missing")

    assert response.status_code == 404
    assert response.headers["x-content-type-options"] == "nosniff"


# --- 3) per-cell tracebacks ---------------------------------------------------------------

KERNEL_PROBE = r"""
import contextlib, io, json, linecache, sys
source = sys.stdin.read()
ns = {"__name__": "kernel_under_test", "__file__": "kernel.py"}
exec(compile(source, "kernel.py", "exec"), ns)
cells = ns["new_main"]()
stderrs = []
for code in json.loads(sys.argv[1]):
    buffer = io.StringIO()
    with contextlib.redirect_stderr(buffer):
        try:
            ns["execute"](cells, code)
        except BaseException as exc:
            ns["report"](exc)
    stderrs.append(buffer.getvalue())
cached = sorted(k for k in linecache.cache if k.startswith("<cell-"))
print(json.dumps({"stderrs": stderrs, "cached": cached}))
"""


def run_kernel_cells(*cells: str) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, "-I", "-c", KERNEL_PROBE, json.dumps(cells)],
        input=code_contexts.KERNEL_SOURCE.encode(),
        capture_output=True,
        timeout=KERNEL_TIMEOUT_S,
        check=True,
    )
    result: dict[str, Any] = json.loads(completed.stdout)
    return result


def test_a_function_from_an_earlier_cell_shows_its_own_source_line() -> None:
    result = run_kernel_cells(
        "def boom():\n    return 1 / 0  # defined in the first cell", "x = 1\nboom()"
    )

    first, second = result["stderrs"]
    assert first == ""
    assert 'File "<cell-2>", line 2, in <module>' in second
    assert 'File "<cell-1>", line 2, in boom' in second
    assert "return 1 / 0  # defined in the first cell" in second
    assert "kernel.py" not in second  # the kernel frames stay hidden


def test_the_cell_source_cache_stays_bounded_and_prunes_the_oldest() -> None:
    result = run_kernel_cells(*(f"v{n} = {n}" for n in range(CELLS_RUN)))

    cached = result["cached"]
    assert len(cached) == MAX_CELLS
    assert "<cell-1>" not in cached
    assert f"<cell-{CELLS_RUN - MAX_CELLS}>" not in cached
    assert f"<cell-{CELLS_RUN - MAX_CELLS + 1}>" in cached
    assert f"<cell-{CELLS_RUN}>" in cached
