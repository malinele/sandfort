"""Toolbox route modules (prefix ``/v1/sandboxes/{sid}/toolbox``).

process, fs, sessions, git, pty (REST plus the ``/pty/{id}/connect`` websocket) and
code-contexts (persistent Python kernels). ``router``
aggregates them and carries the one shared dependency that records sandbox activity for the
idle scanner, so no endpoint touches the tracker itself.
"""

from fastapi import APIRouter, Depends, Request
from starlette.requests import HTTPConnection

from sandfort.api.routes.toolbox import code_contexts, fs, git, process, pty, sessions
from sandfort.api.wiring import ACTIVITY_TRACKER_ATTR
from sandfort.auth.authenticate import authenticate
from sandfort.domain.org import Scope
from sandfort.errors import SandfortError
from sandfort.services.activity import ActivityTracker


async def touch_activity(conn: HTTPConnection) -> None:
    """Record activity for the path's sandbox when the caller holds a valid toolbox key.

    Failures are swallowed: the endpoint's own dependencies reject the call. The websocket
    connect carries no API key (its single-use token is redeemed in the handler), so it
    does not count as activity here.
    """
    sandbox_id = conn.path_params.get("sandbox_id")
    tracker = getattr(conn.app.state, ACTIVITY_TRACKER_ATTR, None)
    if conn.scope["type"] != "http" or not isinstance(sandbox_id, str):
        return
    if not isinstance(tracker, ActivityTracker):
        return
    try:
        principal = await authenticate(Request(conn.scope))
    except SandfortError:
        return
    if Scope.TOOLBOX in principal.scopes:
        tracker.touch(sandbox_id)


router = APIRouter(dependencies=[Depends(touch_activity)])
for _module in (process, fs, sessions, git, pty, code_contexts):
    router.include_router(_module.router)
