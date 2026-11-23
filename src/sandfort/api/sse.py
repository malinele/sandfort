"""Server-sent event formatting and a keepalive wrapper for streaming routes."""

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import anyio

from sandfort.api.safe_json import LONE_SURROGATE, REPLACEMENT_CHARACTER

KEEPALIVE_COMMENT = ": keepalive\n\n"
DEFAULT_KEEPALIVE_INTERVAL_S = 15.0


def format_event(data: Any, *, event: str | None = None, event_id: str | None = None) -> str:
    """Render one SSE frame: optional ``event:`` and ``id:`` lines, then JSON ``data:``."""
    lines: list[str] = []
    if event is not None:
        lines.append(f"event: {event}")
    if event_id is not None:
        lines.append(f"id: {event_id}")
    payload = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    # A stored lone surrogate has no UTF-8 encoding and would break the stream after the response
    # started: render it as U+FFFD, as SafeJSONResponse does for plain responses.
    lines.append("data: " + LONE_SURROGATE.sub(REPLACEMENT_CHARACTER, payload))
    return "\n".join(lines) + "\n\n"


async def with_keepalive(
    frames: AsyncIterator[str], *, interval_s: float = DEFAULT_KEEPALIVE_INTERVAL_S
) -> AsyncIterator[str]:
    """Pass ``frames`` through, emitting a comment frame whenever ``interval_s`` passes idle.

    However the wrapper ends (exhausted, client disconnect, cancellation), the in-flight read is
    cancelled and awaited and ``frames`` is closed, so its ``finally`` steps run right away.
    """

    async def next_frame() -> str:
        return await anext(frames)

    pending = asyncio.ensure_future(next_frame())
    try:
        while True:
            done, _ = await asyncio.wait({pending}, timeout=interval_s)
            if not done:
                yield KEEPALIVE_COMMENT
                continue
            try:
                frame = pending.result()
            except StopAsyncIteration:
                return
            yield frame
            pending = asyncio.ensure_future(next_frame())
    finally:
        pending.cancel()
        with anyio.CancelScope(shield=True):
            await asyncio.wait({pending})
            aclose = getattr(frames, "aclose", None)
            if aclose is not None:
                await aclose()
