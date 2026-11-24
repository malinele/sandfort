"""A streaming body that gives a held resource back when the stream ends, however it ends."""

import weakref
from collections.abc import AsyncIterator, Awaitable, Callable
from uuid import uuid4

from sandfort.toolbox.pty import OrgSlots


async def held_stream(
    frames: AsyncIterator[str], release: Callable[[], None]
) -> AsyncIterator[str]:
    """Yield ``frames`` unchanged; on exit close them first, then call ``release`` exactly once.

    Exit means the frames ran out, the consumer closed this generator, or the task was cancelled
    (a client that left). ``release`` runs even when closing ``frames`` fails. A body that is
    never iterated never reaches the ``finally``: the caller backs this up with
    ``weakref.finalize`` on the returned generator.
    """
    try:
        async for frame in frames:
            yield frame
    finally:
        try:
            aclose = getattr(frames, "aclose", None)
            if aclose is not None:
                await aclose()
        finally:
            release()


async def capped_body(
    slots: OrgSlots, org_id: str, make_frames: Callable[[], Awaitable[AsyncIterator[str]]]
) -> AsyncIterator[str]:
    """Hold one live-log-stream slot of ``org_id`` for as long as the returned body is open.

    The slot is taken before ``make_frames`` runs, so an org at its cap is refused (503
    ``CAPACITY``) before any lookup. When ``make_frames`` fails the slot is given back and the
    error propagates; otherwise the slot frees when the body closes, however it closes.
    """
    key = uuid4().hex
    slots.hold(org_id, key)
    try:
        frames = await make_frames()
    except BaseException:
        slots.release(key)
        raise
    body = held_stream(frames, lambda: slots.release(key))
    # a body that is never iterated never reaches its ``finally``: the slot still frees
    weakref.finalize(body, slots.release, key)
    return body
