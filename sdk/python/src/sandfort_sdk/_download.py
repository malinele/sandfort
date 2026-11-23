"""Write a streamed response body to a local file (shared by snapshot and volume export)."""

import asyncio
from pathlib import Path

from sandfort_sdk._transport import AsyncByteStream, ByteStream


def save_stream(stream: ByteStream, target: Path) -> int:
    """Write the stream to ``target``; a failed download leaves no partial file behind."""
    written = 0
    with target.open("wb") as out:
        try:
            for chunk in stream:
                out.write(chunk)
                written += len(chunk)
        except BaseException:
            out.close()
            target.unlink(missing_ok=True)
            raise
    return written


async def asave_stream(stream: AsyncByteStream, target: Path) -> int:
    """Async :func:`save_stream`; blocking file calls run in a worker thread."""
    written = 0
    out = await asyncio.to_thread(target.open, "wb")
    try:
        async for chunk in stream:
            await asyncio.to_thread(out.write, chunk)
            written += len(chunk)
    except BaseException:
        out.close()
        target.unlink(missing_ok=True)
        raise
    out.close()
    return written
