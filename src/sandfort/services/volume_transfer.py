"""Volume export and restore: a gzipped tar out of a volume, and a gzipped tar back into it.

Export streams the volume read-only through the driver's helper container. The audit row
(``volume.export``, details: the name only, the byte count being unknown up front) is written
after the stream opened and before the first byte leaves, so an export that failed to open
leaves no row and an export that streams is always on record.

Restore replaces the contents. It is refused (409 ``in_use``) while any non-destroyed sandbox
mounts the volume, and (409 ``restore_in_progress``) while another restore of the same volume
runs in this process. The body is a gzipped tar of at most the fs upload limit; it is
decompressed here, in bounded steps, so the restored bytes are counted as they go to the
driver. The driver empties the volume and extracts. Anything that fails after the driver began
(a body over the volume size limit, a corrupt stream, an unreadable tar, a dropped
connection) leaves the volume EMPTY: the volume is emptied again and the answer says so
(``details.volume_emptied``). A body refused before the driver began (not gzip, empty, over
the declared length) changes nothing. The restore audit row (``volume.restore``) is written
once, after the outcome is known, with the restored bytes or the failure.

Driver calls never run inside an open transaction: every database step here is its own short
unit of work in ``VolumeService``. The claim set is per process; it does not stop a sandbox
from being created that mounts the volume right after the scan (the same window the volume
delete has).
"""

import logging
import re
import uuid
import weakref
import zlib
from collections.abc import AsyncIterator, Callable
from contextlib import suppress
from dataclasses import dataclass, field

import anyio

from sandfort.domain.volume import Volume
from sandfort.drivers.base import SandboxDriver, VolumeTransferDriver
from sandfort.drivers.errors import DriverError, DriverForbiddenEntry, DriverInvalidArchive
from sandfort.errors import (
    UNSUPPORTED_MODE,
    Conflict,
    PayloadTooLarge,
    SandfortError,
    Unprocessable,
    upload_limit_error,
)
from sandfort.services import volume_restore_recovery as recovery
from sandfort.services.transfer_slots import TransferSlots
from sandfort.services.volumes import RESTORE_ACTION, VolumeService, unrecovered_restore_conflict

logger = logging.getLogger(__name__)

EXPORT_ACTION = "volume.export"
RESTORE_IN_PROGRESS = "restore_in_progress"
GZIP_WBITS = 16 + zlib.MAX_WBITS
OUTPUT_STEP_BYTES = 1024 * 1024  # most bytes one decompress call may return
# A restore may expand to at most EXPANSION_RATIO times its compressed size, whatever the volume
# size limit says (a limit of 0 means none): 256 MiB of gzipped zeros is about 256 GiB of tar.
# Never less than EXPANSION_FLOOR_BYTES, because a small archive is padded to 10 KiB records and
# compresses far better than the ratio. The size of reference is the declared Content-Length,
# or the bytes received so far when the body has none (chunked).
# A body is one gzip stream, or a few members in a row (pigz, concatenated parts). A flood of
# 20-byte empty members costs CPU per member and no output, which the ratio cannot bound.
MAX_GZIP_MEMBERS = 1000
EXPANSION_RATIO = 64
EXPANSION_FLOOR_BYTES = 16 * 1024 * 1024
MAX_EXPORT_NAME_CHARS = 100
_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
FORBIDDEN_ENTRY = "forbidden_entry"  # ``details.reason`` of a 422 for a member the policy refuses
EMPTIED_NOTE = "the volume was emptied"
NOT_EMPTIED_NOTE = "the volume could not be emptied and may hold part of the archive"


class TransferClaims:
    """The volumes with a restore running in this process."""

    def __init__(self) -> None:
        self._held: set[str] = set()

    def try_claim(self, volume_id: str) -> bool:
        if volume_id in self._held:
            return False
        self._held.add(volume_id)
        return True

    def release(self, volume_id: str) -> None:
        self._held.discard(volume_id)

    def __contains__(self, volume_id: object) -> bool:
        return volume_id in self._held


@dataclass(slots=True)
class Tally:
    """Decompressed bytes counted as they pass."""

    bytes: int = 0


@dataclass(frozen=True, slots=True)
class Limits:
    """What the request says about the size of the compressed body."""

    max_upload_bytes: int
    declared_length: int | None = None


@dataclass(frozen=True, slots=True)
class VolumeExport:
    """An opened export: the file name to offer and the body, closed on any exit."""

    file_name: str
    body: AsyncIterator[bytes]


@dataclass(frozen=True, slots=True)
class RestoreResult:
    volume: Volume
    restored_bytes: int


@dataclass(slots=True)
class _Outcome:
    """What a failed restore reports about the state it left."""

    tally: Tally
    emptied: bool = field(default=False)


def archive_file_name(volume: Volume) -> str:
    """``<volume name>.tar.gz`` with only ``[A-Za-z0-9._-]``; the volume id when none is left."""
    stem = _UNSAFE_NAME_CHARS.sub("-", volume.name).strip("-.")[:MAX_EXPORT_NAME_CHARS]
    return f"{stem or volume.id}.tar.gz"


def too_expanded(limit: int) -> PayloadTooLarge:
    return PayloadTooLarge(
        f"the archive expands to more than {EXPANSION_RATIO} times its compressed size "
        f"(over {limit} bytes)",
        details={"limit_bytes": limit, "max_expansion_ratio": EXPANSION_RATIO},
    )


def too_big_for_volume(limit: int) -> PayloadTooLarge:
    return PayloadTooLarge(
        f"the archive holds more than the volume size limit of {limit} bytes",
        details={"limit_bytes": limit},
    )


async def gunzip_counted(
    source: AsyncIterator[bytes],
    tally: Tally,
    *,
    max_input: int,
    max_output: int | None,
    declared_length: int | None = None,
    expansion_ratio: int | None = None,
) -> AsyncIterator[bytes]:
    """The decompressed bytes of a gzip stream, counted in ``tally``, never held whole.

    Raises ``PayloadTooLarge`` when the compressed bytes pass ``max_input`` or the decompressed
    ones pass ``max_output`` (``None`` = no limit) or, with ``expansion_ratio``, that many times
    the compressed size (``declared_length``, or the bytes received so far; never under
    ``EXPANSION_FLOOR_BYTES``), and ``Unprocessable`` for an empty body, a
    stream that is not gzip, is corrupt or is cut short, and for one holding no data. Several
    gzip members in a row (at most ``MAX_GZIP_MEMBERS``) are read as one stream.
    """
    received = 0
    members = 1
    decoder = zlib.decompressobj(GZIP_WBITS)
    try:
        async for chunk in source:
            await anyio.lowlevel.checkpoint()  # a big body must not hold the event loop
            received += len(chunk)
            if received > max_input:
                raise upload_limit_error(max_input, received, at_least=True)
            pending = chunk
            while pending:
                if decoder.eof:  # the next gzip member
                    members += 1
                    if members > MAX_GZIP_MEMBERS:
                        raise Unprocessable(
                            f"the body holds more than {MAX_GZIP_MEMBERS} gzip members; "
                            "send one gzipped tar"
                        )
                    decoder = zlib.decompressobj(GZIP_WBITS)
                piece = decoder.decompress(pending, OUTPUT_STEP_BYTES)
                pending = decoder.unused_data if decoder.eof else decoder.unconsumed_tail
                tally.bytes += len(piece)
                if max_output is not None and tally.bytes > max_output:
                    raise too_big_for_volume(max_output)
                if expansion_ratio is not None:
                    basis = received if declared_length is None else declared_length
                    allowed = max(EXPANSION_FLOOR_BYTES, expansion_ratio * basis)
                    if tally.bytes > allowed:
                        raise too_expanded(allowed)
                if piece:
                    yield piece
    except zlib.error as exc:
        raise Unprocessable("the body is not a valid gzip stream") from exc
    if received == 0:
        raise Unprocessable("the request body is empty; send a gzipped tar")
    if not decoder.eof:
        raise Unprocessable("the gzip stream is cut short")
    if tally.bytes == 0:
        raise Unprocessable("the gzip stream holds no data; send a gzipped tar")


async def _chained(
    first: bytes, rest: AsyncIterator[bytes], release: Callable[[], None] | None = None
) -> AsyncIterator[bytes]:
    """``first`` (when not empty) and then ``rest``; ``rest`` is closed, and ``release`` called,
    on any exit."""
    try:
        if first:
            yield first
        async for chunk in rest:
            yield chunk
    finally:
        try:
            close = getattr(rest, "aclose", None)
            if close is not None:
                await close()
        finally:
            if release is not None:
                release()


def _annotated(exc: BaseException, emptied: bool) -> BaseException:
    """``exc`` as the API answers it after the driver began: an unreadable archive becomes a 422
    and every 413 or 422 names the state the volume was left in."""
    if isinstance(exc, DriverForbiddenEntry):
        exc = Unprocessable(
            exc.message,
            details={"reason": FORBIDDEN_ENTRY, "violation": exc.violation, "entry": exc.entry},
        )
    elif isinstance(exc, DriverInvalidArchive):
        exc = Unprocessable("the archive is not a readable tar")
    if not isinstance(exc, PayloadTooLarge | Unprocessable):
        return exc
    note = EMPTIED_NOTE if emptied else NOT_EMPTIED_NOTE
    details = {**exc.details, "volume_emptied": emptied}
    return type(exc)(f"{exc.message}; {note}", details=details)


class VolumeTransfer:
    """Export and restore for the volume routes; ``driver`` is the instrumented driver."""

    def __init__(
        self,
        volumes: VolumeService,
        driver: SandboxDriver,
        slots: TransferSlots | None = None,
        faults: tuple[str, ...] = (),
    ) -> None:
        self._volumes = volumes
        self.driver: object = driver
        self._faults = faults  # ``SANDFORT_FAULT_INJECTION`` names (test hooks)
        self.claims = TransferClaims()
        self.slots = TransferSlots() if slots is None else slots

    def _transfer_driver(self) -> VolumeTransferDriver:
        driver = self.driver
        if not isinstance(driver, VolumeTransferDriver):
            raise Conflict("this driver cannot export or restore volumes", reason=UNSUPPORTED_MODE)
        return driver

    # -- export ----------------------------------------------------------------

    async def open_export(self, org_id: str, actor_id: str | None, volume_id: str) -> VolumeExport:
        transfer = self._transfer_driver()
        volume = await self._volumes.authorize_transfer(org_id, volume_id, "exported")
        if volume_id in self.claims:
            raise _restore_running(volume_id)
        if volume.restoring_since is not None:  # a restore died here: it may hold part of one
            raise unrecovered_restore_conflict(volume_id)
        key = uuid.uuid4().hex
        self.slots.hold(org_id, key)  # held until the body is closed
        stream = transfer.export_volume(volume.provider_volume_name)
        try:
            # One chunk first, so a missing volume or a helper that cannot start is an error
            # answer, not a broken body.
            first = await anext(stream, b"")
            details = {"name": volume.name}
            await self._volumes.record_transfer(volume, actor_id, EXPORT_ACTION, details)
        except BaseException:
            with anyio.CancelScope(shield=True):
                try:
                    close = getattr(stream, "aclose", None)
                    if close is not None:
                        await close()
                finally:
                    self.slots.release(key)
            raise
        body = _chained(first, stream, lambda: self.slots.release(key))
        # a body that is never iterated never reaches its ``finally``: the slot still frees
        weakref.finalize(body, self.slots.release, key)
        return VolumeExport(archive_file_name(volume), body)

    # -- restore ---------------------------------------------------------------

    async def restore(
        self,
        org_id: str,
        actor_id: str | None,
        volume_id: str,
        body: AsyncIterator[bytes],
        *,
        max_upload_bytes: int,
        declared_length: int | None = None,
    ) -> RestoreResult:
        """Replace the volume's contents from the gzipped tar ``body`` (at most
        ``max_upload_bytes`` compressed; ``declared_length`` is its Content-Length, if any)."""
        transfer = self._transfer_driver()
        volume = await self._volumes.authorize_transfer(org_id, volume_id, "restored")
        if not self.claims.try_claim(volume_id):
            raise _restore_running(volume_id)
        key = uuid.uuid4().hex
        try:
            self.slots.hold(org_id, key)
            await self._volumes.refuse_if_mounted(org_id, volume_id)
            return await self._restore_claimed(
                transfer, volume, actor_id, body, Limits(max_upload_bytes, declared_length)
            )
        finally:
            self.slots.release(key)
            self.claims.release(volume_id)

    async def _restore_claimed(
        self,
        transfer: VolumeTransferDriver,
        volume: Volume,
        actor_id: str | None,
        body: AsyncIterator[bytes],
        limits: Limits,
    ) -> RestoreResult:
        tally = Tally()
        tar = gunzip_counted(
            body,
            tally,
            max_input=limits.max_upload_bytes,
            max_output=self._volumes.max_bytes,
            declared_length=limits.declared_length,
            expansion_ratio=EXPANSION_RATIO,
        )
        # The first decompressed chunk is read before anything is emptied: a body that is not
        # gzip is refused with the volume untouched.
        first = await anext(tar)
        # The marker is committed before the driver extracts anything and outlives a kill: the
        # next API start empties a volume that still carries it (``volume_restore_recovery``).
        await recovery.mark_restoring(self._volumes, volume)
        try:
            await transfer.restore_volume(volume.provider_volume_name, _chained(first, tar))
            await self._volumes.clear_restoring(volume)
        except BaseException as exc:
            outcome = _Outcome(tally)
            with anyio.CancelScope(shield=True):  # a dropped connection still empties the volume
                outcome.emptied = await recovery.abandon_restore(self._volumes, transfer, volume)
                await self._record_failure(volume, actor_id, exc, outcome)
            converted = _annotated(exc, outcome.emptied)
            if converted is exc:
                raise
            raise converted from exc
        await self._volumes.record_transfer(
            volume,
            actor_id,
            RESTORE_ACTION,
            {"name": volume.name, "restored_bytes": tally.bytes},
        )
        return RestoreResult(volume, tally.bytes)

    async def recover_interrupted(self) -> int:
        """Empty the volumes a crashed restore left marked (API start); markers cleared."""
        return await recovery.recover_interrupted_restores(self._volumes, self.driver, self._faults)

    async def _record_failure(
        self, volume: Volume, actor_id: str | None, exc: BaseException, outcome: _Outcome
    ) -> None:
        reason = exc.message if isinstance(exc, SandfortError | DriverError) else type(exc).__name__
        details = {
            "name": volume.name,
            "restored_bytes": outcome.tally.bytes,
            "reason": reason,
            "volume_emptied": outcome.emptied,
        }
        with suppress(Exception):  # the failure being answered matters more than its row
            await self._volumes.record_transfer(
                volume, actor_id, RESTORE_ACTION, details, ok=False
            )


def _restore_running(volume_id: str) -> Conflict:
    return Conflict(
        f"volume {volume_id} is being restored; try again when that is done",
        reason=RESTORE_IN_PROGRESS,
        details={"volume_id": volume_id},
    )
