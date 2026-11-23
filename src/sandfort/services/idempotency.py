"""Idempotency keys for create requests (WP 4.6).

``begin`` either claims a key for a new request (``None``), replays the stored response of a
completed request with the same body hash, or raises ``IdempotencyMismatch`` when the key was
used with a different body. The in-flight claim lives in this process; the completed response
is stored with the entry (the repository has no update, so the entry is written once, at
completion) and expires a day later by the injected clock. Failed requests store nothing, so
the client may retry with the same key.
"""

import hashlib
import json
import logging
from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from pydantic import BaseModel

from sandfort.clock import Clock
from sandfort.db.repositories.ports import IdempotencyRecord, UnitOfWorkPort
from sandfort.errors import IN_PROGRESS, Conflict, IdempotencyMismatch, ValidationFailed

logger = logging.getLogger(__name__)

IDEMPOTENCY_TTL = timedelta(days=1)
MAX_KEY_LENGTH = 255
MAX_STORED_KEY_LENGTH = 255  # width of the ``idempotency_keys.key`` column


@dataclass(frozen=True, slots=True)
class StoredResponse:
    status: int
    body: dict[str, Any]


def canonical_body_hash(raw: bytes) -> str:
    """sha256 over the canonical JSON form (sorted keys, no whitespace); raw bytes otherwise."""
    try:
        parsed = json.loads(raw)
    except ValueError:
        payload = raw
    else:
        payload = json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def model_body_hash(operation: str, body: BaseModel) -> str:
    """sha256 over the canonical JSON of a validated request model and the operation it is for.

    The model is dumped with its defaults applied, so a request that spells a default out
    (``timeout_s`` 30 and ``30.0``, ``"env": {}``, ``"stdin": null``) hashes like one that
    leaves it out. ``operation`` (the route's path template) keeps two routes that take the
    same fields apart. The hash is stored in ``request_hash`` like the raw-body hash was;
    ``begin`` still accepts that older hash (``legacy_hashes``) for the records written before.
    """
    document = {"operation": operation, "body": body.model_dump(mode="json")}
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def storage_key(key_id: str | None, key: str) -> str:
    """The key under which a slot is stored: ``<api key id>:<idempotency key>``.

    The column is a single ``VARCHAR(255)`` (no migration), so a combination that does not fit
    keeps the key id and stores the sha256 of the idempotency key instead. Rows written before
    the key id was part of the slot never match a prefixed key; they expire after a day.
    """
    if key_id is None:
        return key
    combined = f"{key_id}:{key}"
    if len(combined) <= MAX_STORED_KEY_LENGTH:
        return combined
    return f"{key_id}:{hashlib.sha256(key.encode()).hexdigest()}"


class IdempotencyService:
    """Claims, replays and stores responses per ``(org, API key, Idempotency-Key)``.

    The slot belongs to the calling API key: another key sending the same ``Idempotency-Key``
    neither replays the first key's response, nor gets a mismatch error, nor waits on its
    in-flight request.
    """

    def __init__(self, uow_factory: Callable[[], UnitOfWorkPort], clock: Clock) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._in_flight: dict[tuple[str, str | None, str], str] = {}

    async def begin(
        self,
        org_id: str,
        key_id: str | None,
        key: str,
        request_hash: str,
        legacy_hashes: Collection[str] = (),
    ) -> StoredResponse | None:
        """Claim ``key`` (``None``) or return the stored response of its completed request.

        A stored record matches ``request_hash`` or any of ``legacy_hashes`` (the hash of the
        raw body, which records written before ``model_body_hash`` hold).
        """
        if not key or len(key) > MAX_KEY_LENGTH:
            raise ValidationFailed(f"Idempotency-Key must be 1 to {MAX_KEY_LENGTH} characters")
        slot = (org_id, key_id, key)
        held = self._in_flight.get(slot)
        if held is not None:
            if held != request_hash:
                raise IdempotencyMismatch("idempotency key was used with a different request")
            raise Conflict(
                "a request with this idempotency key is still in progress", reason=IN_PROGRESS
            )
        self._in_flight[slot] = request_hash
        try:
            record = await self._load(org_id, storage_key(key_id, key))
        except BaseException:
            self._in_flight.pop(slot, None)
            raise
        if record is None:
            return None
        self._in_flight.pop(slot, None)
        if record.request_hash != request_hash and record.request_hash not in legacy_hashes:
            raise IdempotencyMismatch("idempotency key was used with a different request")
        return StoredResponse(record.response_status, dict(record.response_body))

    async def complete(
        self,
        org_id: str,
        key_id: str | None,
        key: str,
        request_hash: str,
        status: int,
        body: dict[str, Any],
    ) -> None:
        """Store the response of the claimed request and release the claim."""
        record = IdempotencyRecord(
            org_id=org_id,
            key=storage_key(key_id, key),
            request_hash=request_hash,
            response_status=status,
            response_body=body,
            expires_at=self._clock.now() + IDEMPOTENCY_TTL,
        )
        try:
            async with self._uow_factory() as uow:
                await uow.idempotency.put(record)
                await uow.commit()
        except Conflict:
            logger.warning("idempotency key was recorded concurrently by another process")
        finally:
            self._in_flight.pop((org_id, key_id, key), None)

    def abandon(self, org_id: str, key_id: str | None, key: str) -> None:
        """Release the claim of a request that failed; nothing is stored."""
        self._in_flight.pop((org_id, key_id, key), None)

    async def _load(self, org_id: str, key: str) -> IdempotencyRecord | None:
        """The stored entry, or ``None`` when absent or expired (an expired one is purged)."""
        now = self._clock.now()
        async with self._uow_factory() as uow:
            record = await uow.idempotency.get(org_id, key)
            if record is not None and record.expires_at < now:
                await uow.idempotency.purge_expired(now)
                await uow.commit()
                return None
        return record
