"""Audit recording and the redaction rules for audit details (WP 1.6).

``AuditRecorder`` writes one row through the caller's unit of work and never commits:
the row lands atomically with the state change the caller commits. Details are a
sanitized projection of the request, never the request itself:

* ``env`` mappings keep only the sorted key names and a ``value_count``.
* ``stdin``, ``code``, ``command``, ``args``, ``cmd`` and ``token`` keep only a
  ``redacted-sha256:`` digest and the byte length of the value.
* every other scalar passes through; nested dicts (and dicts inside lists) are
  sanitized recursively with the same rules.
"""

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType, AuditEvent, AuditOutcome
from sandfort.ids import AUDIT, new_id
from sandfort.services.audit_chain import link_hash, successor_id

MAX_COMMAND_CHARS = 512
DIGEST_PREFIX = "redacted-sha256:"
ENV_KEY = "env"
DIGESTED_KEYS = frozenset({"stdin", "code", "command", "args", "cmd", "token"})


def _digest(value: Any) -> dict[str, Any]:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode()
    else:
        raw = json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()
    return {"sha256": DIGEST_PREFIX + hashlib.sha256(raw).hexdigest(), "length": len(raw)}


def _env_summary(env: Mapping[Any, Any]) -> dict[str, Any]:
    return {"keys": sorted(str(name) for name in env), "value_count": len(env)}


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return redact_details(value)
    if isinstance(value, list | tuple):
        return [_sanitize_value(item) for item in value]
    return value


def redact_details(details: Mapping[str, Any]) -> dict[str, Any]:
    """Return the sanitized projection of ``details``; the input is never modified."""
    result: dict[str, Any] = {}
    for key, value in details.items():
        name = str(key).lower()
        if value is None:
            result[key] = None
        elif name == ENV_KEY and isinstance(value, Mapping):
            result[key] = _env_summary(value)
        elif name in DIGESTED_KEYS:
            result[key] = _digest(value)
        else:
            result[key] = _sanitize_value(value)
    return result


class AuditRecorder:
    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    async def record(
        self,
        uow: UnitOfWorkPort,
        *,
        org_id: str,
        actor_type: ActorType,
        actor_id: str | None,
        action: str,
        target_type: str | None = None,
        target_id: str | None = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        request_id: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> AuditEvent:
        """Add one audit row to ``uow`` (the caller commits); ``details`` is redacted here.

        The row is chained to the org's newest row in the same unit of work (WP 5.5).
        """
        head = await uow.audit.latest_link(org_id)
        event_id = new_id(AUDIT)
        if head is not None and event_id <= head.id:
            event_id = successor_id(head.id)
        event = AuditEvent(
            id=event_id,
            org_id=org_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            request_id=request_id,
            ip=ip,
            user_agent=user_agent,
            details=redact_details(details or {}),
            occurred_at=self._clock.now(),
        )
        prev_hash = None if head is None else head.entry_hash
        await uow.audit.add(event, prev_hash=prev_hash, entry_hash=link_hash(prev_hash, event))
        return event
