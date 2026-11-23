"""Attempt bookkeeping for the webhook dispatcher: outcome, history entry, stored failure text.

An attempt ends as an ``AttemptOutcome``: the HTTP status when one came back, otherwise the
short reason chosen by ``webhooks.delivery.classify_failure``. ``failure_text`` turns an outcome
into the sanitised text stored as ``last_error`` and in the history entry: ``None`` for a 2xx,
``http <status>`` for any other status, the transport reason otherwise, at most
``MAX_ERROR_CHARS`` characters. Nothing here ever sees the URL, a header, the body or exception
text. ``body_digest`` is the sha256 of the signed body; the body itself is never stored.
``parked_entry`` is the history entry (kind ``parked``) of a delivery parked because its
endpoint is gone or disabled; its error text is also the delivery's ``last_error``.
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sandfort.webhooks.delivery import MAX_ERROR_CHARS

SUCCESS_STATUSES = range(200, 300)
ATTEMPT_KIND = "attempt"
PARKED_KIND = "parked"
PARKED_ERROR = "endpoint disabled"  # last_error and entry error of a parked delivery
EVENT_MISSING_ERROR = "event missing"


@dataclass(frozen=True, slots=True)
class AttemptOutcome:
    status: int | None  # None when no HTTP status came back
    error: str | None  # transport reason when status is None
    ms: int  # duration of the attempt in milliseconds

    @property
    def success(self) -> bool:
        return self.status in SUCCESS_STATUSES


def failure_text(outcome: AttemptOutcome) -> str | None:
    """The sanitised failure text of ``outcome``; ``None`` when the attempt succeeded."""
    if outcome.success:
        return None
    text = f"http {outcome.status}" if outcome.status is not None else outcome.error
    return (text or "unknown")[:MAX_ERROR_CHARS]


def attempt_entry(outcome: AttemptOutcome, attempted_at: datetime) -> dict[str, Any]:
    """The history entry of one attempt (JSON friendly: ISO time, status, error, duration)."""
    return {
        "kind": ATTEMPT_KIND,
        "attempted_at": attempted_at.isoformat(),
        "status": outcome.status,
        "error": failure_text(outcome),
        "duration_ms": outcome.ms,
    }


def parked_entry(parked_at: datetime, reason: str = PARKED_ERROR) -> dict[str, Any]:
    """The history entry of a delivery parked without an attempt (same keys as an attempt)."""
    return {
        "kind": PARKED_KIND,
        "attempted_at": parked_at.isoformat(),
        "status": None,
        "error": reason,
        "duration_ms": None,
    }


def body_digest(body: bytes) -> str:
    """Hex sha256 of the signed body."""
    return hashlib.sha256(body).hexdigest()
