"""Prefixed, time-sortable identifiers (``sbx_...``, ``org_...``).

Body = 10 chars of millisecond timestamp + 15 random chars, Crockford base32.
The body is 25 chars so the longest prefix (``snap_``) still fits the
``TEXT(30)`` primary-key width from the data model.
"""

import secrets
import time

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
TIME_CHARS = 10
RANDOM_CHARS = 15
BODY_LENGTH = TIME_CHARS + RANDOM_CHARS
MAX_ID_LENGTH = 30

SANDBOX = "sbx"
ORG = "org"
API_KEY = "key"
SNAPSHOT = "snap"
VOLUME = "vol"
JOB = "job"
EVENT = "evt"
WEBHOOK = "whk"
AUDIT = "aud"
SCIM_TOKEN = "stk"

PREFIXES = frozenset(
    {SANDBOX, ORG, API_KEY, SNAPSHOT, VOLUME, JOB, EVENT, WEBHOOK, AUDIT, SCIM_TOKEN}
)


def _encode_time(millis: int) -> str:
    chars = []
    for _ in range(TIME_CHARS):
        millis, digit = divmod(millis, len(ALPHABET))
        chars.append(ALPHABET[digit])
    return "".join(reversed(chars))


def new_id(prefix: str, *, now_ms: int | None = None) -> str:
    """Create ``<prefix>_<time><random>``; ids sort by creation time."""
    if prefix not in PREFIXES:
        raise ValueError(f"unknown id prefix: {prefix!r}")
    millis = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    suffix = "".join(secrets.choice(ALPHABET) for _ in range(RANDOM_CHARS))
    return f"{prefix}_{_encode_time(millis)}{suffix}"


def parse_id(value: str) -> tuple[str, str]:
    """Split an id into ``(prefix, body)``; raise ValueError if malformed."""
    prefix, sep, body = value.partition("_")
    if not sep or prefix not in PREFIXES:
        raise ValueError(f"malformed id: {value!r}")
    if len(body) != BODY_LENGTH or any(char not in ALPHABET for char in body):
        raise ValueError(f"malformed id: {value!r}")
    return prefix, body


def has_prefix(value: str, prefix: str) -> bool:
    try:
        return parse_id(value)[0] == prefix
    except ValueError:
        return False


def new_sandbox_id() -> str:
    return new_id(SANDBOX)


def new_org_id() -> str:
    return new_id(ORG)


def new_api_key_id() -> str:
    return new_id(API_KEY)


def new_snapshot_id() -> str:
    return new_id(SNAPSHOT)


def new_volume_id() -> str:
    return new_id(VOLUME)


def new_job_id() -> str:
    return new_id(JOB)


def new_event_id() -> str:
    return new_id(EVENT)


def new_scim_token_id() -> str:
    return new_id(SCIM_TOKEN)
