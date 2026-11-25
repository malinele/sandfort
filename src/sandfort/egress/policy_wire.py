"""Wire format of the internal egress policy route (docs/egress-v2-design.md section 3.6).

The proxy asks an api instance for the policy of the sandboxes it serves: ``POST
/internal/egress/v1/policies`` with ``{"nonce": "...", "sandbox_ids": [...]}`` (1 to 256 ids and
a per-request nonce, see ``encode_policy_request``). Request and
response each carry an HMAC header, ``t=<unix>,s=<unpadded base64url>``, under a key derived
from ``SANDFORT_EGRESS_SECRET`` (one key per use, so a v1 token key, a v2 token key and the two
message keys never coincide). The MACs give integrity and freshness (``MAC_WINDOW_S``), not
confidentiality. ``verify_response`` never raises: anything that does not verify is simply
false, and the proxy then treats the policy as unavailable. This module holds no I/O, so the
server route of a later round imports the same names.
"""

import base64
import binascii
import hashlib
import hmac
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

POLICY_PATH = "/internal/egress/v1/policies"
MAX_POLICY_IDS = 256
AUTH_HEADER = "X-Sandfort-Egress-Auth"
SIGNATURE_HEADER = "X-Sandfort-Egress-Signature"
MAC_WINDOW_S = 30
MAX_NONCE_CHARS = 64
TOKEN_V2_LABEL = "sandfort/egress/token/v2"
REQUEST_LABEL = "sandfort/egress/policy/request/v1"
RESPONSE_LABEL = "sandfort/egress/policy/response/v1"

_B64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]+")
_HEADER_PATTERN = re.compile(r"t=([0-9]{1,15}),s=([A-Za-z0-9_-]+)")


def _derive(secret: str, label: str) -> bytes:
    return hmac.new(secret.encode(), label.encode(), hashlib.sha256).digest()


def token_v2_key(secret: str) -> bytes:
    """Key that signs ``sfe2_`` tokens."""
    return _derive(secret, TOKEN_V2_LABEL)


def request_key(secret: str) -> bytes:
    """Key that signs requests to the policy route."""
    return _derive(secret, REQUEST_LABEL)


def response_key(secret: str) -> bytes:
    """Key that signs responses of the policy route."""
    return _derive(secret, RESPONSE_LABEL)


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes | None:
    """The bytes of a canonical unpadded base64url string, or ``None`` for any other spelling."""
    if _B64URL_PATTERN.fullmatch(text) is None:
        return None
    try:
        decoded = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None
    return decoded if _b64encode(decoded) == text else None


def _mac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("ascii"), hashlib.sha256).digest()


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def nonce_is_valid(nonce: object) -> bool:
    """True for a non-empty base64url string of at most ``MAX_NONCE_CHARS`` characters."""
    return (
        isinstance(nonce, str)
        and len(nonce) <= MAX_NONCE_CHARS
        and _B64URL_PATTERN.fullmatch(nonce) is not None
    )


def encode_policy_request(sandbox_ids: Sequence[str], nonce: str) -> bytes:
    """The request body for ``sandbox_ids`` and a per-request ``nonce``.

    The body is compact JSON with a fixed key order, ``nonce`` first and ``sandbox_ids`` second:
    ``{"nonce":"<nonce>","sandbox_ids":["sbx_1",...]}``. The client draws a fresh random nonce
    for every request, so two requests for the same ids never share a body, and the response MAC
    (which covers the request body hash) binds each signed answer to one request instance.
    ``ValueError`` outside 1..``MAX_POLICY_IDS`` ids or for a nonce that is not a non-empty
    base64url string of at most ``MAX_NONCE_CHARS`` characters.
    """
    if not 1 <= len(sandbox_ids) <= MAX_POLICY_IDS:
        raise ValueError(f"a policy request carries 1 to {MAX_POLICY_IDS} sandbox ids")
    if not nonce_is_valid(nonce):
        raise ValueError(f"a policy request nonce is 1 to {MAX_NONCE_CHARS} base64url characters")
    payload = {"nonce": nonce, "sandbox_ids": list(sandbox_ids)}
    return json.dumps(payload, separators=(",", ":")).encode()


def sign_request(key: bytes, body: bytes, now: int) -> str:
    """The ``X-Sandfort-Egress-Auth`` value for a request ``body`` sent at unix time ``now``."""
    message = f"POST\n{POLICY_PATH}\n{now}\n{_digest(body)}"
    return f"t={now},s={_b64encode(_mac(key, message))}"


def sign_response(key: bytes, request_body: bytes, body: bytes, now: int) -> str:
    """The ``X-Sandfort-Egress-Signature`` value for a response ``body`` made at ``now``.

    The MAC binds the response to the request it answers:
    ``"<t>\\n<hex sha256 of request body>\\n<hex sha256 of response body>"``.
    """
    message = f"{now}\n{_digest(request_body)}\n{_digest(body)}"
    return f"t={now},s={_b64encode(_mac(key, message))}"


def _fresh_mac(header: str | None, now: int) -> tuple[int, bytes] | None:
    """``(stamp, mac bytes)`` of a well-formed header inside the freshness window, else ``None``."""
    if header is None:
        return None
    match = _HEADER_PATTERN.fullmatch(header.strip())
    if match is None:
        return None
    stamp = int(match.group(1))
    if abs(now - stamp) > MAC_WINDOW_S:
        return None
    given = _b64decode(match.group(2))
    return None if given is None else (stamp, given)


def header_is_fresh(header: str | None, now: int) -> bool:
    """True for a present, well-formed header whose timestamp is inside ``MAC_WINDOW_S`` of ``now``.

    The MAC itself is not checked: the route uses this to refuse a stale or malformed header
    before it reads the request body, and ``verify_request`` still decides authenticity.
    """
    return _fresh_mac(header, now) is not None


def _issued_at_is(body: bytes, stamp: int) -> bool:
    try:
        decoded = json.loads(body)
    except ValueError:
        return False
    if not isinstance(decoded, dict):
        return False
    issued_at = decoded.get("issued_at")
    return isinstance(issued_at, int) and not isinstance(issued_at, bool) and issued_at == stamp


def verify_response(
    key: bytes, header: str | None, request_body: bytes, body: bytes, now: int
) -> bool:
    """True only for a fresh header whose MAC covers exactly ``request_body`` and ``body``.

    The response body's ``issued_at`` must also equal the header timestamp.
    """
    parsed = _fresh_mac(header, now)
    if parsed is None:
        return False
    stamp, given = parsed
    expected = _mac(key, f"{stamp}\n{_digest(request_body)}\n{_digest(body)}")
    return hmac.compare_digest(expected, given) and _issued_at_is(body, stamp)


def verify_request(key: bytes, header: str | None, body: bytes, now: int) -> bool:
    """True only for a well-formed, fresh header whose MAC covers exactly the request ``body``."""
    parsed = _fresh_mac(header, now)
    if parsed is None:
        return False
    stamp, given = parsed
    message = f"POST\n{POLICY_PATH}\n{stamp}\n{_digest(body)}"
    return hmac.compare_digest(_mac(key, message), given)


@dataclass(frozen=True, slots=True)
class PolicyRecord:
    """The policy of one sandbox as the route reports it."""

    sandbox_id: str
    found: bool
    generation: int = 0
    epoch: int = 0
    rules: tuple[str, ...] = ()


def _whole_number(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("expected a non-negative integer")
    return value


def _record(raw: object) -> PolicyRecord:
    if not isinstance(raw, dict):
        raise ValueError("policy record must be an object")
    sandbox_id: Any = raw.get("sandbox_id")
    found: Any = raw.get("found")
    if not isinstance(sandbox_id, str) or not sandbox_id or not isinstance(found, bool):
        raise ValueError("policy record needs a sandbox_id and a boolean found")
    if not found:
        return PolicyRecord(sandbox_id=sandbox_id, found=False)
    rules = raw.get("rules")
    if not isinstance(rules, list) or not all(isinstance(rule, str) for rule in rules):
        raise ValueError("rules must be a list of strings")
    return PolicyRecord(
        sandbox_id=sandbox_id,
        found=True,
        generation=_whole_number(raw.get("generation")),
        epoch=_whole_number(raw.get("epoch")),
        rules=tuple(rules),
    )


def parse_policy_response(body: bytes) -> tuple[int, dict[str, PolicyRecord]]:
    """``(issued_at, records by sandbox id)``; ``ValueError`` on anything malformed."""
    try:
        decoded = json.loads(body)
    except ValueError:  # JSONDecodeError and UnicodeDecodeError
        raise ValueError("policy response is not JSON") from None
    if not isinstance(decoded, dict):
        raise ValueError("policy response must be an object")
    policies = decoded.get("policies")
    if not isinstance(policies, list):
        raise ValueError("policies must be a list")
    issued_at = _whole_number(decoded.get("issued_at"))
    records = [_record(raw) for raw in policies]
    return issued_at, {record.sandbox_id: record for record in records}
