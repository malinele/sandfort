"""``POST /internal/egress/v1/policies``: the policy channel the egress proxy reads.

Internal and out of the public spec (``include_in_schema=False``). The route does its own MAC
authentication under keys derived from ``SANDFORT_EGRESS_SECRET`` and uses no api-key
dependency: a missing or bad request MAC, a stale timestamp or an empty secret answers an
unsigned 401. Only a 200 carries ``X-Sandfort-Egress-Signature``, a MAC bound to the request
body hash and the response body, whose ``issued_at`` equals the signature timestamp. The hop is
plain HTTP on the private network: the MACs give integrity and freshness, not confidentiality.
The route is mounted only when ``SANDFORT_EGRESS_POLICY_ROUTE_ENABLED`` is set and the egress
secret is configured (``sandfort.api.app``), and it checks the header's form and freshness before
it reads the request body. The body is ``{"nonce": ..., "sandbox_ids": [...]}``: the client draws
a fresh nonce per request and the response MAC covers the request body hash, so a captured 200
answers no later request. The wire format lives in ``sandfort.egress.policy_wire``.
"""

import json
import time
from functools import partial

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from sandfort.api.deps import get_settings, get_uow
from sandfort.egress.policy_wire import (
    AUTH_HEADER,
    MAX_NONCE_CHARS,
    MAX_POLICY_IDS,
    POLICY_PATH,
    SIGNATURE_HEADER,
    header_is_fresh,
    nonce_is_valid,
    request_key,
    response_key,
    sign_response,
    verify_request,
)
from sandfort.errors import Unprocessable
from sandfort.services.egress_policy import read_policies

router = APIRouter(tags=["egress"])

_BAD_BODY = (
    f'body must be {{"nonce": "<base64url, at most {MAX_NONCE_CHARS} characters>", '
    f'"sandbox_ids": [...]}} with 1 to {MAX_POLICY_IDS} sandbox ids'
)


def _unauthorized() -> JSONResponse:
    return JSONResponse({"detail": "unauthorized"}, status_code=401)


def _sandbox_ids(body: bytes) -> list[str]:
    """The requested ids; ``Unprocessable`` unless the body is the documented object."""
    try:
        decoded = json.loads(body)
    except ValueError:
        raise Unprocessable(_BAD_BODY) from None
    if not isinstance(decoded, dict) or set(decoded) != {"sandbox_ids", "nonce"}:
        raise Unprocessable(_BAD_BODY)
    if not nonce_is_valid(decoded["nonce"]):
        raise Unprocessable(_BAD_BODY)
    ids = decoded["sandbox_ids"]
    if not isinstance(ids, list) or not 1 <= len(ids) <= MAX_POLICY_IDS:
        raise Unprocessable(_BAD_BODY)
    if not all(isinstance(item, str) and item for item in ids):
        raise Unprocessable(_BAD_BODY)
    return ids


@router.post(POLICY_PATH, include_in_schema=False)
async def egress_policies(request: Request) -> Response:
    """Answer the policies of the requested sandboxes, signed against the request body hash.

    An unsigned 401 for a missing secret, a missing, malformed or stale auth header or a bad
    request MAC (the header is checked before the body is read); 422 for a body that is not
    ``{"nonce", "sandbox_ids"}``; otherwise a 200 with ``X-Sandfort-Egress-Signature``.
    """
    secret = get_settings(request).egress_secret
    if not secret:
        return _unauthorized()
    now = int(time.time())
    if not header_is_fresh(request.headers.get(AUTH_HEADER), now):
        return _unauthorized()
    body = await request.body()
    if not verify_request(request_key(secret), request.headers.get(AUTH_HEADER), body, now):
        return _unauthorized()
    ids = _sandbox_ids(body)
    policies = await read_policies(partial(get_uow, request), ids)
    payload = json.dumps({"issued_at": now, "policies": policies}, separators=(",", ":")).encode()
    signature = sign_response(response_key(secret), body, payload, now)
    return Response(payload, media_type="application/json", headers={SIGNATURE_HEADER: signature})
