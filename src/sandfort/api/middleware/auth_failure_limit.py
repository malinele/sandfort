"""Optional pre-authentication limit on failed authentications per client address (B28).

A bad key always costs a key lookup and an HMAC, and nothing answers 429 for it: the per-key
limiter runs after ``authenticate``. This middleware counts the 401 answers to requests that
carry an ``Authorization`` header, per client address (``scope["client"][0]``, else
``UNKNOWN_PEER``), in a fixed 60 second window that opens at the first failure. Once an address
has ``limit_per_minute`` failures in its open window, every http request from it that carries an
``Authorization`` header answers 429 ``RATE_LIMITED`` with ``Retry-After`` (the whole seconds
left in the window, at least 1) before any key lookup, a valid key included. Requests without
the header pass untouched and are never counted, because they cost no lookup. A 403, a 429 and
every other status are not failures, and websockets are untouched. The count is taken from the
responses, so requests already in flight when the limit is reached still finish.

A 401 response is the one signal that covers API keys, session tokens and SCIM tokens, and an
ASGI middleware sees every request before routing, the toolbox activity touch and the routing
forwarder, so no dependency or ``authenticate`` has to change. With cross-node routing on, a
request that carries the forwarded header passes untouched: the route guard checks it by HMAC
and the node that received the request counted the caller from the relayed 401. With routing
off the header grants nothing, so it is not exempt.

The limit is off unless ``SANDFORT_AUTH_FAILURE_LIMIT_PER_MINUTE`` is above 0. Behind a proxy
that uvicorn does not trust for ``X-Forwarded-For``, every client has the proxy's address, and
one client with a bad key would lock out all the others, so an operator must choose it. No
audit row is written (no org is known and ``RATE_LIMITED`` is never audited) and there is no
new metric: this middleware sits inside the telemetry middleware, which already counts the 429
answers by status. On SCIM paths the refusal is a SCIM Error body, as every other SCIM error.
"""

import math
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from fastapi import FastAPI
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sandfort.api.errors import REQUEST_ID_ATTR, error_response
from sandfort.api.middleware.rate_limit import (
    ALLOWED,
    MAX_BUCKETS,
    SWEEP_TARGET,
    UNKNOWN_PEER,
    RateDecision,
)
from sandfort.api.safe_json import SafeJSONResponse
from sandfort.api.scim.errors import describe_failure
from sandfort.api.scim.resources import SCIM_MEDIA_TYPE
from sandfort.clock import Clock, SystemClock
from sandfort.errors import RateLimited
from sandfort.routing.forward import FORWARDED_HEADER

AUTH_FAILURE_LIMITER_ATTR = "auth_failure_limiter"
AUTH_FAILURES_LIMITED_MESSAGE = "too many failed authentication attempts from this address"
FAILURE_WINDOW = timedelta(seconds=60)
UNAUTHORIZED_STATUS = 401
# Must equal SCIM_PREFIX in sandfort.api.routes.scim (a test pins it). The routes import this
# package, so the value is repeated here instead of imported.
SCIM_PATH_PREFIX: Final = "/scim/v2"


@dataclass(frozen=True, slots=True)
class _Window:
    started_at: datetime
    failures: int


class AuthFailureLimiter:
    """Failures per address in a fixed window that opens at the first failure."""

    def __init__(self, clock: Clock, *, limit_per_minute: int) -> None:
        if limit_per_minute < 1:
            raise ValueError(
                f"auth failure limit must be at least 1 per minute, got {limit_per_minute}"
            )
        self._clock = clock
        self._limit_per_minute = limit_per_minute
        self._windows: dict[str, _Window] = {}

    @property
    def limit_per_minute(self) -> int:
        return self._limit_per_minute

    def check(self, address: str) -> RateDecision:
        now = self._clock.now()
        window = self._current(address, now)
        if window is None or window.failures < self._limit_per_minute:
            return ALLOWED
        left_s = math.ceil((window.started_at + FAILURE_WINDOW - now).total_seconds())
        return RateDecision(allowed=False, retry_after_s=max(left_s, 1))

    def record_failure(self, address: str) -> None:
        now = self._clock.now()
        window = self._current(address, now)
        if window is None:
            self._windows[address] = _Window(started_at=now, failures=1)
        else:
            self._windows[address] = _Window(window.started_at, window.failures + 1)
        self._sweep()

    def _current(self, address: str, now: datetime) -> _Window | None:
        """The open window of ``address``, none once it ended (a clock step back ends it too)."""
        window = self._windows.get(address)
        if window is None or not window.started_at <= now < window.started_at + FAILURE_WINDOW:
            return None
        return window

    def _sweep(self) -> None:
        """Past ``MAX_BUCKETS``, keep only the ``SWEEP_TARGET`` newest windows."""
        if len(self._windows) <= MAX_BUCKETS:
            return
        newest = sorted(self._windows.items(), key=lambda item: item[1].started_at, reverse=True)
        self._windows = dict(newest[:SWEEP_TARGET])


def _counting(send: Send, limiter: AuthFailureLimiter, address: str) -> Send:
    """Wrap ``send`` so every 401 response start is recorded as a failure of ``address``."""

    async def counted(message: Message) -> None:
        if message["type"] == "http.response.start" and message["status"] == UNAUTHORIZED_STATUS:
            limiter.record_failure(address)
        await send(message)

    return counted


def _is_scim_path(path: str) -> bool:
    return path == SCIM_PATH_PREFIX or path.startswith(SCIM_PATH_PREFIX + "/")


def _scim_refusal(refusal: RateLimited) -> SafeJSONResponse:
    """The refusal as a SCIM Error body with its 429 status and ``Retry-After`` header."""
    failure = describe_failure(refusal)
    return SafeJSONResponse(
        content=failure.body(),
        status_code=failure.status,
        headers=dict(failure.headers),
        media_type=SCIM_MEDIA_TYPE,
    )


class AuthFailureLimitMiddleware:
    """Refuse a blocked address with 429 before any key lookup, and count 401 answers."""

    def __init__(self, app: ASGIApp, *, exempt_forwarded_hops: bool = False) -> None:
        self.app = app
        self._exempt_forwarded_hops = exempt_forwarded_hops

    def _limiter_for(self, scope: Scope) -> AuthFailureLimiter | None:
        if scope["type"] != "http":
            return None
        headers = Headers(scope=scope)
        if "authorization" not in headers:
            return None
        if self._exempt_forwarded_hops and FORWARDED_HEADER in headers:
            return None
        limiter: AuthFailureLimiter | None = getattr(
            scope["app"].state, AUTH_FAILURE_LIMITER_ATTR, None
        )
        return limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        limiter = self._limiter_for(scope)
        if limiter is None:
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        address = str(client[0]) if client else UNKNOWN_PEER
        decision = limiter.check(address)
        if decision.allowed:
            await self.app(scope, receive, _counting(send, limiter, address))
            return
        refusal = RateLimited(
            AUTH_FAILURES_LIMITED_MESSAGE,
            retry_after_s=decision.retry_after_s,
            details={"retry_after_s": decision.retry_after_s},
        )
        if _is_scim_path(str(scope.get("path", ""))):
            await _scim_refusal(refusal)(scope, receive, send)
            return
        request_id = scope.get("state", {}).get(REQUEST_ID_ATTR)
        await error_response(refusal, request_id=request_id)(scope, receive, send)


def install_auth_failure_limit(
    app: FastAPI, limit_per_minute: int, *, exempt_forwarded_hops: bool
) -> None:
    """Count failed authentications per client address and refuse past ``limit_per_minute``."""
    setattr(
        app.state,
        AUTH_FAILURE_LIMITER_ATTR,
        AuthFailureLimiter(SystemClock(), limit_per_minute=limit_per_minute),
    )
    app.add_middleware(AuthFailureLimitMiddleware, exempt_forwarded_hops=exempt_forwarded_hops)
