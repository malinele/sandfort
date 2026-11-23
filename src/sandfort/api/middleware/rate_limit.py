"""Per-key token-bucket rate limiting behind the ``RateLimiter`` protocol (WP 4.4).

``install_rate_limit`` applies the limiter to an API application by overriding its
``authenticate`` dependency: the override authenticates first (a missing or bad key is still
a 401 and never touches a bucket), then takes one token from the caller's bucket and answers
429 ``RATE_LIMITED`` with a whole-second ``Retry-After`` when the bucket is empty. Every
``require_scopes`` dependency resolves ``authenticate``, so the limit covers each authenticated
route of the app (mounted or not) and runs before the scope check. Routes that never
authenticate (``/healthz``, ``/readyz``, the token-authorized PTY websocket) are exempt.

``TokenBucketRateLimiter`` keeps one bucket per key in process memory: ``burst`` tokens
when full, refilled at ``refill_per_s`` tokens per second of the injected clock. ``acquire``
never awaits between reading and writing a bucket, so it is atomic on the event loop. The
authenticated limiter keys on the user id when the principal has one (every session of a user
shares a bucket) and on the key id otherwise. When the map outgrows ``MAX_BUCKETS`` the least
recently used buckets are dropped down to ``SWEEP_TARGET``, so memory stays bounded.

``ExchangeRateLimitMiddleware`` is the pre-authentication limiter for the sign-on exchange
route: one bucket per connection peer address (never a forwarded header).
"""

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from fastapi import FastAPI, Request
from starlette.types import ASGIApp, Receive, Scope, Send

from sandfort.api.errors import REQUEST_ID_ATTR, error_response
from sandfort.auth.authenticate import authenticate
from sandfort.auth.principal import Principal
from sandfort.clock import Clock, SystemClock
from sandfort.errors import InternalError, RateLimited

RATE_LIMITER_ATTR = "rate_limiter"
EXCHANGE_LIMITER_ATTR = "exchange_rate_limiter"
RATE_LIMITED_MESSAGE = "rate limit exceeded for this API key"
EXCHANGE_LIMITED_MESSAGE = "too many sign-on exchange requests from this address"
MAX_BUCKETS = 10_000  # sweep when a limiter holds more buckets than this
SWEEP_TARGET = MAX_BUCKETS // 2  # ... and keep this many, the most recently used
EXCHANGE_PATH = "/v1/auth/sso/exchange"
EXCHANGE_REFILL_PER_S = 1  # sustained exchanges per second per client address
EXCHANGE_BURST = 10  # back-to-back exchanges one client address may make
UNKNOWN_PEER = "unknown"


@dataclass(frozen=True, slots=True)
class RateDecision:
    """``allowed``, or the whole seconds to wait before the next request can pass."""

    allowed: bool
    retry_after_s: int = 0


ALLOWED = RateDecision(allowed=True)


class RateLimiter(Protocol):
    async def acquire(self, key_id: str) -> RateDecision: ...


@dataclass(frozen=True, slots=True)
class _Bucket:
    tokens: float
    updated_at: datetime


class TokenBucketRateLimiter:
    def __init__(self, clock: Clock, *, refill_per_s: int, burst: int) -> None:
        if refill_per_s < 1:
            raise ValueError(f"rate limit refill must be at least 1/s, got {refill_per_s}")
        if burst < 1:
            raise ValueError(f"rate limit burst must be at least 1, got {burst}")
        self._clock = clock
        self._refill_per_s = refill_per_s
        self._burst = burst
        self._buckets: dict[str, _Bucket] = {}

    async def acquire(self, key_id: str) -> RateDecision:
        now = self._clock.now()
        tokens = self._available(self._buckets.get(key_id), now)
        if tokens >= 1:
            self._buckets[key_id] = _Bucket(tokens=tokens - 1, updated_at=now)
            self._sweep()
            return ALLOWED
        self._buckets[key_id] = _Bucket(tokens=tokens, updated_at=now)
        self._sweep()
        wait_s = math.ceil((1 - tokens) / self._refill_per_s)
        return RateDecision(allowed=False, retry_after_s=max(wait_s, 1))

    def _sweep(self) -> None:
        """Past ``MAX_BUCKETS``, keep only the ``SWEEP_TARGET`` most recently used buckets."""
        if len(self._buckets) <= MAX_BUCKETS:
            return
        newest = sorted(self._buckets.items(), key=lambda item: item[1].updated_at, reverse=True)
        self._buckets = dict(newest[:SWEEP_TARGET])

    def _available(self, bucket: _Bucket | None, now: datetime) -> float:
        if bucket is None:
            return float(self._burst)
        elapsed_s = max((now - bucket.updated_at).total_seconds(), 0.0)  # a clock step back
        return min(float(self._burst), bucket.tokens + elapsed_s * self._refill_per_s)


async def rate_limited_authenticate(request: Request) -> Principal:
    """``authenticate``, then one token from the caller's bucket (429 when it is empty)."""
    principal = await authenticate(request)
    limiter: RateLimiter | None = getattr(request.app.state, RATE_LIMITER_ATTR, None)
    if limiter is None:
        raise InternalError("rate limiter is not configured")
    decision = await limiter.acquire(principal.user_id or principal.key_id)
    if not decision.allowed:
        raise RateLimited(
            RATE_LIMITED_MESSAGE,
            retry_after_s=decision.retry_after_s,
            details={"retry_after_s": decision.retry_after_s},
        )
    return principal


def install_rate_limit(app: FastAPI, limiter: RateLimiter) -> None:
    """Limit every authenticated request on ``app`` through ``limiter`` (replaceable later)."""
    setattr(app.state, RATE_LIMITER_ATTR, limiter)
    app.dependency_overrides[authenticate] = rate_limited_authenticate


class ExchangeRateLimitMiddleware:
    """Limit ``POST`` sign-on exchanges per peer address before any authentication work."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] != EXCHANGE_PATH:
            await self.app(scope, receive, send)
            return
        limiter: RateLimiter | None = getattr(scope["app"].state, EXCHANGE_LIMITER_ATTR, None)
        if limiter is None:
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        decision = await limiter.acquire(client[0] if client else UNKNOWN_PEER)
        if decision.allowed:
            await self.app(scope, receive, send)
            return
        refusal = RateLimited(
            EXCHANGE_LIMITED_MESSAGE,
            retry_after_s=decision.retry_after_s,
            details={"retry_after_s": decision.retry_after_s},
        )
        request_id = scope.get("state", {}).get(REQUEST_ID_ATTR)
        await error_response(refusal, request_id=request_id)(scope, receive, send)


def install_exchange_rate_limit(app: FastAPI, limiter: RateLimiter | None = None) -> None:
    """Guard only the sign-on exchange route (``limiter`` defaults to a per-address bucket)."""
    chosen = limiter or TokenBucketRateLimiter(
        SystemClock(), refill_per_s=EXCHANGE_REFILL_PER_S, burst=EXCHANGE_BURST
    )
    setattr(app.state, EXCHANGE_LIMITER_ATTR, chosen)
    app.add_middleware(ExchangeRateLimitMiddleware)
