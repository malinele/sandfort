"""B28: failed authentications per client address, refused with 429 before the key lookup."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

import sandfort.auth.authenticate as authenticate_module
from sandfort.api.middleware import auth_failure_limit
from sandfort.api.middleware.auth_failure_limit import (
    AUTH_FAILURE_LIMITER_ATTR,
    AuthFailureLimiter,
    AuthFailureLimitMiddleware,
)
from sandfort.api.routes.scim import SCIM_PREFIX
from sandfort.auth.api_keys import parse_prefix
from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.routing.forward import FORWARDED_HEADER
from test_api_keys import KEYS, SANDBOX_SCOPES, SANDBOXES, T0, World, auth, open_world, seed_key

LIMIT = 3
BAD_KEY = "sf_live_aaaaaaaa_" + "x" * 43  # well formed, unknown prefix
SESSION_SECRET = "s" * 40
SCIM_USERS = "/scim/v2/Users"
SCIM_CONTENT_TYPE = "application/scim+json"
OTHER_ADDRESS = "198.51.100.9"
ENV_NAME = "SANDFORT_AUTH_FAILURE_LIMIT_PER_MINUTE"


@pytest.fixture
async def guarded(tmp_path: Path) -> AsyncIterator[World]:
    async with open_world(tmp_path, auth_failure_limit_per_minute=LIMIT) as opened:
        setattr(
            opened.app.state,
            AUTH_FAILURE_LIMITER_ATTR,
            AuthFailureLimiter(opened.clock, limit_per_minute=LIMIT),
        )
        yield opened


@pytest.fixture
async def scim_guarded(tmp_path: Path) -> AsyncIterator[World]:
    async with open_world(
        tmp_path,
        auth_failure_limit_per_minute=LIMIT,
        scim_enabled=True,
        session_secret=SESSION_SECRET,
    ) as opened:
        setattr(
            opened.app.state,
            AUTH_FAILURE_LIMITER_ATTR,
            AuthFailureLimiter(opened.clock, limit_per_minute=LIMIT),
        )
        yield opened


@asynccontextmanager
async def client_from(app: FastAPI, address: str) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=(address, 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def fail_up_to_the_limit(world: World) -> None:
    for _ in range(LIMIT):
        response = await world.client.get(SANDBOXES, headers=auth(BAD_KEY))
        assert response.status_code == 401


def middleware_classes(app: FastAPI) -> set[object]:
    return {middleware.cls for middleware in app.user_middleware}


async def test_default_settings_install_no_failure_limit(tmp_path: Path) -> None:
    assert Settings().auth_failure_limit_per_minute == 0

    async with open_world(tmp_path) as opened:
        assert getattr(opened.app.state, AUTH_FAILURE_LIMITER_ATTR, None) is None
        assert AuthFailureLimitMiddleware not in middleware_classes(opened.app)
        for _ in range(10):
            response = await opened.client.get(SANDBOXES, headers=auth(BAD_KEY))
            assert response.status_code == 401


async def test_a_configured_limit_installs_the_middleware(tmp_path: Path) -> None:
    async with open_world(tmp_path, auth_failure_limit_per_minute=5) as opened:
        limiter = getattr(opened.app.state, AUTH_FAILURE_LIMITER_ATTR)
        assert isinstance(limiter, AuthFailureLimiter)
        assert limiter.limit_per_minute == 5
        assert AuthFailureLimitMiddleware in middleware_classes(opened.app)


async def test_past_the_limit_the_answer_is_429_before_the_key_lookup(
    guarded: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed: list[str] = []

    def spy(key: str) -> str:
        parsed.append(key)
        return parse_prefix(key)

    monkeypatch.setattr(authenticate_module, "parse_prefix", spy)

    await fail_up_to_the_limit(guarded)
    looked_up = len(parsed)
    assert looked_up >= LIMIT

    response = await guarded.client.get(SANDBOXES, headers=auth(BAD_KEY))

    assert response.status_code == 429
    error = response.json()["error"]
    assert error["code"] == "RATE_LIMITED"
    assert error["message"] == auth_failure_limit.AUTH_FAILURES_LIMITED_MESSAGE
    assert error["details"] == {"retry_after_s": 60}
    assert response.headers["Retry-After"] == "60"
    assert error["request_id"] == response.headers["X-Request-Id"]
    assert len(parsed) == looked_up


async def test_a_scim_path_gets_a_scim_429_past_the_limit(scim_guarded: World) -> None:
    for _ in range(LIMIT):
        failed = await scim_guarded.client.get(SCIM_USERS, headers=auth(BAD_KEY))
        assert failed.status_code == 401
        assert failed.headers["content-type"].startswith(SCIM_CONTENT_TYPE)

    refused = await scim_guarded.client.get(SCIM_USERS, headers=auth(BAD_KEY))

    assert refused.status_code == 429
    assert refused.headers["content-type"].startswith(SCIM_CONTENT_TYPE)
    assert refused.json() == {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": "429",
        "detail": auth_failure_limit.AUTH_FAILURES_LIMITED_MESSAGE,
    }
    assert int(refused.headers["retry-after"]) >= 1


async def test_a_non_scim_path_keeps_the_native_429(guarded: World) -> None:
    await fail_up_to_the_limit(guarded)

    refused = await guarded.client.get(SANDBOXES, headers=auth(BAD_KEY))

    assert refused.status_code == 429
    assert refused.headers["content-type"].startswith("application/json")
    assert refused.json()["error"]["code"] == "RATE_LIMITED"


async def test_a_path_that_only_starts_with_the_scim_prefix_keeps_the_native_429(
    guarded: World,
) -> None:
    await fail_up_to_the_limit(guarded)

    refused = await guarded.client.get("/scim/v2x", headers=auth(BAD_KEY))

    assert refused.status_code == 429
    assert refused.headers["content-type"].startswith("application/json")
    assert refused.json()["error"]["code"] == "RATE_LIMITED"


def test_scim_path_prefix_matches_the_router() -> None:
    assert auth_failure_limit.SCIM_PATH_PREFIX == SCIM_PREFIX


async def test_the_window_ends_60_seconds_after_the_first_failure(guarded: World) -> None:
    key = await seed_key(guarded.app, guarded.org_id, SANDBOX_SCOPES)
    await fail_up_to_the_limit(guarded)

    guarded.clock.advance(timedelta(seconds=59))
    blocked = await guarded.client.get(SANDBOXES, headers=auth(key))
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"] == "1"

    guarded.clock.advance(timedelta(seconds=1))
    reopened = await guarded.client.get(SANDBOXES, headers=auth(key))
    assert reopened.status_code == 200


async def test_a_blocked_address_refuses_a_valid_key_and_other_addresses_pass(
    guarded: World,
) -> None:
    key = await seed_key(guarded.app, guarded.org_id, SANDBOX_SCOPES)
    await fail_up_to_the_limit(guarded)

    refused = await guarded.client.get(SANDBOXES, headers=auth(key))
    assert refused.status_code == 429

    async with client_from(guarded.app, OTHER_ADDRESS) as other:
        assert (await other.get(SANDBOXES, headers=auth(key))).status_code == 200
        assert (await other.get(SANDBOXES, headers=auth(BAD_KEY))).status_code == 401


async def test_requests_without_a_credential_are_neither_counted_nor_refused(
    guarded: World,
) -> None:
    key = await seed_key(guarded.app, guarded.org_id, SANDBOX_SCOPES)
    for _ in range(LIMIT * 2):
        assert (await guarded.client.get(SANDBOXES)).status_code == 401
    assert (await guarded.client.get(SANDBOXES, headers=auth(key))).status_code == 200

    await fail_up_to_the_limit(guarded)

    assert (await guarded.client.get(SANDBOXES)).status_code == 401
    assert (await guarded.client.get("/healthz")).status_code == 200


async def test_a_403_is_not_a_failed_authentication(guarded: World) -> None:
    key = await seed_key(guarded.app, guarded.org_id, SANDBOX_SCOPES)
    for _ in range(LIMIT * 2):
        assert (await guarded.client.get(KEYS, headers=auth(key))).status_code == 403

    assert (await guarded.client.get(SANDBOXES, headers=auth(key))).status_code == 200


def tiny_app(*, exempt_forwarded_hops: bool) -> Starlette:
    async def deny(request: Request) -> JSONResponse:
        return JSONResponse({"denied": True}, status_code=401)

    app = Starlette(routes=[Route("/probe", deny)])
    app.add_middleware(AuthFailureLimitMiddleware, exempt_forwarded_hops=exempt_forwarded_hops)
    setattr(
        app.state,
        AUTH_FAILURE_LIMITER_ATTR,
        AuthFailureLimiter(FrozenClock(T0), limit_per_minute=2),
    )
    return app


@pytest.mark.parametrize(
    ("exempt", "expected"),
    [(True, [401, 401, 401, 401]), (False, [401, 401, 429, 429])],
)
async def test_forwarded_hops_are_exempt_only_when_routing_is_on(
    exempt: bool, expected: list[int]
) -> None:
    transport = httpx.ASGITransport(app=tiny_app(exempt_forwarded_hops=exempt))
    headers = {"Authorization": "Bearer x", FORWARDED_HEADER: "1"}
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        statuses = [(await client.get("/probe", headers=headers)).status_code for _ in range(4)]

    assert statuses == expected


def test_a_clock_step_back_opens_a_new_window() -> None:
    clock = FrozenClock(T0)
    limiter = AuthFailureLimiter(clock, limit_per_minute=2)
    limiter.record_failure("10.0.0.1")
    limiter.record_failure("10.0.0.1")
    assert limiter.check("10.0.0.1").allowed is False

    clock.set(T0 - timedelta(seconds=1))

    assert limiter.check("10.0.0.1").allowed is True


def test_the_window_map_stays_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth_failure_limit, "MAX_BUCKETS", 4)
    monkeypatch.setattr(auth_failure_limit, "SWEEP_TARGET", 2)
    clock = FrozenClock(T0)
    limiter = AuthFailureLimiter(clock, limit_per_minute=1)

    for index in range(8):
        limiter.record_failure(f"10.0.0.{index}")
        clock.advance(timedelta(seconds=1))

    assert len(limiter._windows) <= 4
    assert "10.0.0.7" in limiter._windows
    assert "10.0.0.0" not in limiter._windows


def test_a_limit_below_one_is_refused() -> None:
    for bad in (0, -1):
        with pytest.raises(ValueError, match="at least 1 per minute"):
            AuthFailureLimiter(FrozenClock(T0), limit_per_minute=bad)


def test_the_limit_comes_from_the_environment() -> None:
    assert Settings.from_env({ENV_NAME: "30"}).auth_failure_limit_per_minute == 30
    assert Settings.from_env({}).auth_failure_limit_per_minute == 0
    with pytest.raises(ValueError, match=f"{ENV_NAME} must be 0 or more, got -1"):
        Settings.from_env({ENV_NAME: "-1"})
