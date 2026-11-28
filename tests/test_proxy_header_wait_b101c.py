"""Round 101c: the wait for an upstream's response headers frees its slot on a disconnect."""

import asyncio
from dataclasses import replace
from typing import Any

import httpx
import pytest
from tests.test_proxy import SETTINGS, TIMEOUT_S, World, call, error_code, host_for
from tests.test_proxy_caps_b33 import HoldingTransport, RawRequest, limited, status, until

from sandfort.config import Settings
from sandfort.proxy.app import create_proxy_app
from sandfort.proxy.limits import PreviewLimits

SLOW_S = 0.3


class SlowTransport(HoldingTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/slow":
            await asyncio.sleep(SLOW_S)
            return httpx.Response(200, stream=httpx.ByteStream(b"slow"))
        return await super().handle_async_request(request)


def bounded(world: World, client: httpx.AsyncClient, *, timeout_s: float) -> Any:
    settings = replace(
        SETTINGS,
        preview_max_concurrent_per_sandbox=1,
        preview_response_header_timeout_s=timeout_s,
    )
    return create_proxy_app(
        settings, tokens=world.tokens, lookup=world.lookup, driver=world.driver, http_client=client
    )


@pytest.fixture
def world() -> World:
    return World()


async def test_a_disconnect_before_the_headers_frees_the_slot(world: World) -> None:
    transport = HoldingTransport()
    async with httpx.AsyncClient(transport=transport) as client:
        host = host_for((await world.add(public=True)).id)
        proxy = limited(world, client, per_sandbox=1)
        request = RawRequest(proxy, host, "/hold")
        await until(lambda: transport.held == 1)
        busy = await status(proxy, host)

        request.gone.set()
        await until(lambda: proxy._limits.active() == 0)
        await asyncio.wait_for(request.task, TIMEOUT_S)
        after = await status(proxy, host)
        transport.release.set()

    assert busy == 503
    assert request.sent == []
    assert after == 200


async def test_a_body_request_without_headers_in_time_answers_502(world: World) -> None:
    transport = HoldingTransport()
    async with httpx.AsyncClient(transport=transport) as client:
        host = host_for((await world.add(public=True)).id)
        proxy = bounded(world, client, timeout_s=0.2)
        refused = await call(proxy, "POST", host, "/hold", content=b"payload")
        active = proxy._limits.active()
        after = await status(proxy, host)
        transport.release.set()

    assert transport.held == 1
    assert refused.status_code == 502
    assert error_code(refused) == "BAD_GATEWAY"
    assert active == 0
    assert after == 200


async def test_zero_waits_for_a_slow_upstream(world: World) -> None:
    async with httpx.AsyncClient(transport=SlowTransport()) as client:
        host = host_for((await world.add(public=True)).id)
        proxy = bounded(world, client, timeout_s=0)
        response = await call(proxy, "GET", host, "/slow")
        posted = await call(proxy, "POST", host, "/slow", content=b"payload")

    assert (response.status_code, response.text) == (200, "slow")
    assert (posted.status_code, posted.text) == (200, "slow")
    assert proxy._limits.active() == 0


def test_the_header_wait_defaults_to_300_and_loads_from_the_environment() -> None:
    loaded = Settings.from_env({"SANDFORT_PREVIEW_RESPONSE_HEADER_TIMEOUT_S": "2.5"})
    off = Settings.from_env({"SANDFORT_PREVIEW_RESPONSE_HEADER_TIMEOUT_S": "0"})

    limits = PreviewLimits.from_settings(loaded)

    assert Settings().preview_response_header_timeout_s == 300.0
    assert loaded.preview_response_header_timeout_s == 2.5
    assert off.preview_response_header_timeout_s == 0.0
    assert limits.header_timeout_s == 2.5
    assert PreviewLimits(1, 1).header_timeout_s == 0.0
    with pytest.raises(ValueError, match="PREVIEW_RESPONSE_HEADER_TIMEOUT_S"):
        Settings.from_env({"SANDFORT_PREVIEW_RESPONSE_HEADER_TIMEOUT_S": "-1"})
    with pytest.raises(ValueError):
        PreviewLimits(1, 1, header_timeout_s=-1.0)
