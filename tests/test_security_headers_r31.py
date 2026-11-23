"""Security headers: framing, referrer and CSP on JSON answers, HTML pages left alone.

Small apps carry the real middleware and the real exception handlers; the docs page test uses
the full ``create_app`` with the fake driver (``/docs`` touches no database).
"""

from collections.abc import AsyncIterator

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.responses import PlainTextResponse, StreamingResponse

from sandfort.api.app import create_app
from sandfort.api.errors import register_exception_handlers
from sandfort.api.security_headers import CONTENT_SECURITY_POLICY_VALUE, SecurityHeadersMiddleware
from sandfort.config import Settings

CSP = "content-security-policy"
EXPECTED_CSP = "default-src 'none'; frame-ancestors 'none'"
ROUTE_CSP = "default-src 'self'"


def build_app() -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/json")
    async def json_route() -> dict[str, str]:
        return {"ok": "yes"}

    @app.get("/problem")
    async def problem_route() -> JSONResponse:
        return JSONResponse({"type": "x"}, media_type="application/problem+json")

    @app.get("/empty", status_code=204)
    async def empty_route() -> None:
        return None

    @app.get("/page", response_class=HTMLResponse)
    async def page_route() -> str:
        return "<html></html>"

    @app.get("/text")
    async def text_route() -> PlainTextResponse:
        return PlainTextResponse("plain")

    @app.get("/own-policy")
    async def own_policy_route() -> JSONResponse:
        return JSONResponse({"ok": True}, headers={CSP: ROUTE_CSP, "X-Frame-Options": "SAMEORIGIN"})

    @app.get("/boom")
    async def boom_route() -> None:
        raise RuntimeError("secret detail")

    @app.get("/stream")
    async def stream_route() -> StreamingResponse:
        async def chunks() -> AsyncIterator[bytes]:
            for part in (b"a", b"b", b"c"):
                yield part

        return StreamingResponse(chunks(), media_type="text/event-stream")

    return app


async def fetch(app: FastAPI, path: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get(path)


def assert_fixed_headers(response: httpx.Response) -> None:
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"


async def test_a_json_answer_carries_all_four_headers() -> None:
    response = await fetch(build_app(), "/json")

    assert response.status_code == 200
    assert_fixed_headers(response)
    assert response.headers[CSP] == EXPECTED_CSP == CONTENT_SECURITY_POLICY_VALUE


async def test_a_plus_json_answer_carries_the_csp() -> None:
    response = await fetch(build_app(), "/problem")

    assert response.headers[CSP] == EXPECTED_CSP


async def test_an_empty_bodied_answer_carries_the_csp() -> None:
    response = await fetch(build_app(), "/empty")

    assert response.status_code == 204
    assert_fixed_headers(response)
    assert response.headers[CSP] == EXPECTED_CSP


async def test_a_404_carries_all_four_headers() -> None:
    response = await fetch(build_app(), "/missing")

    assert response.status_code == 404
    assert_fixed_headers(response)
    assert response.headers[CSP] == EXPECTED_CSP


async def test_a_500_from_the_shared_error_builder_carries_all_four_headers() -> None:
    response = await fetch(build_app(), "/boom")

    assert response.status_code == 500
    assert_fixed_headers(response)
    assert response.headers[CSP] == EXPECTED_CSP
    assert "secret detail" not in response.text


async def test_an_html_page_gets_no_csp_but_the_other_headers() -> None:
    response = await fetch(build_app(), "/page")

    assert_fixed_headers(response)
    assert CSP not in response.headers


async def test_a_non_json_body_gets_no_csp() -> None:
    response = await fetch(build_app(), "/text")

    assert_fixed_headers(response)
    assert CSP not in response.headers


async def test_headers_a_route_set_are_kept() -> None:
    response = await fetch(build_app(), "/own-policy")

    assert response.headers[CSP] == ROUTE_CSP
    assert response.headers["x-frame-options"] == "SAMEORIGIN"
    assert response.headers["referrer-policy"] == "no-referrer"


async def test_the_interactive_docs_page_carries_its_own_policy_and_still_loads() -> None:
    settings = Settings(
        driver="fake", database_url="sqlite+aiosqlite:///:memory:", api_key_pepper="test-pepper"
    )
    app = create_app(settings)
    try:
        response = await fetch(app, "/docs")
    finally:
        await app.state.engine.dispose()

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "swagger-ui" in response.text
    assert "frame-ancestors 'none'" in response.headers[CSP]
    assert response.headers[CSP] != EXPECTED_CSP  # the docs policy, not the JSON one
    assert response.headers["x-frame-options"] == "DENY"


async def test_the_redoc_csp_allows_the_redoc_logo_host_in_img_src() -> None:
    settings = Settings(
        driver="fake", database_url="sqlite+aiosqlite:///:memory:", api_key_pepper="test-pepper"
    )
    app = create_app(settings)
    try:
        response = await fetch(app, "/redoc")
    finally:
        await app.state.engine.dispose()

    directives = {d.split(" ", 1)[0]: d for d in response.headers[CSP].split("; ")}
    assert "https://cdn.redoc.ly" in directives["img-src"].split()


async def test_the_docs_csp_keeps_img_src_to_self_and_data() -> None:
    settings = Settings(
        driver="fake", database_url="sqlite+aiosqlite:///:memory:", api_key_pepper="test-pepper"
    )
    app = create_app(settings)
    try:
        response = await fetch(app, "/docs")
    finally:
        await app.state.engine.dispose()

    directives = {d.split(" ", 1)[0]: d for d in response.headers[CSP].split("; ")}
    assert directives["img-src"] == "img-src 'self' data:"
    assert "redoc.ly" not in response.headers[CSP]


async def test_the_non_docs_csp_does_not_gain_the_redoc_logo_host() -> None:
    response = await fetch(build_app(), "/json")

    assert response.headers[CSP] == EXPECTED_CSP
    assert "redoc" not in CONTENT_SECURITY_POLICY_VALUE


async def test_a_streamed_body_arrives_chunk_by_chunk() -> None:
    transport = httpx.ASGITransport(app=build_app())
    seen: list[bytes] = []
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        async with client.stream("GET", "/stream") as response:
            assert_fixed_headers(response)
            assert CSP not in response.headers
            async for chunk in response.aiter_raw():
                seen.append(chunk)

    assert b"".join(seen) == b"abc"
