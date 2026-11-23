"""Docs pages: Subresource Integrity on every CDN asset, no inline script, a strict page CSP."""

import re
from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI

from sandfort.api.app import create_app
from sandfort.api.docs_pages import SWAGGER_INIT_PATH
from sandfort.config import Settings

CSP = "content-security-policy"
CDN = "https://cdn.jsdelivr.net"
REDOC_LOGO_HOST = "https://cdn.redoc.ly"
SWAGGER_CSS = f"{CDN}/npm/swagger-ui-dist@5.17.14/swagger-ui.css"
SWAGGER_JS = f"{CDN}/npm/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"
REDOC_JS = f"{CDN}/npm/redoc@2.2.0/bundles/redoc.standalone.js"
SWAGGER_CSS_HASH = "sha384-wxLW6kwyHktdDGr6Pv1zgm/VGJh99lfUbzSn6HNHBENZlCN7W602k9VkGdxuFvPn"
SWAGGER_JS_HASH = "sha384-wmyclcVGX/WhUkdkATwhaK1X1JtiNrr2EoYJ+diV3vj4v6OC5yCeSu+yW13SYJep"
REDOC_JS_HASH = "sha384-bhu6JhWKMHdb3pqlE9NXT5CzRVPNj+jiENmqnbjSX8b1g88rfhWpJFCFB5G+X8x0"
INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", re.IGNORECASE)


@pytest.fixture
async def app() -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    settings = Settings(
        driver="fake", database_url="sqlite+aiosqlite:///:memory:", api_key_pepper="test-pepper"
    )
    application = create_app(settings)
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


def _tag_with(html: str, url: str) -> str:
    match = re.search(rf"<[^>]*{re.escape(url)}[^>]*>", html)
    assert match is not None, url
    return match.group(0)


@pytest.mark.parametrize(
    ("path", "assets"),
    [
        ("/docs", ((SWAGGER_CSS, SWAGGER_CSS_HASH), (SWAGGER_JS, SWAGGER_JS_HASH))),
        ("/redoc", ((REDOC_JS, REDOC_JS_HASH),)),
    ],
)
async def test_cdn_assets_carry_the_exact_integrity_hash_and_crossorigin(
    client: httpx.AsyncClient, path: str, assets: tuple[tuple[str, str], ...]
) -> None:
    html = (await client.get(path)).text

    for url, digest in assets:
        tag = _tag_with(html, url)
        assert f'integrity="{digest}"' in tag
        assert 'crossorigin="anonymous"' in tag


@pytest.mark.parametrize("path", ["/docs", "/redoc"])
async def test_pages_have_no_inline_script_and_no_google_fonts(
    client: httpx.AsyncClient, path: str
) -> None:
    html = (await client.get(path)).text

    assert INLINE_SCRIPT.search(html) is None
    assert "fonts.googleapis.com" not in html and "fonts.gstatic.com" not in html
    assert "<title>Sandfort API</title>" in html
    assert 'href="data:image/' in html


async def test_redoc_names_the_openapi_path(client: httpx.AsyncClient) -> None:
    html = (await client.get("/redoc")).text

    assert 'spec-url="/openapi.json"' in html


async def test_swagger_page_loads_the_same_origin_bootstrap(client: httpx.AsyncClient) -> None:
    html = (await client.get("/docs")).text

    assert f'<script src="{SWAGGER_INIT_PATH}"></script>' in html


async def test_bootstrap_script_is_javascript_cacheable_and_unauthenticated(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get(SWAGGER_INIT_PATH)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/javascript")
    assert "public" in response.headers["cache-control"]
    assert "max-age" in response.headers["cache-control"]
    assert "SwaggerUIBundle" in response.text
    assert '"/openapi.json"' in response.text
    assert '"#swagger-ui"' in response.text


async def test_img_src_allows_the_redoc_host_on_redoc_only(client: httpx.AsyncClient) -> None:
    docs = (await client.get("/docs")).headers[CSP]
    redoc = (await client.get("/redoc")).headers[CSP]

    assert "img-src 'self' data:;" in docs
    assert REDOC_LOGO_HOST not in docs
    assert f"img-src 'self' data: {REDOC_LOGO_HOST};" in redoc


@pytest.mark.parametrize("path", ["/docs", "/redoc"])
async def test_csp_has_no_unsafe_inline_script_and_no_google_fonts(
    client: httpx.AsyncClient, path: str
) -> None:
    policy = (await client.get(path)).headers[CSP]
    directives = {d.split(" ", 1)[0]: d for d in policy.split("; ")}

    assert directives["script-src"] == f"script-src 'self' {CDN}"
    assert "'unsafe-inline'" in directives["style-src"]
    assert CDN in directives["style-src"]
    assert "google" not in policy and "gstatic" not in policy
    sources = directives["img-src"].split()[1:]
    assert "https:" not in sources  # no scheme-wide https source
    remote = [s for s in sources if s.startswith("https://")]
    assert remote == ([REDOC_LOGO_HOST] if path == "/redoc" else [])
    assert "connect-src 'self'" in policy and "worker-src blob:" in policy
    for fixed in ("frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"):
        assert fixed in policy


async def test_pages_and_bootstrap_stay_out_of_the_schema(client: httpx.AsyncClient) -> None:
    paths = (await client.get("/openapi.json")).json()["paths"]

    for path in ("/docs", "/redoc", SWAGGER_INIT_PATH):
        assert path not in paths
