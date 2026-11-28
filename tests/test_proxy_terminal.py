"""WP 5.2: the web terminal page the preview proxy serves at ``GET /terminal``.

The proxy is driven through httpx's ASGI transport; no sandbox exists, so a preview host that
reaches the routing path answers 404 while the terminal page needs no sandbox lookup at all.
"""

import re
from typing import Any

import httpx
import pytest

from sandfort.config import Settings
from sandfort.domain.sandbox import Sandbox
from sandfort.drivers.fake import FakeDriver
from sandfort.ids import new_sandbox_id
from sandfort.proxy.app import create_proxy_app
from sandfort.proxy.terminal import (
    TERMINAL_PATH,
    XTERM_SCRIPT_INTEGRITY,
    XTERM_SCRIPT_URL,
    XTERM_STYLESHEET_INTEGRITY,
    XTERM_STYLESHEET_URL,
)

SETTINGS = Settings(driver="fake")
PROXY_HOST = "proxy.test"
SANDBOX_ID = "sbx_01JTERMINALPAGE"
PTY_ID = "pty_01JTERMINALPAGE"
TOKEN = "tok-only-once-7f3a9c"
QUERY = {"sandbox": SANDBOX_ID, "pty": PTY_ID, "token": TOKEN}
PINNED_SCRIPT = "https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.js"
PINNED_STYLESHEET = "https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.css"
SCRIPT_SRI = "sha384-M169f14mRZOXm3hD/v2Ti0ThIT/RnAQagXA9nlE15yHAtrW19gdePJh/HaTzUOe/"
STYLESHEET_SRI = "sha384-8Xk9wy/gzEDUKrXtrmCFa2bBuK3BpjpDuL/p0SeKQX19Khl/M+lHOgD/CyYf7efP"
CONNECT_PATH = f"/v1/sandboxes/{SANDBOX_ID}/toolbox/pty/{PTY_ID}/connect?token={TOKEN}"


async def no_sandbox(sandbox_id: str) -> Sandbox | None:
    return None


async def get_terminal(
    params: dict[str, str], *, host: str = PROXY_HOST, settings: Settings = SETTINGS
) -> httpx.Response:
    app: Any = create_proxy_app(settings, lookup=no_sandbox, driver=FakeDriver())
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://proxy.test") as client:
            return await client.get(TERMINAL_PATH, params=params, headers={"host": host})
    finally:
        await app.aclose()


def tag_for(html: str, url: str) -> str:
    """The one <link> or <script> start tag whose attributes contain ``url``."""
    found: list[str] = re.findall(r"<(?:link|script)\b[^>]*>", html)
    tags = [tag for tag in found if url in tag]
    assert len(tags) == 1, tags
    return tags[0]


async def test_page_is_served_with_the_pinned_xterm_assets() -> None:
    response = await get_terminal(QUERY)

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/html")
    assert (XTERM_SCRIPT_URL, XTERM_STYLESHEET_URL) == (PINNED_SCRIPT, PINNED_STYLESHEET)
    assert f'src="{PINNED_SCRIPT}"' in response.text
    assert f'href="{PINNED_STYLESHEET}"' in response.text
    assert "resize" not in response.text.lower()


def test_integrity_constants_are_the_computed_sha384_hashes() -> None:
    assert XTERM_SCRIPT_INTEGRITY == SCRIPT_SRI
    assert XTERM_STYLESHEET_INTEGRITY == STYLESHEET_SRI


async def test_script_tag_carries_integrity_and_crossorigin() -> None:
    response = await get_terminal(QUERY)

    assert response.status_code == 200, response.text
    tag = tag_for(response.text, PINNED_SCRIPT)
    assert f'integrity="{SCRIPT_SRI}"' in tag
    assert 'crossorigin="anonymous"' in tag
    assert "nonce=" in tag


async def test_stylesheet_tag_carries_integrity_and_crossorigin() -> None:
    response = await get_terminal(QUERY)

    assert response.status_code == 200, response.text
    tag = tag_for(response.text, PINNED_STYLESHEET)
    assert f'integrity="{STYLESHEET_SRI}"' in tag
    assert 'crossorigin="anonymous"' in tag
    assert 'rel="stylesheet"' in tag


async def test_each_integrity_value_appears_once_and_the_two_differ() -> None:
    response = await get_terminal(QUERY)

    assert response.text.count(SCRIPT_SRI) == 1
    assert response.text.count(STYLESHEET_SRI) == 1
    assert SCRIPT_SRI != STYLESHEET_SRI


async def test_csp_still_allows_the_integrity_checked_files() -> None:
    response = await get_terminal(QUERY)

    policy = response.headers["content-security-policy"]
    match = re.search(r"script-src 'nonce-([^']+)'", policy)
    assert match is not None, policy
    assert f'nonce="{match.group(1)}"' in tag_for(response.text, PINNED_SCRIPT)
    assert "style-src https://cdn.jsdelivr.net" in policy
    assert "default-src 'none'" in policy


async def test_an_error_page_has_no_integrity_markup() -> None:
    response = await get_terminal({**QUERY, "pty": "  "})

    assert response.status_code == 400
    assert "integrity" not in response.text


async def test_websocket_url_carries_sandbox_pty_and_token() -> None:
    response = await get_terminal(QUERY)

    assert response.status_code == 200, response.text
    assert f'"ws://{PROXY_HOST}:{SETTINGS.port}{CONNECT_PATH}"' in response.text


async def test_default_base_uses_the_api_port_not_the_proxy_port() -> None:
    response = await get_terminal(QUERY, host=f"localhost:{SETTINGS.proxy_port}")

    assert response.status_code == 200, response.text
    assert f'"ws://localhost:{SETTINGS.port}{CONNECT_PATH}"' in response.text


async def test_public_api_url_sets_the_websocket_base() -> None:
    settings = Settings(driver="fake", public_api_url="https://api.example.com/sandfort")

    response = await get_terminal(QUERY, settings=settings)

    assert response.status_code == 200, response.text
    assert f'"wss://api.example.com/sandfort{CONNECT_PATH}"' in response.text


async def test_token_appears_exactly_once_in_the_body() -> None:
    response = await get_terminal(QUERY)

    assert response.status_code == 200, response.text
    assert response.text.count(TOKEN) == 1


@pytest.mark.parametrize("missing", ["sandbox", "pty", "token"])
async def test_a_missing_parameter_is_rejected(missing: str) -> None:
    params = {name: value for name, value in QUERY.items() if name != missing}

    response = await get_terminal(params)

    assert 400 <= response.status_code < 500
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert TOKEN not in response.text


async def test_a_blank_parameter_is_rejected() -> None:
    response = await get_terminal({**QUERY, "pty": "  "})

    assert response.status_code == 400
    assert TOKEN not in response.text


async def test_markup_in_parameters_cannot_escape_the_script() -> None:
    hostile = "</script><script>alert(1)</script>"

    response = await get_terminal({**QUERY, "sandbox": hostile})

    assert response.status_code == 200, response.text
    assert "alert(1)</script>" not in response.text
    assert "%3C%2Fscript%3E%3Cscript%3Ealert%281%29" in response.text


async def test_page_headers_pin_scripts_to_a_nonce_and_send_no_referrer() -> None:
    response = await get_terminal(QUERY)

    policy = response.headers["content-security-policy"]
    match = re.search(r"script-src 'nonce-([^']+)'", policy)
    assert match is not None, policy
    assert response.text.count(f'nonce="{match.group(1)}"') == 2
    assert "frame-ancestors 'none'" in policy
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"


async def test_a_preview_host_keeps_its_own_terminal_path() -> None:
    preview_host = f"8080-{new_sandbox_id().lower()}.{SETTINGS.preview_domain}"

    response = await get_terminal(QUERY, host=preview_host)

    assert response.status_code == 404
    assert PINNED_SCRIPT not in response.text


def test_public_api_url_is_read_from_the_environment_without_a_trailing_slash() -> None:
    settings = Settings.from_env({"SANDFORT_PUBLIC_API_URL": " https://api.example.com/ "})

    assert settings.public_api_url == "https://api.example.com"
    assert Settings.from_env({}).public_api_url == ""


@pytest.mark.parametrize("value", ["api.example.com", "ftp://api.example.com", "http://a/?x=1"])
def test_a_malformed_public_api_url_is_refused(value: str) -> None:
    with pytest.raises(ValueError, match="SANDFORT_PUBLIC_API_URL"):
        Settings.from_env({"SANDFORT_PUBLIC_API_URL": value})
