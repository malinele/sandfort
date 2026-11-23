"""The interactive docs pages: ``/docs`` (Swagger UI) and ``/redoc`` (ReDoc).

The HTML is rendered here, not by FastAPI's helpers, so no page carries an inline script: the
Swagger UI bootstrap is a same-origin script served at ``SWAGGER_INIT_PATH``. Every bundle is
loaded from a pinned jsdelivr URL with a Subresource Integrity hash and ``crossorigin``. The
pages, the bootstrap script and their routes stay out of the OpenAPI schema and need no
authentication. Each page sets its own policy: ``DOCS_CONTENT_SECURITY_POLICY_VALUE`` for
``/docs`` and ``REDOC_CONTENT_SECURITY_POLICY_VALUE`` (adds the ReDoc logo host) for ``/redoc``.
The dark theme (``docs_theme``) is inline CSS and a JSON ``theme`` option; both fit the policies.
"""

import json
from html import escape

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse

from sandfort.api.docs_theme import (
    TOPBAR_ID,
    redoc_style_block,
    redoc_theme_json,
    swagger_style_block,
    topbar_html,
)
from sandfort.api.security_headers import (
    CONTENT_SECURITY_POLICY_HEADER,
    DOCS_CONTENT_SECURITY_POLICY_VALUE,
    REDOC_CONTENT_SECURITY_POLICY_VALUE,
)

OPENAPI_PATH = "/openapi.json"
DOCS_PATH = "/docs"
REDOC_PATH = "/redoc"
SWAGGER_INIT_PATH = f"{DOCS_PATH}/init.js"
DOCS_TITLE = "Sandfort API"
# Exact versions, never a floating major: the pages load the same bundle on every visit.
SWAGGER_BASE_URL = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14"
SWAGGER_CSS_URL = f"{SWAGGER_BASE_URL}/swagger-ui.css"
SWAGGER_JS_URL = f"{SWAGGER_BASE_URL}/swagger-ui-bundle.js"
SWAGGER_CSS_INTEGRITY = "sha384-wxLW6kwyHktdDGr6Pv1zgm/VGJh99lfUbzSn6HNHBENZlCN7W602k9VkGdxuFvPn"
SWAGGER_JS_INTEGRITY = "sha384-wmyclcVGX/WhUkdkATwhaK1X1JtiNrr2EoYJ+diV3vj4v6OC5yCeSu+yW13SYJep"
REDOC_BASE_URL = "https://cdn.jsdelivr.net/npm/redoc@2.2.0/bundles"
REDOC_JS_URL = f"{REDOC_BASE_URL}/redoc.standalone.js"
REDOC_JS_INTEGRITY = "sha384-bhu6JhWKMHdb3pqlE9NXT5CzRVPNj+jiENmqnbjSX8b1g88rfhWpJFCFB5G+X8x0"
# A one-pixel transparent PNG: the pages request no favicon from a third-party host.
DOCS_FAVICON_URL = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA"
    "60e6kgAAAABJRU5ErkJggg=="
)
JAVASCRIPT_MEDIA_TYPE = "application/javascript"
INIT_CACHE_CONTROL = "public, max-age=3600"

_HEAD = (
    '<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
    f'<link rel="icon" type="image/png" href="{DOCS_FAVICON_URL}">\n'
    f"<title>{escape(DOCS_TITLE)}</title>\n"
)


def render_swagger_page() -> str:
    """Swagger UI page: SRI-pinned stylesheet and bundle, the dark theme, the bootstrap."""
    return (
        "<!DOCTYPE html>\n<html>\n<head>\n"
        f"{_HEAD}"
        f'<link rel="stylesheet" href="{SWAGGER_CSS_URL}"\n'
        f'  integrity="{SWAGGER_CSS_INTEGRITY}" crossorigin="anonymous">\n'
        f"{swagger_style_block()}"
        "</head>\n<body>\n"
        f"{topbar_html('Swagger UI')}"
        '<div id="swagger-ui"></div>\n'
        f'<script src="{SWAGGER_JS_URL}"\n'
        f'  integrity="{SWAGGER_JS_INTEGRITY}" crossorigin="anonymous"></script>\n'
        f'<script src="{SWAGGER_INIT_PATH}"></script>\n'
        "</body>\n</html>\n"
    )


def render_redoc_page() -> str:
    """ReDoc page: brand bar, the themed redoc element and the pinned standalone bundle with SRI."""
    return (
        "<!DOCTYPE html>\n<html>\n<head>\n"
        f"{_HEAD}"
        f"{redoc_style_block()}"
        "</head>\n<body>\n"
        f"{topbar_html('ReDoc')}"
        f'<redoc spec-url="{escape(OPENAPI_PATH)}" scroll-y-offset="#{TOPBAR_ID}"\n'
        f'  theme="{escape(redoc_theme_json())}"></redoc>\n'
        f'<script src="{REDOC_JS_URL}"\n'
        f'  integrity="{REDOC_JS_INTEGRITY}" crossorigin="anonymous"></script>\n'
        "</body>\n</html>\n"
    )


def render_swagger_init_script() -> str:
    """The Swagger UI bootstrap, served as a file so the page needs no inline script."""
    return (
        "window.ui = SwaggerUIBundle({\n"
        f"  url: {json.dumps(OPENAPI_PATH)},\n"
        '  dom_id: "#swagger-ui"\n'
        "});\n"
    )


def _page(html: str, policy: str) -> HTMLResponse:
    response = HTMLResponse(html)
    response.headers[CONTENT_SECURITY_POLICY_HEADER] = policy
    return response


def _for_method(request: Request, response: Response) -> Response:
    """Answer HEAD with the GET status and headers (content length included) and no body."""
    if request.method == "HEAD":
        response.body = b""
    return response


def install_docs_pages(app: FastAPI) -> None:
    """Register ``/docs``, ``/redoc`` and the Swagger UI bootstrap script on ``app``.

    Each route answers GET and HEAD; HEAD carries the GET headers and an empty body, so uptime
    checks that probe with HEAD see the pages as up.
    """

    async def swagger_ui(request: Request) -> Response:
        page = _page(render_swagger_page(), DOCS_CONTENT_SECURITY_POLICY_VALUE)
        return _for_method(request, page)

    async def redoc(request: Request) -> Response:
        page = _page(render_redoc_page(), REDOC_CONTENT_SECURITY_POLICY_VALUE)
        return _for_method(request, page)

    async def swagger_init(request: Request) -> Response:
        response = Response(
            render_swagger_init_script(),
            media_type=JAVASCRIPT_MEDIA_TYPE,
            headers={"Cache-Control": INIT_CACHE_CONTROL},
        )
        return _for_method(request, response)

    methods = ["GET", "HEAD"]
    app.add_api_route(DOCS_PATH, swagger_ui, methods=methods, include_in_schema=False)
    app.add_api_route(REDOC_PATH, redoc, methods=methods, include_in_schema=False)
    app.add_api_route(SWAGGER_INIT_PATH, swagger_init, methods=methods, include_in_schema=False)
