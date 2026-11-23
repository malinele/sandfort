"""The dark theme of the interactive docs pages, matching the landing page (``site/index.html``).

Everything is inline CSS or a JSON option, so no new asset is loaded: the docs policy has
``style-src 'unsafe-inline'`` (both UIs inject styles at run time) but ``font-src data:`` only,
so Geist and JetBrains Mono cannot be fetched from a CDN. The stacks below name them first and
fall back to system fonts; the faces render where they are installed.
"""

import json
from html import escape

TOPBAR_ID = "topbar"
TOPBAR_HEIGHT_PX = 56
LANDING_URL = "https://sandfort.dev/"
BRAND_ARIA_LABEL = "Sandfort"

SANS = '"Geist", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif'
MONO = '"JetBrains Mono", ui-monospace, "SF Mono", Menlo, monospace'

_TOKENS = {
    "bg": "#0b0d11",
    "bg-1": "#101319",
    "bg-2": "#151922",
    "bg-3": "#1c212c",
    "line": "#222834",
    "line-2": "#2f3746",
    "text": "#e9ebef",
    "text-2": "#b4bac6",
    "muted": "#8c94a3",
    "accent": "#e0a458",
    "accent-ink": "#1a1206",
    "ok": "#8fc18a",
    "bad": "#e58a76",
}

_ROOT = ":root{color-scheme:dark;" + ";".join(f"--{k}:{v}" for k, v in _TOKENS.items()) + "}"

_BASE_CSS = f"""
{_ROOT}
html,body{{margin:0;background:var(--bg);color:var(--text);font:400 16px/1.6 {SANS};
-webkit-font-smoothing:antialiased}}
code,kbd,samp,pre{{font-family:{MONO}}}
#{TOPBAR_ID}{{position:sticky;top:0;z-index:200;height:{TOPBAR_HEIGHT_PX}px;box-sizing:border-box;
display:flex;align-items:center;gap:14px;padding:0 clamp(16px,4vw,40px);
background:var(--bg);border-bottom:1px solid var(--line)}}
#{TOPBAR_ID} a{{display:flex;align-items:center;gap:10px;color:var(--text);text-decoration:none;
font:600 17px/1 {SANS};letter-spacing:-.02em}}
#{TOPBAR_ID} .mark{{width:26px;height:26px;border-radius:6px;background:var(--bg-2);
border:1px solid var(--line-2);display:grid;place-items:center;color:var(--accent);
font:700 15px/1 {MONO}}}
#{TOPBAR_ID} .page{{margin-left:auto;font:400 12px/1 {MONO};color:var(--muted)}}
#{TOPBAR_ID} a:focus-visible{{outline:2px solid var(--accent);outline-offset:3px;border-radius:4px}}
"""

_SWAGGER_CSS = f"""
.swagger-ui,.swagger-ui .info .title,.swagger-ui .info li,.swagger-ui .info p,
.swagger-ui .info a,.swagger-ui .opblock-tag,.swagger-ui .opblock .opblock-summary-description,
.swagger-ui .opblock-description-wrapper p,.swagger-ui .opblock-external-docs-wrapper p,
.swagger-ui .opblock-title_normal p,.swagger-ui .response-col_status,
.swagger-ui .response-col_description,.swagger-ui .parameter__name,.swagger-ui .parameter__type,
.swagger-ui table thead tr td,.swagger-ui table thead tr th,.swagger-ui .tab li,
.swagger-ui .model-title,.swagger-ui .model,.swagger-ui .prop-type,.swagger-ui label,
.swagger-ui .markdown p,.swagger-ui .markdown li,.swagger-ui .renderedMarkdown p,
.swagger-ui .btn,.swagger-ui select,.swagger-ui .scheme-container .schemes>label,
.swagger-ui section.models h4,.swagger-ui section.models h5,.swagger-ui .opblock-summary-path,
.swagger-ui h1,.swagger-ui h2,.swagger-ui h3,.swagger-ui h4,.swagger-ui h5{{
color:var(--text);font-family:{SANS}}}
.swagger-ui .opblock-summary-path,.swagger-ui .opblock-summary-path__deprecated,
.swagger-ui .parameter__name,.swagger-ui .parameter__type,.swagger-ui .prop-type,
.swagger-ui .microlight,.swagger-ui code,.swagger-ui pre,.swagger-ui textarea,
.swagger-ui input[type=text],.swagger-ui input[type=password],.swagger-ui input[type=search],
.swagger-ui input[type=email],.swagger-ui input[type=file]{{font-family:{MONO}}}
.swagger-ui .wrapper{{max-width:1200px;padding:0 clamp(16px,4vw,40px)}}
.swagger-ui .info .title small pre,.swagger-ui .info .title small{{background:var(--bg-3);
color:var(--muted)}}
.swagger-ui .info a,.swagger-ui .markdown a{{color:var(--accent)}}
.swagger-ui .info :is(h1,h2,h3,h4,h5,h6),.swagger-ui .markdown :is(h1,h2,h3,h4,h5,h6),
.swagger-ui .renderedMarkdown :is(h1,h2,h3,h4,h5,h6){{color:var(--text);font-family:{SANS}}}
.swagger-ui .markdown code,.swagger-ui .renderedMarkdown code{{background:var(--bg-2);
border:1px solid var(--line);color:var(--accent);font-family:{MONO};font-size:.84em;
font-weight:500;padding:.05em .35em}}
.swagger-ui .info .title small.version-stamp{{background:var(--accent)}}
.swagger-ui .info .title small.version-stamp pre{{color:var(--accent-ink)}}
.swagger-ui .scheme-container{{background:var(--bg-1);box-shadow:none;
border-top:1px solid var(--line);border-bottom:1px solid var(--line)}}
.swagger-ui .opblock-tag{{border-bottom:1px solid var(--line)}}
.swagger-ui .opblock-tag:hover{{background:var(--bg-1)}}
.swagger-ui .opblock{{background:var(--bg-1);border:1px solid var(--line-2);box-shadow:none;
border-radius:8px}}
.swagger-ui .opblock .opblock-summary{{border-color:var(--line-2)}}
.swagger-ui .opblock .opblock-section-header,.swagger-ui .opblock-description-wrapper,
.swagger-ui .responses-inner h4,.swagger-ui .responses-inner h5{{background:var(--bg-2);
box-shadow:none;color:var(--text)}}
.swagger-ui .opblock .opblock-summary-path,.swagger-ui .opblock .opblock-summary-path a{{
color:var(--text)}}
.swagger-ui .opblock-section-header h4,.swagger-ui .opblock-section-header label,
.swagger-ui .opblock-title_normal,.swagger-ui .opblock-title_normal h4,
.swagger-ui .tab-header h4,.swagger-ui h4.opblock-title,.swagger-ui .opblock-body h4{{
color:var(--text)}}
.swagger-ui .opblock-summary-method{{font-family:{MONO};border-radius:4px;color:var(--accent-ink)}}
.swagger-ui .opblock.opblock-get{{border-color:var(--ok)}}
.swagger-ui .opblock.opblock-get .opblock-summary-method{{background:var(--ok)}}
.swagger-ui .opblock.opblock-post{{border-color:var(--accent)}}
.swagger-ui .opblock.opblock-post .opblock-summary-method{{background:var(--accent)}}
.swagger-ui .opblock.opblock-put,.swagger-ui .opblock.opblock-patch{{border-color:#8aa8d6}}
.swagger-ui .opblock.opblock-put .opblock-summary-method,
.swagger-ui .opblock.opblock-patch .opblock-summary-method{{background:#8aa8d6}}
.swagger-ui .opblock.opblock-delete{{border-color:var(--bad)}}
.swagger-ui .opblock.opblock-delete .opblock-summary-method{{background:var(--bad)}}
.swagger-ui .opblock.opblock-get,.swagger-ui .opblock.opblock-post,
.swagger-ui .opblock.opblock-put,.swagger-ui .opblock.opblock-patch,
.swagger-ui .opblock.opblock-delete{{background:var(--bg-1)}}
.swagger-ui .btn{{background:transparent;border:1px solid var(--line-2);box-shadow:none;
border-radius:6px}}
.swagger-ui .btn:hover{{border-color:var(--accent);box-shadow:none}}
.swagger-ui .btn.execute,.swagger-ui .btn.authorize{{background:var(--accent);
border-color:var(--accent);color:var(--accent-ink)}}
.swagger-ui .btn.authorize svg{{fill:var(--accent-ink)}}
.swagger-ui .btn.cancel{{border-color:var(--bad);color:var(--bad)}}
.swagger-ui input[type=text],.swagger-ui input[type=password],.swagger-ui input[type=search],
.swagger-ui input[type=email],.swagger-ui input[type=file],.swagger-ui textarea,
.swagger-ui select{{background:var(--bg);color:var(--text);border:1px solid var(--line-2);
border-radius:6px}}
.swagger-ui input:focus-visible,.swagger-ui textarea:focus-visible,
.swagger-ui select:focus-visible,.swagger-ui .btn:focus-visible{{outline:2px solid var(--accent)}}
.swagger-ui table tbody tr td{{border-bottom:1px solid var(--line);color:var(--text-2)}}
.swagger-ui table thead tr td,.swagger-ui table thead tr th{{border-bottom:1px solid var(--line-2);
color:var(--muted)}}
.swagger-ui .response-col_links,.swagger-ui .parameter__extension,
.swagger-ui .parameter__in,.swagger-ui .opblock-summary-description{{color:var(--muted)}}
.swagger-ui .tab li{{color:var(--muted)}}
.swagger-ui .tab li.active{{color:var(--text)}}
.swagger-ui .highlight-code>.microlight,.swagger-ui .microlight,.swagger-ui .example,
.swagger-ui .opblock-body pre.microlight{{background:var(--bg)!important;
color:var(--text-2)!important;border:1px solid var(--line);border-radius:6px}}
.swagger-ui section.models{{border:1px solid var(--line-2);border-radius:8px}}
.swagger-ui section.models.is-open h4{{border-bottom:1px solid var(--line)}}
.swagger-ui .model-box,.swagger-ui .models-control{{background:transparent}}
.swagger-ui .model-toggle:after,.swagger-ui .arrow,.swagger-ui svg:not(:root){{fill:var(--muted)}}
.swagger-ui .dialog-ux .modal-ux{{background:var(--bg-1);border:1px solid var(--line-2);
color:var(--text)}}
.swagger-ui .dialog-ux .modal-ux-header{{border-bottom:1px solid var(--line)}}
.swagger-ui .dialog-ux .modal-ux-header h3{{color:var(--text)}}
.swagger-ui .loading-container .loading:after{{color:var(--muted)}}
"""


def topbar_html(page_label: str) -> str:
    """The ``$ Sandfort`` brand bar both pages share; ``page_label`` names the page on the right."""
    return (
        f'<header id="{TOPBAR_ID}">'
        f'<a href="{escape(LANDING_URL)}" aria-label="{BRAND_ARIA_LABEL}">'
        '<span class="mark" aria-hidden="true">$</span>Sandfort</a>'
        f'<span class="page">API reference / {escape(page_label)}</span></header>\n'
    )


def swagger_style_block() -> str:
    """The ``<style>`` element for ``/docs``; it follows the Swagger stylesheet to win on order."""
    return f"<style>{_BASE_CSS}{_SWAGGER_CSS}</style>\n"


def redoc_style_block() -> str:
    """The ``<style>`` element for ``/redoc``: page background and topbar only."""
    return f"<style>{_BASE_CSS}</style>\n"


def redoc_theme_json() -> str:
    """The ReDoc ``theme`` option, a JSON object for the ``theme`` attribute of ``<redoc>``."""
    theme = {
        "colors": {
            "primary": {"main": _TOKENS["accent"]},
            "success": {"main": _TOKENS["ok"]},
            "error": {"main": _TOKENS["bad"]},
            "text": {"primary": _TOKENS["text"], "secondary": _TOKENS["text-2"]},
            "border": {"dark": _TOKENS["line-2"], "light": _TOKENS["line"]},
            "http": {
                "get": _TOKENS["ok"],
                "post": _TOKENS["accent"],
                "put": "#8aa8d6",
                "patch": "#8aa8d6",
                "delete": _TOKENS["bad"],
            },
        },
        "typography": {
            "fontFamily": SANS,
            "headings": {"fontFamily": SANS},
            "code": {
                "fontFamily": MONO,
                "color": _TOKENS["accent"],
                "backgroundColor": _TOKENS["bg-2"],
            },
            "links": {"color": _TOKENS["accent"], "hover": "#f0bd7a"},
        },
        "sidebar": {
            "backgroundColor": _TOKENS["bg-1"],
            "textColor": _TOKENS["text-2"],
            "activeTextColor": _TOKENS["text"],
        },
        "rightPanel": {"backgroundColor": _TOKENS["bg-1"], "textColor": _TOKENS["text"]},
        "codeBlock": {"backgroundColor": _TOKENS["bg"]},
        "schema": {"nestedBackground": _TOKENS["bg-1"], "typeNameColor": _TOKENS["muted"]},
    }
    return json.dumps(theme, separators=(",", ":"))
