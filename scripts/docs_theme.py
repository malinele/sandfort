"""Page shell for the generated docs site: tokens and chrome copied from site/index.html."""

from __future__ import annotations

import hashlib
import html
from pathlib import Path

LANDING = "https://sandfort.dev/"
CANONICAL_BASE = "https://docs.sandfort.dev/"
THEME_COLOR_DARK = "#0b0d11"
THEME_COLOR_LIGHT = "#ffffff"


def theme_color_meta(*, always_dark: bool = False) -> str:
    """Theme-color metas; an always-dark page carries the dark value for both schemes."""
    light = THEME_COLOR_DARK if always_dark else THEME_COLOR_LIGHT
    return (
        '<meta name="theme-color" media="(prefers-color-scheme: dark)" '
        f'content="{THEME_COLOR_DARK}">\n'
        '<meta name="theme-color" media="(prefers-color-scheme: light)" '
        f'content="{light}">'
    )


MAILTO = (
    "mailto:office@sandfort.dev?subject=Sandfort%20beta%20access&amp;body=Team%20%2F%20company%3A%0A"
    "What%20your%20agent%20runs%3A%0AHosted%20beta%20or%20self-hosted%3A%0A"
    "Stack%20(Python%2C%20TypeScript%2C%20MCP%2C%20CLI)%3A%0A"
)
# Umami tracker (self-hosted, no cookies). The website ID is a placeholder until the operator
# creates the docs.sandfort.dev website in Umami (deploy/umami/README.md section 5). The
# host must also be allowed by script-src and connect-src in deploy/static-nginx/docs.conf.
UMAMI_HOST = "https://umami.sandfort.dev"
UMAMI_DOCS_WEBSITE_ID = "f88825f1-b3cc-441a-b5e8-e7ff35c9e74c"
ANALYTICS_SNIPPET = (
    f'<script defer src="{UMAMI_HOST}/script.js" '
    f'data-website-id="{UMAMI_DOCS_WEBSITE_ID}" data-domains="docs.sandfort.dev"></script>'
)
BETA_REQUEST_EVENT = 'data-umami-event="beta_request"'
BRAND_MARK = '<span class="mark" aria-hidden="true">$</span>'
FAVICON = (
    '<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' '
    "viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%230b0d11'/%3E%3Ctext "
    "x='16' y='23' font-family='monospace' font-size='20' font-weight='700' fill='%23e0a458' "
    "text-anchor='middle'%3E%24%3C/text%3E%3C/svg%3E\">"
)
SECTIONS = (
    ("agent-loop", "Agent loop"),
    ("two-ways", "Run it"),
    ("isolation", "Isolation"),
    ("governance", "Governance"),
    ("limits", "Limits"),
)
API_PAGE = "index.html"
DOC_LINKS = (
    (API_PAGE, "API reference"),
    ("quickstart.html", "Quickstart"),
    ("guide.html", "Connect guide"),
    ("operations.html", "Runbook"),
    ("security.html", "Security"),
    ("isolation-tiers.html", "Isolation tiers"),
    ("beta-terms.html", "Beta terms"),
    ("release.html", "Releases"),
    ("governance.html", "Governance page"),
)

STYLESHEET_FILE = "docs.css"
# Written once to the site root as STYLESHEET_FILE and linked from every page.
CSS = (Path(__file__).resolve().parent / "docs_site.css").read_text(encoding="utf-8")
STYLESHEET_HASH_LENGTH = 12
# Content hash of the stylesheet, computed at build time. Pages link the file with it as a
# query string, so HTML and CSS stay matched although the stylesheet is cached for minutes.
STYLESHEET_HASH = hashlib.sha256(CSS.encode("utf-8")).hexdigest()[:STYLESHEET_HASH_LENGTH]

SCRIPT = """
(function(){
  var d=document;
  var status=d.getElementById('copy-status');
  function say(msg){
    if(!status)return;
    status.textContent='';
    setTimeout(function(){status.textContent=msg},50);
    setTimeout(function(){status.textContent=''},2500);
  }
  d.querySelectorAll('[data-copy]').forEach(function(b){
    b.addEventListener('click',function(){
      var slab=b.closest('.slab');var pre=slab&&slab.querySelector('pre');
      var txt=pre?pre.innerText:'';
      function done(){
        say('Copied');b.textContent='Copied';
        setTimeout(function(){b.textContent='Copy'},1600)
      }
      function fail(){say('Copy failed')}
      var cb=navigator.clipboard;
      if(cb&&cb.writeText){cb.writeText(txt).then(done,fail)}else{fail()}
    });
  });
  var toc=d.querySelector('details.toc');
  if(toc&&window.matchMedia&&matchMedia('(min-width:1024px)').matches){toc.open=true}
})();
"""
COPY_STATUS = (
    '<div class="sr" id="copy-status" role="status" aria-live="polite" aria-atomic="true"></div>'
)


def clean_path(filename: str) -> str:
    """Root-absolute clean-URL path of a published page: `guide.html` is `/guide`, the API
    reference is `/`. The files keep their `.html` names; links never carry the suffix."""
    if filename == API_PAGE:
        return "/"
    return "/" + filename.removesuffix(".html")


def _header() -> str:
    links = "\n".join(
        f'        <li><a href="{LANDING}#{a}">{label}</a></li>' for a, label in SECTIONS
    )
    return f"""<header class="nav">
  <div class="in">
    <a class="brand" href="{LANDING}" aria-label="Sandfort home">{BRAND_MARK}Sandfort</a>
    <nav aria-label="Sections">
      <ul>
{links}
      </ul>
    </nav>
    <span class="sp"></span>
    <a class="docs" href="{clean_path(API_PAGE)}">API reference</a>
    <a class="btn btn-p" {BETA_REQUEST_EVENT} data-umami-event-placement="nav"
      href="{MAILTO}">Request beta access</a>
  </div>
</header>"""


def _subnav(active: str) -> str:
    links = []
    for href, label in DOC_LINKS:
        current = ' aria-current="page"' if href == active else ""
        links.append(f'<a href="{clean_path(href)}"{current}>{label}</a>')
    back = f'<a class="back" href="{LANDING}">&#8592; sandfort.dev</a>'
    inner = back + "".join(links)
    return f'<div class="subnav"><nav class="in" aria-label="Documentation">{inner}</nav></div>'


def _event_attrs(href: str) -> str:
    """Umami event attributes for the beta-request mailto link in the footer."""
    if href != MAILTO:
        return ""
    return f' {BETA_REQUEST_EVENT} data-umami-event-placement="footer"'


def _footer() -> str:
    def col(title: str, items: list[tuple[str, str]]) -> str:
        # A label, not a heading: the footer must not skip from h1/h2 to h4.
        ident = f"footer-{title.lower()}"
        lis = "".join(f'<li><a{_event_attrs(h)} href="{h}">{t}</a></li>' for h, t in items)
        return (
            f'<div><p class="fh" id="{ident}">{title}</p>'
            f'<ul aria-labelledby="{ident}">{lis}</ul></div>'
        )

    product = [(f"{LANDING}#{a}", label) for a, label in SECTIONS[:4]]
    developers = [
        *((clean_path(href), label) for href, label in DOC_LINKS),
        (f"{LANDING}#deploy", "Deployment"),
        (f"{LANDING}#limits", "Limits"),
        (f"{LANDING}#measured", "How we measured"),
    ]
    contact = [
        (MAILTO, "Request beta access"),
        ("mailto:office@sandfort.dev", "office@sandfort.dev"),
    ]
    return f"""<footer>
  <div class="in">
    <div class="about">
      <a class="brand" href="{LANDING}">{BRAND_MARK}Sandfort</a>
      <p>Sandboxes for AI-generated code, on infrastructure you control.</p>
    </div>
    {col("Product", product)}
    {col("Developers", developers)}
    {col("Contact", contact)}
    <div class="legal">
      <span>&#169; 2026 Polygon Consulting doo, Beograd, Serbia</span>
      <span>Polygon Consulting d.o.o. Beograd-Savski Venac, Kozara 1, Beograd, Serbia
      &#183; APR mati&#269;ni broj 21466352 &#183; PIB 111345107 &#183; office@sandfort.dev</span>
      <span>Sandfort 0.1.0, source-available under FSL-1.1-Apache-2.0</span>
    </div>
  </div>
</footer>"""


def canonical_url(filename: str) -> str:
    """Absolute clean-URL address of a published page (`guide.html` is served as `/guide`);
    the API reference is the bare site root."""
    if filename == "index.html":
        return CANONICAL_BASE
    return CANONICAL_BASE + filename.removesuffix(".html")


def render_page(
    *,
    title: str,
    description: str,
    filename: str,
    body: str,
    scripts: str = "",
    always_dark: bool = False,
    canonical: bool = True,
    extra_head: str = "",
    link_base: str = "",
) -> str:
    """Wrap `body` in the shared chrome. `body` is trusted generated HTML.

    `always_dark` pins the page to the dark scheme, `canonical=False` omits the canonical
    link, and `extra_head` is trusted markup appended to the head. `link_base` prefixes the
    stylesheet and script addresses: empty keeps them relative, "/" makes them root-absolute
    (for the not-found page, served from any path depth). Page links are always root-absolute
    clean URLs and the skip link is the fragment `#main`, so both work at any depth. The
    stylesheet address always carries `?v=` plus the content hash of the stylesheet.
    """
    page_title = html.escape(f"{title} - Sandfort docs")
    desc = html.escape(description, quote=True)
    html_class = ' class="always-dark"' if always_dark else ""
    canonical_tag = ""
    if canonical:
        canonical_tag = f'<link rel="canonical" href="{canonical_url(filename)}">\n'
    status = f"{COPY_STATUS}\n" if "data-copy" in body else ""
    extra = f"{extra_head}\n" if extra_head else ""
    return f"""<!doctype html>
<html lang="en"{html_class}>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{page_title}</title>
<meta name="description" content="{desc}">
{theme_color_meta(always_dark=always_dark)}
{canonical_tag}{extra}{FAVICON}
<link rel="stylesheet" href="{link_base}{STYLESHEET_FILE}?v={STYLESHEET_HASH}">
{ANALYTICS_SNIPPET}
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
{_header()}
{_subnav(filename)}
<main id="main">
{body}
</main>
{status}{_footer()}
<script src="{link_base}docs.js"></script>
{scripts}
</body>
</html>
"""


def doc_body(content: str, toc: str) -> str:
    """Two-column article layout: contents list plus the converted Markdown."""
    toc_block = ""
    if toc:
        toc_block = f'<details class="toc"><summary>On this page</summary>{toc}</details>\n'
    cls = "doc has-toc" if toc else "doc"
    return (
        f'<div class="frame"><div class="{cls}">\n{toc_block}'
        f'<article class="prose">\n{content}\n</article>\n</div></div>'
    )
