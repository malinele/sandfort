#!/usr/bin/env python3
"""Generate the docs site (docs.sandfort.dev) from the repo's own Markdown and OpenAPI spec.

    .venv/bin/python scripts/build_docs_site.py [--out site/docs]

Python standard library only. Sources are never modified; output is fully regenerated.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import docs_theme  # noqa: E402
from docs_md import FENCE_RE, Renderer, toc_html  # noqa: E402
from docs_theme import (  # noqa: E402
    CANONICAL_BASE,
    DOC_LINKS,
    canonical_url,
    clean_path,
    doc_body,
    render_page,
)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "site" / "docs"
SPEC_SOURCE = ROOT / "openapi" / "sandfort.v1.json"
# Informational sidecar next to the compact spec copy. It is not a ConfigMap key in
# deploy/redeploy-beta.sh, so it is built but not published.
SPEC_SIDECAR_FILE = "openapi.json.sha256"
SPEC_SIDECAR_LABEL = "openapi/sandfort.v1.json"

RELEASE_TOKEN = "{{CURRENT_RELEASE}}"
RELEASE_FALLBACK = "the latest release tag"
GIT_TIMEOUT_SECONDS = 10
DOCS_HOST_HTML_LINK = re.compile(
    r'href="' + re.escape(CANONICAL_BASE) + r'([A-Za-z0-9-]+)\.html(#[^"]*)?"'
)

# Same CDN bundle and integrity hash as src/sandfort/api/docs_pages.py (REDOC_JS_INTEGRITY).
REDOC_JS_URL = "https://cdn.jsdelivr.net/npm/redoc@2.2.0/bundles/redoc.standalone.js"
REDOC_JS_INTEGRITY = "sha384-bhu6JhWKMHdb3pqlE9NXT5CzRVPNj+jiENmqnbjSX8b1g88rfhWpJFCFB5G+X8x0"
MAX_DESCRIPTION = 200
API_DESCRIPTION = "Sandfort REST API reference, rendered from the OpenAPI specification."
NOT_FOUND_FILE = "404.html"
NOT_FOUND_DESCRIPTION = "The page you requested is not part of the Sandfort documentation."
ROBOTS_FILE = "robots.txt"
SITEMAP_FILE = "sitemap.xml"
SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"


@dataclass(frozen=True)
class MarkdownPage:
    source: str
    output: str


MARKDOWN_PAGES = (
    MarkdownPage("docs/beta-quickstart.md", "quickstart.html"),
    MarkdownPage("docs/beta-terms.md", "beta-terms.html"),
    MarkdownPage("docs/operations.md", "operations.html"),
    MarkdownPage("docs/security.md", "security.html"),
    MarkdownPage("docs/isolation-tiers.md", "isolation-tiers.html"),
    MarkdownPage("docs/release.md", "release.html"),
    MarkdownPage("docs/governance.md", "governance.html"),
    MarkdownPage("docs/connect-guide.md", "guide.html"),
)

SANS = (
    'ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, '
    "sans-serif"
)
MONO = 'ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace'

REDOC_THEME = {
    "spacing": {"unit": 5, "sectionHorizontal": 36, "sectionVertical": 36},
    "colors": {
        "tonalOffset": 0.2,
        "primary": {
            "main": "#e0a458",
            "light": "#f0bd7a",
            "dark": "#b9833d",
            "contrastText": "#1a1206",
        },
        "success": {"main": "#8fc18a"},
        "warning": {"main": "#e0a458", "contrastText": "#1a1206"},
        "error": {"main": "#e58a76"},
        "gray": {"50": "#151922", "100": "#1c212c"},
        "text": {"primary": "#e9ebef", "secondary": "#b4bac6"},
        "border": {"dark": "#2f3746", "light": "#222834"},
        "responses": {
            "success": {"color": "#8fc18a", "backgroundColor": "rgba(143,193,138,.08)"},
            "error": {"color": "#e58a76", "backgroundColor": "rgba(229,138,118,.08)"},
            "redirect": {"color": "#e0a458", "backgroundColor": "rgba(224,164,88,.08)"},
            "info": {"color": "#93b6e0", "backgroundColor": "rgba(147,182,224,.08)"},
        },
        "http": {
            "get": "#8fc18a",
            "post": "#e0a458",
            "put": "#93b6e0",
            "patch": "#c8a6e6",
            "delete": "#e58a76",
            "options": "#8c94a3",
            "basic": "#8c94a3",
            "link": "#8c94a3",
            "head": "#8c94a3",
        },
    },
    "typography": {
        "fontSize": "15px",
        "lineHeight": "1.6",
        "fontWeightRegular": "400",
        "fontWeightBold": "600",
        "fontFamily": SANS,
        "smoothing": "antialiased",
        "headings": {"fontFamily": SANS, "fontWeight": "600"},
        "code": {
            "fontSize": "13px",
            "fontFamily": MONO,
            "fontWeight": "400",
            "color": "#e9ebef",
            "backgroundColor": "#151922",
            "wrap": True,
        },
        "links": {"color": "#f0bd7a", "visited": "#f0bd7a", "hover": "#e0a458"},
    },
    "sidebar": {
        "width": "280px",
        "backgroundColor": "#101319",
        "textColor": "#b4bac6",
        "activeTextColor": "#e0a458",
        "groupItems": {"textTransform": "none"},
        "arrow": {"size": "1.2em", "color": "#8c94a3"},
    },
    "rightPanel": {"backgroundColor": "#07080a", "textColor": "#e9ebef", "width": "40%"},
    "codeBlock": {"backgroundColor": "#07080a"},
    "schema": {
        "nestedBackground": "#101319",
        "linesColor": "#2f3746",
        "typeNameColor": "#93b6e0",
        "typeTitleColor": "#c8a6e6",
        "requireLabelColor": "#e58a76",
    },
    "fab": {"backgroundColor": "#e0a458", "color": "#1a1206"},
}


REDOC_INIT_JS = """(function(){
  var el=document.getElementById("redoc");
  var note=document.getElementById("redoc-status");
  if(typeof Redoc==="undefined"){if(note)note.hidden=false;return;}
  Redoc.init("openapi.json",__OPTIONS__,el,function(err){
    if(err&&note){note.hidden=false;}
  });
})();
"""


def _redoc_init_js() -> str:
    options = json.dumps(
        {"scrollYOffset": ".nav", "hideDownloadButton": False, "theme": REDOC_THEME},
        separators=(",", ":"),
    )
    return REDOC_INIT_JS.replace("__OPTIONS__", options)


def _redoc_scripts() -> str:
    json.dumps(
        {"scrollYOffset": ".nav", "hideDownloadButton": False, "theme": REDOC_THEME},
        separators=(",", ":"),
    )
    return (
        f'<script src="{REDOC_JS_URL}"\n'
        f'  integrity="{REDOC_JS_INTEGRITY}" crossorigin="anonymous"></script>\n'
        '<script src="redoc-init.js"></script>'
    )


HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch")
UNTAGGED = "other"


def _api_operations(spec: dict) -> dict[str, list[tuple[str, str, str]]]:
    """Operations grouped by first tag, in spec order: {tag: [(METHOD, path, summary)]}."""
    groups: dict[str, list[tuple[str, str, str]]] = {}
    for path, item in spec.get("paths", {}).items():
        for method in HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            tag = (op.get("tags") or [UNTAGGED])[0]
            summary = op.get("summary") or op.get("operationId") or ""
            groups.setdefault(tag, []).append((method.upper(), path, summary))
    return groups


def _api_fallback(spec: dict) -> str:
    """Static reference: shown without JavaScript, replaced by Redoc when it starts.

    One h1, a short intro and the operations (method, path, summary) grouped by tag. The full
    schemas stay in the interactive view and in openapi.json.
    """
    info = spec.get("info", {})
    title = html.escape(f"{info.get('title', 'Sandfort')} API reference")
    version = html.escape(str(info.get("version", "")))
    groups = _api_operations(spec)
    count = sum(len(ops) for ops in groups.values())
    sections = []
    for tag, ops in groups.items():
        slug = re.sub(r"[^a-z0-9]+", "-", tag.lower()).strip("-") or UNTAGGED
        items = "\n".join(
            f'<li><code class="method">{m}</code> <code>{html.escape(p)}</code>'
            f"{' - ' + html.escape(summary) if summary else ''}</li>"
            for m, p, summary in ops
        )
        sections.append(
            f'<h2 id="tag-{slug}">{html.escape(tag)}</h2>\n<ul class="ops">\n{items}\n</ul>'
        )
    intro = (
        f"<p>REST API version {version}: {count} operations in {len(groups)} groups. Every "
        "operation except the health and status routes needs an API key sent as "
        "<code>Authorization: Bearer</code>. This list is the plain version of the "
        'interactive reference; the full specification is <a href="openapi.json">openapi.json</a>.'
        "</p>"
    )
    return (
        '<div class="frame"><div class="doc"><article class="prose api-static">\n'
        f"<h1>{title}</h1>\n{intro}\n" + "\n".join(sections) + "\n</article></div></div>"
    )


def build_api_page(spec: dict | None = None) -> str:
    if spec is None:
        spec = json.loads(SPEC_SOURCE.read_text(encoding="utf-8"))
    body = (
        '<p class="api-note" id="redoc-status" hidden>The interactive reference could not load. '
        'The raw specification is available as <a href="openapi.json">openapi.json</a>.</p>\n'
        f'<div id="redoc">\n{_api_fallback(spec)}\n</div>\n'
        '<noscript><p class="api-note">The interactive view needs JavaScript; the list above '
        'works without it. The raw specification is available as '
        '<a href="openapi.json">openapi.json</a>.</p></noscript>'
    )
    return render_page(
        title="API reference",
        description=API_DESCRIPTION,
        filename="index.html",
        body=body,
        scripts=_redoc_scripts(),
        always_dark=True,  # Redoc is embedded with a dark-only theme
    )


def build_not_found_page() -> str:
    """The 404 page: same chrome, noindex, no canonical; links are root-absolute."""
    items = "\n".join(
        f'<li><a href="{clean_path(href)}">{html.escape(label)}</a></li>'
        for href, label in DOC_LINKS
    )
    content = (
        "<h1>Page not found</h1>\n"
        "<p>This address does not match a page in the Sandfort documentation. "
        "Continue from one of these pages:</p>\n"
        f"<ul>\n{items}\n</ul>"
    )
    return render_page(
        title="Page not found",
        description=NOT_FOUND_DESCRIPTION,
        filename=NOT_FOUND_FILE,
        body=doc_body(content, ""),
        canonical=False,
        extra_head='<meta name="robots" content="noindex">',
        link_base="/",
    )


def build_robots() -> str:
    return f"User-agent: *\nDisallow:\n\nSitemap: {CANONICAL_BASE}{SITEMAP_FILE}\n"


def build_sitemap(filenames: list[str]) -> str:
    entries = "\n".join(
        f"  <url><loc>{html.escape(canonical_url(name))}</loc></url>" for name in filenames
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<urlset xmlns="{SITEMAP_NS}">\n{entries}\n</urlset>\n'
    )


def _short(text: str) -> str:
    if len(text) <= MAX_DESCRIPTION:
        return text
    cut = text[:MAX_DESCRIPTION].rsplit(" ", 1)[0]
    return cut.rstrip(".,;:") + "..."


TABLE_TITLE_RE = re.compile(r"^(?:\*\*(.+?)\*\*|(?:Table\s*\d*[:.]\s*)(.+?))\s*:?\s*$")
OPEN_TH_RE = re.compile(r"<th(?=[ >])")
COPY_BUTTON = '<button class="tool" type="button" data-copy>Copy</button>'
TABLE_WRAP = '<div class="tbl-wrap" tabindex="0">'


def _attr(text: str) -> str:
    """Escape plain or entity-escaped text for use inside a double-quoted attribute."""
    return html.escape(html.unescape(text), quote=True)


class AccessibleRenderer(Renderer):
    """Renderer that names what a screen reader meets: anchors, copy buttons, tables."""

    def __init__(self) -> None:
        super().__init__()
        self._code_blocks = 0
        self._tables_under: dict[int, int] = {}

    def _paragraph(self, lines: list[str], start: int, tight: bool) -> tuple[str, int]:
        rendered, end = super()._paragraph(lines, start, tight)
        if self.first_paragraph == "Contents":  # a label, not a summary of the page
            self.first_paragraph = ""
        return rendered, end

    def _heading(self, line: str) -> str:
        rendered = super()._heading(line)
        label = _attr(f"Link to section: {self.headings[-1].text}")
        return rendered.replace('aria-label="Link to this section"', f'aria-label="{label}"')

    def _fence(self, lines: list[str], start: int) -> tuple[str, int]:
        rendered, end = super()._fence(lines, start)
        match = FENCE_RE.match(lines[start])
        language = (match.group(3) if match else "") or "text"
        self._code_blocks += 1
        label = _attr(f"Copy code: {language} block {self._code_blocks}")
        button = COPY_BUTTON.replace("data-copy", f'aria-label="{label}" data-copy')
        return rendered.replace(COPY_BUTTON, button), end

    @staticmethod
    def _table_title(lines: list[str], start: int) -> str:
        """Text of a title line right above the table (a bold line or `Table: ...`), or ''."""
        k = start - 1
        while k >= 0 and not lines[k].strip():
            k -= 1
        if k < 0 or k < start - 2 or (k > 0 and lines[k - 1].strip()):
            return ""
        match = TABLE_TITLE_RE.match(lines[k].strip())
        return (match.group(1) or match.group(2)) if match else ""

    def _table(self, lines: list[str], start: int) -> tuple[str, int]:
        rendered, end = super()._table(lines, start)
        title = self._table_title(lines, start)
        heading = self.headings[-1].text if self.headings else ""
        under = len(self.headings)
        self._tables_under[under] = self._tables_under.get(under, 0) + 1
        nth = self._tables_under[under]
        name = title or heading
        label = f"Table: {name}" if name else "Table"
        if not title and nth > 1:
            label += f" ({nth})"
        table = OPEN_TH_RE.sub('<th scope="col"', rendered)
        if title:
            caption = f"<caption>{self.inline(title)}</caption>"
            table = table.replace("<table>", f"<table>{caption}", 1)
        wrap = f'<div class="tbl-wrap" role="region" aria-label="{_attr(label)}" tabindex="0">'
        return table.replace(TABLE_WRAP, wrap, 1), end


def drop_duplicate_contents(content: str) -> str:
    """Remove a hand-written "Contents" list; the generated contents list replaces it."""
    marker = "<p><strong>Contents</strong></p>\n<ol>"
    at = content.find(marker)
    if at < 0:
        return content
    depth, pos = 0, at + len(marker) - len("<ol>")
    for tag in re.finditer(r"</?ol[ >]", content[pos:]):
        depth += -1 if tag.group(0).startswith("</") else 1
        if depth == 0:
            end = content.index(">", pos + tag.start()) + 1
            return (content[:at] + content[end:]).lstrip("\n")
    return content


def _git(root: Path, *args: str) -> str | None:
    """Output of a git command run in `root`, or None when git or the repository is missing."""
    try:
        done = subprocess.run(
            ["git", *args],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = done.stdout.strip()
    return out if done.returncode == 0 and out else None


def current_release_text(root: Path) -> str:
    """The current tag and its commit as release-note prose, read from git at build time.

    Falls back to a static phrase when git, the repository or any tag is unavailable, so the
    page cannot go stale and the build never fails because of it.
    """
    tag = _git(root, "describe", "--tags", "--abbrev=0")
    commit = _git(root, "rev-list", "-n1", tag) if tag else None
    if tag is None or commit is None:
        return RELEASE_FALLBACK
    return f"the current tag `{tag}` (commit `{commit}`)"


def clean_docs_links(content: str) -> str:
    """Rewrite absolute links to this site's `.html` files to their clean-URL address."""
    return DOCS_HOST_HTML_LINK.sub(
        lambda m: f'href="{CANONICAL_BASE}{m.group(1)}{m.group(2) or ""}"', content
    )


def build_markdown_page(page: MarkdownPage, root: Path) -> tuple[str, list[str]]:
    """Return (page html, list of warnings)."""
    source = root / page.source
    renderer = AccessibleRenderer()
    text = source.read_text(encoding="utf-8")
    if RELEASE_TOKEN in text:
        text = text.replace(RELEASE_TOKEN, current_release_text(root))
    content = clean_docs_links(renderer.render(text))
    toc = toc_html(renderer.headings)
    if toc:
        content = drop_duplicate_contents(content)
    h1 = next((h for h in renderer.headings if h.level == 1), None)
    if h1 is None:
        raise ValueError(f"{page.source} has no level-1 heading")
    known = {h.id for h in renderer.headings}
    warnings = [
        f"{page.source}: link to #{t} has no matching heading"
        for t in dict.fromkeys(renderer.anchor_targets)
        if t not in known
    ]
    result = render_page(
        title=html.unescape(h1.text),
        description=_short(renderer.first_paragraph),
        filename=page.output,
        body=doc_body(content, toc),
    )
    return result, warnings


def compact_json(value: object) -> str:
    """Serialize without indentation; key order is kept (no sorting)."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, sort_keys=False)


def spec_sidecar(spec_path: Path) -> str:
    """`sha256sum` line for the byte-exact repository specification.

    The site copy is a compact re-serialisation, so only the parsed content is equal; the
    digest of the repository file lets a reader check which specification the copy came from.
    """
    digest = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    return f"{digest}  {SPEC_SIDECAR_LABEL}\n"


def build(out_dir: Path, root: Path = ROOT) -> list[str]:
    """Write the whole site into `out_dir`; return source warnings."""
    out_dir.mkdir(parents=True, exist_ok=True)
    spec_path = root / "openapi" / "sandfort.v1.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))  # fail early on an invalid spec
    (out_dir / "openapi.json").write_text(compact_json(spec), encoding="utf-8")
    (out_dir / SPEC_SIDECAR_FILE).write_text(spec_sidecar(spec_path), encoding="utf-8")
    (out_dir / "index.html").write_text(build_api_page(spec), encoding="utf-8")
    (out_dir / "redoc-init.js").write_text(_redoc_init_js(), encoding="utf-8")
    (out_dir / "docs.js").write_text(docs_theme.SCRIPT, encoding="utf-8")
    (out_dir / docs_theme.STYLESHEET_FILE).write_text(docs_theme.CSS, encoding="utf-8")
    warnings: list[str] = []
    for page in MARKDOWN_PAGES:
        rendered, page_warnings = build_markdown_page(page, root)
        (out_dir / page.output).write_text(rendered, encoding="utf-8")
        warnings.extend(page_warnings)
    published = ["index.html", *(page.output for page in MARKDOWN_PAGES)]
    (out_dir / NOT_FOUND_FILE).write_text(build_not_found_page(), encoding="utf-8")
    (out_dir / ROBOTS_FILE).write_text(build_robots(), encoding="utf-8")
    (out_dir / SITEMAP_FILE).write_text(build_sitemap(published), encoding="utf-8")
    return warnings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output directory")
    args = parser.parse_args(argv)
    warnings = build(args.out)
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    print(f"wrote docs site to {args.out}")
    print(f"note: {SPEC_SIDECAR_FILE} is informational and is not published (not a ConfigMap key)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
