"""Accessibility of the generated docs site: API page without JavaScript, landmarks, names."""

from __future__ import annotations

import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_docs_site as bds  # noqa: E402

MIN_TEXT_CONTRAST = 4.5
SPEC = json.loads((ROOT / "openapi" / "sandfort.v1.json").read_text(encoding="utf-8"))
CSS = (ROOT / "scripts" / "docs_site.css").read_text(encoding="utf-8")
MARKDOWN_PAGES = tuple(p.output for p in bds.MARKDOWN_PAGES)
ALL_PAGES = ("index.html", *MARKDOWN_PAGES, "404.html")


# ---- WCAG 2.x contrast ---------------------------------------------------------------------


def _rgb(color: str) -> tuple[float, float, float]:
    color = color.lstrip("#")
    return tuple(int(color[i : i + 2], 16) / 255 for i in (0, 2, 4))  # type: ignore[return-value]


def _channel(value: float) -> float:
    return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4


def luminance(color: str) -> float:
    r, g, b = (_channel(v) for v in _rgb(color))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(foreground: str, background: str) -> float:
    high, low = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def _blend(overlay: tuple[float, float, float, float], base: str) -> str:
    r, g, b, alpha = overlay
    mixed = [alpha * o + (1 - alpha) * c for o, c in zip((r, g, b), _rgb(base), strict=True)]
    return "#" + "".join(f"{round(v * 255):02x}" for v in mixed)


def _tokens(block: str) -> dict[str, str]:
    return dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})\b", block))


def _scheme_tokens() -> dict[str, dict[str, str]]:
    dark_block = CSS[CSS.index(":root{") : CSS.index("}", CSS.index(":root{"))]
    light_start = CSS.index(":root:not(.always-dark){")
    light_block = CSS[light_start : CSS.index("}", light_start)]
    dark = _tokens(dark_block)
    return {"dark": dark, "light": {**dark, **_tokens(light_block)}}


def _zebra(scheme: str, tokens: dict[str, str]) -> str:
    alpha_rgb = (255, 255, 255, 0.015) if scheme == "dark" else (0, 0, 0, 0.03)
    overlay = (alpha_rgb[0] / 255, alpha_rgb[1] / 255, alpha_rgb[2] / 255, alpha_rgb[3])
    return _blend(overlay, tokens["bg"])


# (foreground token, background token): every pair the stylesheet uses for text.
TEXT_PAIRS = (
    ("text", "bg"), ("text", "bg-1"), ("text", "bg-2"), ("text", "bg-3"),
    ("text-2", "bg"), ("text-2", "bg-1"), ("text-2", "bg-2"), ("text-2", "bg-3"),
    ("muted", "bg"), ("muted", "bg-1"), ("muted", "bg-2"), ("muted", "bg-3"),
    ("faint", "bg"), ("faint", "bg-1"), ("faint", "bg-2"), ("faint", "bg-3"),
    ("accent-text", "bg"), ("accent-text", "bg-1"), ("accent-text", "bg-2"),
    ("accent-2", "bg"), ("accent-2", "bg-1"), ("accent-2", "bg-2"),
    ("accent-ink", "accent"), ("accent-ink", "accent-hover"),
)  # fmt: skip


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_text_token_pairs_pass_aa(scheme: str) -> None:
    tokens = _scheme_tokens()[scheme]
    failures = []
    for fg, bg in TEXT_PAIRS:
        ratio = contrast(tokens[fg], tokens[bg])
        if ratio < MIN_TEXT_CONTRAST:
            failures.append(f"{scheme}: {fg} on {bg} is {ratio:.2f}")
    assert not failures, failures


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_table_cells_on_zebra_rows_pass_aa(scheme: str) -> None:
    tokens = _scheme_tokens()[scheme]
    zebra = _zebra(scheme, tokens)
    for fg in ("text-2", "text", "accent-2"):
        assert contrast(tokens[fg], zebra) >= MIN_TEXT_CONTRAST, (scheme, fg)


def test_contrast_function_matches_known_values() -> None:
    assert contrast("#000000", "#ffffff") == pytest.approx(21.0)
    assert contrast("#777777", "#ffffff") == pytest.approx(4.48, abs=0.01)
    assert contrast("#ffffff", "#ffffff") == pytest.approx(1.0)


def test_heading_anchor_is_not_dimmed_by_opacity_when_visible() -> None:
    anchor_rules = re.findall(r"\.anchor\{[^}]*\}", CSS)
    assert anchor_rules and "opacity:.45" not in CSS
    assert "color:var(--muted)" in anchor_rules[0]


# ---- built pages ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("docs-a11y")
    bds.build(out)
    return out


class _Dom(HTMLParser):
    """Collects headings, tags with their attributes, and the text inside noscript/main."""

    def __init__(self) -> None:
        super().__init__()
        self.headings: list[tuple[str, bool]] = []  # (tag, inside main)
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self._in_main = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        self.tags.append((tag, attributes))
        if tag == "main":
            self._in_main = True
        if re.fullmatch(r"h[1-6]", tag):
            self.headings.append((tag, self._in_main))

    def handle_endtag(self, tag: str) -> None:
        if tag == "main":
            self._in_main = False

    def find(self, tag: str) -> list[dict[str, str | None]]:
        return [a for t, a in self.tags if t == tag]


def _dom(built: Path, name: str) -> _Dom:
    dom = _Dom()
    dom.feed((built / name).read_text(encoding="utf-8"))
    return dom


def test_api_page_has_one_h1_and_static_operations_without_javascript(built: Path) -> None:
    page = (built / "index.html").read_text(encoding="utf-8")
    dom = _dom(built, "index.html")
    assert [t for t, _ in dom.headings].count("h1") == 1
    container = page[page.index('<div id="redoc">') : page.index("</main>")]
    assert "<h1>" in container and "<h2 " in container
    operations = [
        (method.upper(), path)
        for path, item in SPEC["paths"].items()
        for method in item
        if method in bds.HTTP_METHODS
    ]
    assert operations  # every operation of the committed spec must appear below
    for method, path in operations:
        assert f'<code class="method">{method}</code> <code>{path}</code>' in container, (
            method,
            path,
        )


def test_api_page_groups_follow_the_spec_tags_and_keep_summaries(built: Path) -> None:
    page = (built / "index.html").read_text(encoding="utf-8")
    tags = {tag for item in SPEC["paths"].values() for op in item.values() for tag in op["tags"]}
    for tag in tags:
        assert f">{tag}</h2>" in page
    assert "Create Api Key" in page


def test_api_page_fallback_does_not_blow_the_pages_budget(built: Path) -> None:
    assert (built / "index.html").stat().st_size < 30_000


def test_api_page_still_loads_redoc_into_the_container(built: Path) -> None:
    page = (built / "index.html").read_text(encoding="utf-8")
    assert "redoc.standalone.js" in page
    assert 'document.getElementById("redoc")' in (built / "redoc-init.js").read_text()


@pytest.mark.parametrize("name", ALL_PAGES)
def test_footer_does_not_use_headings(built: Path, name: str) -> None:
    page = (built / name).read_text(encoding="utf-8")
    footer = page[page.index("<footer>") :]
    assert not re.search(r"<h[1-6]", footer)
    for label in ("Product", "Developers", "Contact"):
        ident = f"footer-{label.lower()}"
        assert f'<p class="fh" id="{ident}">{label}</p>' in footer
        assert f'aria-labelledby="{ident}"' in footer


@pytest.mark.parametrize("name", ALL_PAGES)
def test_every_heading_is_inside_main_and_h1_is_unique(built: Path, name: str) -> None:
    dom = _dom(built, name)
    assert all(in_main for _, in_main in dom.headings)
    assert [t for t, _ in dom.headings].count("h1") == 1


@pytest.mark.parametrize("name", MARKDOWN_PAGES)
def test_tables_are_regions_with_names_and_column_headers(built: Path, name: str) -> None:
    page = (built / name).read_text(encoding="utf-8")
    dom = _dom(built, name)
    wraps = [a for a in dom.find("div") if "tbl-wrap" in (a.get("class") or "")]
    assert len(wraps) == page.count("<table")
    labels = []
    for attrs in wraps:
        assert attrs.get("role") == "region" and attrs.get("tabindex") == "0"
        assert (attrs.get("aria-label") or "").startswith("Table")
        labels.append(attrs["aria-label"])
    assert len(set(labels)) == len(labels), "region names must be distinct on a page"
    assert "<th>" not in page
    for header in dom.find("th"):
        assert header.get("scope") == "col"


@pytest.mark.parametrize("name", MARKDOWN_PAGES)
def test_heading_anchors_are_named_after_their_section(built: Path, name: str) -> None:
    page = (built / name).read_text(encoding="utf-8")
    assert "Link to this section" not in page
    names = re.findall(r'class="anchor" href="#[^"]+" aria-label="([^"]+)"', page)
    assert names and all(n.startswith("Link to section: ") for n in names)
    assert len(set(names)) == len(names)
    assert len(names) == page.count('class="anchor"')


def test_copy_buttons_are_named_numbered_and_announced(built: Path) -> None:
    page = (built / "guide.html").read_text(encoding="utf-8")
    labels = re.findall(r'aria-label="(Copy code: [^"]+)" data-copy', page)
    blocks = len(re.findall(r"<pre[\s>]", page))  # one copy button per code block
    assert blocks > 0
    assert len(labels) == page.count("data-copy") == blocks
    assert len(set(labels)) == blocks
    assert re.fullmatch(r"Copy code: [\w+#.-]+ block 1", labels[0])
    assert 'id="copy-status" role="status" aria-live="polite"' in page
    assert "copy-status" in (built / "docs.js").read_text(encoding="utf-8")
    assert "'Copied'" in (built / "docs.js").read_text(encoding="utf-8")


def test_pages_without_code_blocks_carry_no_copy_status(built: Path) -> None:
    assert "copy-status" not in (built / "isolation-tiers.html").read_text(encoding="utf-8")


def test_guide_has_one_contents_list(built: Path) -> None:
    page = (built / "guide.html").read_text(encoding="utf-8")
    assert "<p><strong>Contents</strong></p>" not in page
    assert page.count('class="toc"') == 1
    assert "1-what-you-receive-from-the-maintainer" in page


def test_guide_description_is_not_the_contents_label(built: Path) -> None:
    page = (built / "guide.html").read_text(encoding="utf-8")
    assert 'name="description" content="Contents"' not in page


# ---- renderer units ------------------------------------------------------------------------


def test_renderer_adds_caption_scope_region_and_numbered_copy_labels() -> None:
    md = (
        "# Title\n\n## Limits\n\n**Quota table**\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n"
        "| c |\n|---|\n| 3 |\n\n```python\nprint(1)\n```\n\n```\nplain\n```\n"
    )
    out = bds.AccessibleRenderer().render(md)
    assert (
        '<div class="tbl-wrap" role="region" aria-label="Table: Quota table" tabindex="0">' in out
    )
    assert "<caption>Quota table</caption>" in out
    assert out.count('<th scope="col">') == 3
    assert 'aria-label="Table: Limits (2)"' in out
    assert 'aria-label="Copy code: python block 1" data-copy' in out
    assert 'aria-label="Copy code: text block 2" data-copy' in out
    assert 'aria-label="Link to section: Limits"' in out


def test_table_title_requires_a_standalone_line() -> None:
    md = "## H\n\nsome text **bold**\n| a |\n|---|\n| 1 |\n"
    out = bds.AccessibleRenderer().render(md)
    assert "<caption>" not in out
    assert 'aria-label="Table: H"' in out


def test_heading_labels_escape_markup() -> None:
    out = bds.AccessibleRenderer().render('# A "quoted" <b> & `code`\n')
    assert 'aria-label="Link to section: A &quot;quoted&quot; &lt;b&gt; &amp; code"' in out


def test_drop_duplicate_contents_removes_nested_list_and_keeps_the_rest() -> None:
    content = (
        "<p><strong>Contents</strong></p>\n<ol>\n<li><a>x</a><ol>\n<li>y</li>\n</ol></li>\n"
        "</ol>\n<p>After</p>"
    )
    assert bds.drop_duplicate_contents(content) == "<p>After</p>"
    assert bds.drop_duplicate_contents("<p>No list</p>") == "<p>No list</p>"
