"""Small Markdown to HTML converter for the docs site (standard library only).

It covers the constructs the repo's own docs use: ATX headings, paragraphs, nested bullet and
numbered lists, fenced code blocks, pipe tables, horizontal rules, links, inline code, bold and
italic. All text is HTML-escaped; raw HTML in the source is never passed through.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

FENCE_RE = re.compile(r"^( *)(`{3,}|~{3,})\s*([^`\s]*)[^`]*$")
HEADING_RE = re.compile(r"^ {0,3}(#{1,6})\s+(.*?)(?:\s+#+)?\s*$")
HR_RE = re.compile(r"^ {0,3}([-*_])(?: *\1){2,} *$")
LIST_RE = re.compile(r"^( *)([-*+]|\d{1,9}[.)])( +|$)(.*)$")
COMMENT_RE = re.compile(r"^\s*<!--.*-->\s*$")
SEPARATOR_CELL_RE = re.compile(r"^:?-+:?$")
CODE_SPAN_RE = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)", re.DOTALL)
ESCAPE_RE = re.compile(r"\\([\\`*_{}\[\]()#+\-.!|<>])")
AUTOLINK_RE = re.compile(r"&lt;(https?://[^\s<>&]+)&gt;")
LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
BOLD_RE = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*", re.DOTALL)
ITALIC_RE = re.compile(r"(?<![\w*])\*(?=[^\s*])(.+?)(?<=[^\s*])\*(?![\w*])", re.DOTALL)
PLACEHOLDER_RE = re.compile(r"\x00(\d+)\x00")
SAFE_URL_RE = re.compile(r"^(https?://|mailto:|#|[^:]*$)")


@dataclass(frozen=True)
class Heading:
    level: int
    id: str
    html: str
    text: str


def slugify(raw: str) -> str:
    """GitHub-style heading slug, so in-document `#anchor` links in the sources keep working."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", raw)
    text = re.sub(r"[`*]", "", text).lower()
    text = re.sub(r"[^\w\s-]", "", text).strip()
    return re.sub(r"\s", "-", text)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _split_row(line: str) -> list[str]:
    """Split a pipe-table row on `|`, ignoring pipes inside code spans and escaped pipes."""
    body = line.strip().removeprefix("|")
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    cells: list[str] = []
    current: list[str] = []
    in_code = 0
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "`":
            run = len(re.match(r"`+", body[i:]).group(0))  # type: ignore[union-attr]
            current.append(body[i : i + run])
            if in_code == 0:
                in_code = run
            elif in_code == run:
                in_code = 0
            i += run
        elif ch == "\\" and body[i + 1 : i + 2] == "|":
            current.append("|")
            i += 2
        elif ch == "|" and not in_code:
            cells.append("".join(current).strip())
            current = []
            i += 1
        else:
            current.append(ch)
            i += 1
    cells.append("".join(current).strip())
    return cells


def _is_separator(line: str) -> bool:
    if "|" not in line:
        return False
    cells = _split_row(line)
    return bool(cells) and all(SEPARATOR_CELL_RE.match(c) for c in cells)


def _alignment(cell: str) -> str:
    left, right = cell.startswith(":"), cell.endswith(":")
    if left and right:
        return "center"
    return "right" if right else ""


class Renderer:
    """Convert one Markdown document. Headings and in-page link targets are collected."""

    def __init__(self) -> None:
        self.headings: list[Heading] = []
        self.anchor_targets: list[str] = []
        self.first_paragraph = ""
        self._used_ids: dict[str, int] = {}
        self._depth = 0

    # ---- inline -------------------------------------------------------------------------

    def inline(self, text: str) -> str:
        stash: list[str] = []

        def keep(fragment: str) -> str:
            stash.append(fragment)
            return f"\x00{len(stash) - 1}\x00"

        def code(m: re.Match[str]) -> str:
            inner = m.group(2).replace("\n", " ")
            if len(inner) > 2 and inner.startswith(" ") and inner.endswith(" "):
                inner = inner[1:-1]
            return keep(f"<code>{html.escape(inner)}</code>")

        text = CODE_SPAN_RE.sub(code, text)
        text = ESCAPE_RE.sub(lambda m: keep(html.escape(m.group(1))), text)
        text = html.escape(text)
        text = AUTOLINK_RE.sub(lambda m: keep(self._anchor(m.group(1), m.group(1))), text)
        text = LINK_RE.sub(lambda m: keep(self._anchor(m.group(2), m.group(1))), text)
        text = BOLD_RE.sub(r"<strong>\1</strong>", text)
        text = ITALIC_RE.sub(r"<em>\1</em>", text)
        # Placeholders can nest (a link whose text holds a code span), so resolve until stable.
        while PLACEHOLDER_RE.search(text):
            text = PLACEHOLDER_RE.sub(lambda m: stash[int(m.group(1))], text)
        return text

    def _anchor(self, href: str, label: str) -> str:
        raw_href = html.unescape(href)
        if not SAFE_URL_RE.match(raw_href):
            return label
        if raw_href.startswith("#"):
            self.anchor_targets.append(raw_href[1:])
        return f'<a href="{html.escape(raw_href)}">{label}</a>'

    # ---- blocks -------------------------------------------------------------------------

    def render(self, markdown: str) -> str:
        lines = markdown.replace("\r\n", "\n").split("\n")
        return "\n".join(self._blocks(lines, tight=False))

    def _blocks(self, lines: list[str], tight: bool) -> list[str]:
        out: list[str] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if not line.strip() or COMMENT_RE.match(line):
                i += 1
            elif FENCE_RE.match(line):
                block, i = self._fence(lines, i)
                out.append(block)
            elif HEADING_RE.match(line):
                out.append(self._heading(line))
                i += 1
            elif HR_RE.match(line):
                out.append("<hr>")
                i += 1
            elif self._table_starts(lines, i):
                block, i = self._table(lines, i)
                out.append(block)
            elif LIST_RE.match(line):
                block, i = self._list(lines, i)
                out.append(block)
            else:
                block, i = self._paragraph(lines, i, tight)
                out.append(block)
        return out

    def _heading(self, line: str) -> str:
        m = HEADING_RE.match(line)
        assert m is not None
        level, raw = len(m.group(1)), m.group(2)
        base = slugify(raw) or "section"
        count = self._used_ids.get(base, 0)
        self._used_ids[base] = count + 1
        slug = base if count == 0 else f"{base}-{count}"
        inner = self.inline(raw)
        self.headings.append(Heading(level, slug, inner, re.sub(r"<[^>]+>", "", inner)))
        anchor = f'<a class="anchor" href="#{slug}" aria-label="Link to this section">#</a>'
        return f'<h{level} id="{slug}">{inner}{anchor}</h{level}>'

    def _fence(self, lines: list[str], start: int) -> tuple[str, int]:
        m = FENCE_RE.match(lines[start])
        assert m is not None
        indent, fence, lang = len(m.group(1)), m.group(2), m.group(3)
        body: list[str] = []
        i = start + 1
        while i < len(lines):
            stripped = lines[i].strip()
            if stripped and set(stripped) == {fence[0]} and len(stripped) >= len(fence):
                i += 1
                break
            body.append(lines[i][min(indent, _indent(lines[i])) :])
            i += 1
        label = f'<span class="tab static">{html.escape(lang)}</span>' if lang else ""
        button = '<button class="tool" type="button" data-copy>Copy</button>'
        rail = f'<div class="rail">{label}{button}</div>'
        code = html.escape("\n".join(body))
        return f'<div class="slab">{rail}<pre class="code"><code>{code}</code></pre></div>', i

    def _table(self, lines: list[str], start: int) -> tuple[str, int]:
        header = _split_row(lines[start])
        aligns = [_alignment(c) for c in _split_row(lines[start + 1])]
        rows: list[list[str]] = []
        i = start + 2
        while i < len(lines) and lines[i].strip() and "|" in lines[i]:
            rows.append(_split_row(lines[i]))
            i += 1
        width = len(header)

        def cell(tag: str, text: str, col: int) -> str:
            align = aligns[col] if col < len(aligns) else ""
            style = f' style="text-align:{align}"' if align else ""
            return f"<{tag}{style}>{self.inline(text)}</{tag}>"

        head = "".join(cell("th", c, k) for k, c in enumerate(header))
        body_rows = []
        for row in rows:
            padded = (row + [""] * width)[:width]
            tds = "".join(cell("td", c, k) for k, c in enumerate(padded))
            body_rows.append(f"<tr>{tds}</tr>")
        table = f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"
        return f'<div class="tbl-wrap" tabindex="0">{table}</div>', i

    @staticmethod
    def _table_starts(lines: list[str], i: int) -> bool:
        return (
            lines[i].lstrip().startswith("|")
            and i + 1 < len(lines)
            and _is_separator(lines[i + 1])
        )

    def _interrupts_paragraph(self, lines: list[str], i: int) -> bool:
        line = lines[i]
        if (
            FENCE_RE.match(line)
            or HEADING_RE.match(line)
            or HR_RE.match(line)
            or COMMENT_RE.match(line)
        ):
            return True
        if self._table_starts(lines, i):
            return True
        m = LIST_RE.match(line)
        if m and m.group(4).strip():
            marker = m.group(2)
            return not marker[0].isdigit() or marker[:-1] == "1"
        return False

    def _paragraph(self, lines: list[str], start: int, tight: bool) -> tuple[str, int]:
        parts = [lines[start].strip()]
        i = start + 1
        while i < len(lines) and lines[i].strip() and not self._interrupts_paragraph(lines, i):
            parts.append(lines[i].strip())
            i += 1
        text = "\n".join(parts)
        rendered = self.inline(text)
        if self._depth == 0 and not self.first_paragraph:
            plain = html.unescape(re.sub(r"<[^>]+>", "", rendered))
            self.first_paragraph = re.sub(r"\s+", " ", plain)
        return (rendered if tight else f"<p>{rendered}</p>"), i

    def _list(self, lines: list[str], start: int) -> tuple[str, int]:
        first = LIST_RE.match(lines[start])
        assert first is not None
        base = len(first.group(1))
        ordered = first.group(2)[0].isdigit()
        number = int(first.group(2)[:-1]) if ordered else 1
        items: list[list[str]] = []
        cur: list[str] | None = None
        content_indent = 0
        in_fence = False
        loose = False
        i = start
        while i < len(lines):
            line = lines[i]
            if not line.strip():
                nxt = next((k for k in range(i + 1, len(lines)) if lines[k].strip()), None)
                if nxt is None or cur is None:
                    break
                nm = LIST_RE.match(lines[nxt])
                continues = _indent(lines[nxt]) > base or in_fence
                sibling = (
                    nm is not None
                    and len(nm.group(1)) == base
                    and nm.group(2)[0].isdigit() == ordered
                )
                if not (continues or sibling):
                    break
                cur.append("")
                loose = loose or not in_fence
                i += 1
                continue
            mk = LIST_RE.match(line)
            ind = _indent(line)
            if cur is not None and in_fence:
                cur.append(line[min(ind, content_indent) :])
                in_fence = self._toggle_fence(line, in_fence)
                i += 1
                continue
            if mk and ind == base and mk.group(2)[0].isdigit() == ordered:
                cur = [mk.group(4)]
                items.append(cur)
                content_indent = ind + len(mk.group(2)) + len(mk.group(3))
                in_fence = self._toggle_fence(mk.group(4), False)
            elif mk and ind <= base:
                break
            elif cur is not None and ind > base:
                cur.append(line[min(ind, content_indent) :])
                in_fence = self._toggle_fence(line, in_fence)
            elif cur is not None and cur[-1].strip() and not self._interrupts_paragraph(lines, i):
                cur.append(line.strip())
            else:
                break
            i += 1
        tag = "ol" if ordered else "ul"
        attr = f' start="{number}"' if ordered and number != 1 else ""
        rendered = []
        for item in items:
            while item and not item[-1].strip():
                item.pop()
            self._depth += 1
            body = "\n".join(self._blocks(item, tight=not loose))
            self._depth -= 1
            rendered.append(f"<li>{body}</li>")
        return f"<{tag}{attr}>\n" + "\n".join(rendered) + f"\n</{tag}>", i

    @staticmethod
    def _toggle_fence(line: str, in_fence: bool) -> bool:
        if FENCE_RE.match(line) or line.strip().startswith(("```", "~~~")):
            return not in_fence
        return in_fence


def toc_html(headings: list[Heading]) -> str:
    """Nested contents list from h2 and h3 headings; empty string when there are none."""
    entries = [h for h in headings if h.level in (2, 3)]
    if not entries:
        return ""
    parts = ["<ul>"]
    open_li = open_sub = False
    for h in entries:
        link = f'<a href="#{h.id}">{h.html}</a>'
        if h.level == 3 and open_li:
            if not open_sub:
                parts.append("<ul>")
                open_sub = True
            parts.append(f"<li>{link}</li>")
            continue
        if open_sub:
            parts.append("</ul>")
            open_sub = False
        if open_li:
            parts.append("</li>")
        parts.append(f"<li>{link}")
        open_li = True
    if open_sub:
        parts.append("</ul>")
    parts.append("</li></ul>")
    return "".join(parts)
