"""Comparison page (site/compare.html): wiring, analytics and anchor integrity."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMPARE = (ROOT / "site" / "compare.html").read_text(encoding="utf-8")
INDEX = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
SITEMAP = (ROOT / "site" / "sitemap.xml").read_text(encoding="utf-8")
LLMS = (ROOT / "site" / "llms.txt").read_text(encoding="utf-8")

CANONICAL = "https://sandfort.dev/compare.html"
WEBSITE_ID_RE = re.compile(r'data-website-id="([^"]+)"')


def test_umami_website_id_matches_landing() -> None:
    compare_ids = set(WEBSITE_ID_RE.findall(COMPARE))
    index_ids = set(WEBSITE_ID_RE.findall(INDEX))
    assert len(compare_ids) == 1
    assert compare_ids == index_ids


def test_canonical_url_is_wired() -> None:
    assert f'<link rel="canonical" href="{CANONICAL}">' in COMPARE
    assert f"<loc>{CANONICAL}</loc>" in SITEMAP
    assert CANONICAL in LLMS
    assert 'href="/compare.html"' in INDEX  # footer link on the landing


def test_tables_have_accessible_labels() -> None:
    tables = re.findall(r"<table[^>]*>", COMPARE)
    assert len(tables) == 2
    assert all("aria-label=" in tag for tag in tables)


def test_landing_anchor_links_resolve() -> None:
    anchors = set(re.findall(r'href="https://sandfort\.dev/#([a-z-]+)"', COMPARE))
    assert anchors  # the nav links to landing sections
    index_ids = set(re.findall(r'id="([^"]+)"', INDEX))
    missing = anchors - index_ids
    assert not missing, f"compare.html links to missing landing ids: {sorted(missing)}"


def test_no_placeholder_markers() -> None:
    # Markers are concatenated so this file itself passes the export placeholder gate.
    markers = (
        "[REPO" + "_URL]",
        "[COMPARISON" + "_URL]",
        "TREBA " + "POTVRDU",
        "RE-" + "VERIFY",
    )
    for marker in markers:
        assert marker not in COMPARE
