"""Round 65: landing accessibility, landing 404, /docs redirect, API edge 413, docs notes."""

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
INDEX = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
NOT_FOUND = (ROOT / "site" / "404.html").read_text(encoding="utf-8")
LANDING_CONF = (ROOT / "deploy" / "static-nginx" / "landing.conf").read_text(encoding="utf-8")
DOCS_CONF = (ROOT / "deploy" / "static-nginx" / "docs.conf").read_text(encoding="utf-8")
DEPLOY_SCRIPT = ROOT / "deploy" / "redeploy-beta.sh"
INGRESS = (ROOT / "deploy" / "k8s" / "ingress.yaml").read_text(encoding="utf-8")
OPERATIONS = (ROOT / "docs" / "operations.md").read_text(encoding="utf-8")
RELEASE = (ROOT / "docs" / "release.md").read_text(encoding="utf-8")
GUIDE_PATH = ROOT / "docs" / "connect-guide.md"
MAX_TAB_NAME_WORDS = 4


class Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


def tags(html: str) -> list[tuple[str, dict[str, str | None]]]:
    parser = Tags()
    parser.feed(html)
    return parser.tags


def test_landing_footer_uses_labelled_lists_not_headings() -> None:
    footer = INDEX[INDEX.index("<footer>") :]
    assert not re.search(r"<h[1-6]", footer)
    for name in ("product", "developers", "contact"):
        assert f'<p class="fh" id="footer-{name}">' in footer
        assert f'aria-labelledby="footer-{name}"' in footer


def test_feature_tabs_have_short_accessible_names() -> None:
    feature = [
        attrs
        for tag, attrs in tags(INDEX)
        if tag == "button" and attrs.get("role") == "tab" and str(attrs.get("id")).startswith("b-")
    ]
    assert len(feature) == 5
    for attrs in feature:
        label = attrs.get("aria-label") or ""
        assert 2 <= len(label.split()) <= MAX_TAB_NAME_WORDS, label


def test_landing_tables_have_an_accessible_name() -> None:
    tables = [attrs for tag, attrs in tags(INDEX) if tag == "table"]
    assert len(tables) == 2
    assert all(attrs.get("aria-label") for attrs in tables)


def test_governance_and_isolation_tier_links_do_not_share_text_across_targets() -> None:
    pattern = re.compile(r'<a [^>]*href="([^"]*)"[^>]*>(Governance|Isolation tiers)</a>')
    targets: dict[str, set[str]] = {}
    pages = [ROOT / "site" / "index.html", *sorted((ROOT / "site" / "docs").glob("*.html"))]
    for page in pages:
        for href, text in pattern.findall(page.read_text(encoding="utf-8")):
            targets.setdefault(text, set()).add(href)
    for text, hrefs in targets.items():
        page_links = {h for h in hrefs if "#" not in h}
        section_links = hrefs - page_links
        assert len(page_links) <= 1 and (not page_links or not section_links), (text, hrefs)


@pytest.mark.skipif(
    not DEPLOY_SCRIPT.is_file(), reason="private ops script not present in public tree"
)
def test_landing_404_page_is_shipped_by_the_deploy_script() -> None:
    assert '"404.html=$ROOT/site/404.html"' in DEPLOY_SCRIPT.read_text(encoding="utf-8")


def test_landing_404_page_and_nginx_wiring() -> None:
    assert '<html lang="en">' in NOT_FOUND
    assert 'class="skip"' in NOT_FOUND
    assert 'href="/"' in NOT_FOUND and "https://docs.sandfort.dev/" in NOT_FOUND
    assert "error_page 404 /404.html;" in LANDING_CONF
    assert "location = /404.html {" in LANDING_CONF and "internal;" in LANDING_CONF


def test_docs_path_redirects_to_the_api_reference() -> None:
    assert "location = /docs { return 301 /; }" in DOCS_CONF


def test_api_edge_example_caps_bodies_and_answers_413_as_json() -> None:
    assert 'proxy-body-size: "257m"' in INGRESS
    assert "error_page 413" in INGRESS
    assert "application/json" in INGRESS
    assert '"code":"PAYLOAD_TOO_LARGE"' in INGRESS


def test_docs_notes() -> None:
    assert "`max_sandboxes` is\n  the node's `SANDFORT_NODE_MAX_SANDBOXES`" in OPERATIONS
    assert "`0` means no per-node cap" in OPERATIONS
    assert "repository is private" in RELEASE and "FSL-1.1-Apache-2.0" in RELEASE


def test_guide_webhook_retry_text_matches_the_dispatcher() -> None:
    guide = GUIDE_PATH.read_text(encoding="utf-8")
    assert "first retry comes about 5 seconds" in guide
    assert "WEBHOOK_DISPATCH_INTERVAL_S" in guide
    assert guide.count("sandfort_cli-0.1.0bNN") == 1
