"""Tests for scripts/build_docs_site.py (generates the docs.sandfort.dev pages)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path
from xml.etree import ElementTree

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
PAGES = (
    "index.html",
    "quickstart.html",
    "guide.html",
    "operations.html",
    "security.html",
    "isolation-tiers.html",
    "beta-terms.html",
    "release.html",
    "governance.html",
)
MARKDOWN_PAGES = tuple(name for name in PAGES if name != "index.html")
MD_LINK = re.compile(r"""href=["'][^"']*\.md(?:#[^"']*)?["']""")
VOID_TAGS = {"meta", "link", "base", "br", "hr", "img", "input"}

sys.path.insert(0, str(SCRIPTS))
from docs_md import Renderer, slugify, toc_html  # noqa: E402
from docs_theme import UMAMI_HOST  # noqa: E402

UMAMI_SCRIPT = f"{UMAMI_HOST}/script.js"


class _TagBalance(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.errors: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in VOID_TAGS:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID_TAGS:
            return
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
        else:
            self.errors.append(f"unexpected </{tag}> at {self.getpos()}")


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("docs-site")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "build_docs_site.py"), "--out", str(out)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return out


def test_generator_writes_all_pages_and_spec(built: Path) -> None:
    for name in (*PAGES, "openapi.json"):
        assert (built / name).is_file(), name


DEPLOY_SCRIPT = ROOT / "deploy" / "redeploy-beta.sh"

needs_private_ops = pytest.mark.skipif(
    not DEPLOY_SCRIPT.is_file(),
    reason="private ops script not present in public tree",
)
DEPLOY_KEY = re.compile(r'"([^"=$\s]+)=\$d/([^"\s]+)"')
NOT_FOUND = "404.html"
ROBOTS = "robots.txt"
SITEMAP = "sitemap.xml"
LLMS = "llms.txt"
SEO_FILES = (NOT_FOUND, ROBOTS, SITEMAP, LLMS)
STYLESHEET = "docs.css"
BUILT_EXTRAS = ("openapi.json", "redoc-init.js", "docs.js", STYLESHEET, *SEO_FILES)
SPEC_SOURCE = ROOT / "openapi" / "sandfort.v1.json"
# Informational sidecar: built next to the spec copy but not published (not a ConfigMap key).
SPEC_SIDECAR = "openapi.json.sha256"
STYLESHEET_HASH_LENGTH = 12
# The ConfigMap limit is 1 MiB (1,048,576). The site is two ConfigMaps (pages, spec) and each one
# is held to these numbers separately. The stylesheet is one shared file, not inlined.
MAX_BUILT_BYTES = 1_000_000
# Margin under the limit per ConfigMap, so the next page does not cross it silently.
MARGIN_BUILT_BYTES = 900_000
PAGES_CONFIGMAP = "sandfort-docs"
SPEC_CONFIGMAP = "sandfort-docs-spec"
CANONICAL_BASE = "https://docs.sandfort.dev/"


def _deploy_configmap_keys(name_expression: str) -> dict[str, str]:
    """Keys of one `replace_configmap` call in deploy_docs, up to the next statement."""
    text = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    block = text[text.index(f"replace_configmap {name_expression}") :]
    lines = block.splitlines()
    call = [lines[0]]
    for line in lines[1:]:
        if not call[-1].endswith("\\"):
            break
        call.append(line)
    return dict(DEPLOY_KEY.findall("\n".join(call)))


def _deploy_pages_keys() -> dict[str, str]:
    return _deploy_configmap_keys(PAGES_CONFIGMAP)


def _deploy_spec_keys() -> dict[str, str]:
    return _deploy_configmap_keys('"$DOCS_SPEC_CM"')


def _deploy_docs_keys() -> dict[str, str]:
    """Union of both ConfigMaps; a key in both would be a conflict, tested separately."""
    return {**_deploy_pages_keys(), **_deploy_spec_keys()}


@needs_private_ops
def test_deploy_script_lists_exactly_the_built_files(built: Path) -> None:
    keys = _deploy_docs_keys()
    assert all(key == path for key, path in keys.items())
    built_names = {p.name for p in built.iterdir() if p.is_file()} - {SPEC_SIDECAR}
    assert SPEC_SIDECAR not in keys  # informational, not published
    assert set(keys) == {*PAGES, *BUILT_EXTRAS}
    assert set(SEO_FILES) <= set(keys)
    assert set(keys) == built_names


def test_build_writes_not_found_robots_and_sitemap(built: Path) -> None:
    for name in SEO_FILES:
        assert (built / name).is_file(), name


def test_not_found_page_has_subnav_noindex_and_no_canonical(built: Path) -> None:
    text = (built / NOT_FOUND).read_text(encoding="utf-8")
    assert "Page not found" in text
    assert '<meta name="robots" content="noindex">' in text
    assert 'rel="canonical"' not in text
    subnav = text[text.index('class="subnav"') :]
    subnav = subnav[: subnav.index("</nav>")]
    for page in PAGES:
        assert f'href="{_clean(page)}"' in subnav, page
    parser = _TagBalance()
    parser.feed(text)
    assert parser.errors == []
    assert parser.stack == []


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.hrefs: list[str] = []
        self.script_srcs: list[str] = []
        self.stylesheets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        self.tags.append(tag)
        if tag == "link" and values.get("rel") == "stylesheet" and values.get("href"):
            self.stylesheets.append(str(values["href"]))
        if tag == "a" and values.get("href") is not None:
            self.hrefs.append(str(values["href"]))
        elif tag == "script" and values.get("src") is not None:
            self.script_srcs.append(str(values["src"]))


EXTERNAL_PREFIXES = ("https://", "mailto:", "data:")


def _links(path: Path) -> _Links:
    parser = _Links()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser


def _local_stylesheets(links: _Links) -> list[str]:
    return [h for h in links.stylesheets if not h.startswith(EXTERNAL_PREFIXES)]


def _clean(name: str) -> str:
    """Root-absolute clean-URL path of a page: `guide.html` is `/guide`, the index `/`."""
    return "/" if name == "index.html" else "/" + name.removesuffix(".html")


def _built_stylesheet_hash(built: Path) -> str:
    digest = hashlib.sha256((built / STYLESHEET).read_bytes()).hexdigest()
    return digest[:STYLESHEET_HASH_LENGTH]


def test_every_page_links_the_stylesheet_with_its_content_hash(built: Path) -> None:
    expected = f"docs.css?v={_built_stylesheet_hash(built)}"
    assert re.fullmatch(r"docs\.css\?v=[0-9a-f]{12}", expected)
    for name in PAGES:
        assert _local_stylesheets(_links(built / name)) == [expected], name


def test_not_found_page_uses_the_root_absolute_hashed_stylesheet(built: Path) -> None:
    expected = f"/docs.css?v={_built_stylesheet_hash(built)}"
    assert _local_stylesheets(_links(built / NOT_FOUND)) == [expected]


@needs_private_ops
def test_spec_sidecar_holds_the_sha256_of_the_repository_specification(built: Path) -> None:
    # The sidecar is informational: built next to the copy, but not a ConfigMap key.
    sidecar = (built / SPEC_SIDECAR).read_text(encoding="utf-8")
    repo_hash = hashlib.sha256(SPEC_SOURCE.read_bytes()).hexdigest()
    assert sidecar.split() == [repo_hash, "openapi/sandfort.v1.json"]
    assert sidecar.endswith("\n")
    assert SPEC_SIDECAR not in _deploy_docs_keys()


def test_committed_spec_sidecar_matches_the_repository_specification() -> None:
    committed = (ROOT / "site" / "docs" / SPEC_SIDECAR).read_text(encoding="utf-8")
    assert committed.split()[0] == hashlib.sha256(SPEC_SOURCE.read_bytes()).hexdigest()


def test_release_page_documents_the_spec_copy_equality() -> None:
    text = (ROOT / "docs" / "release.md").read_text(encoding="utf-8")
    assert SPEC_SIDECAR in text
    assert "semantically equal" in text


def test_not_found_page_has_no_base_element(built: Path) -> None:
    # The docs CSP sets base-uri 'none', so browsers ignore a base element.
    assert "base" not in _links(built / NOT_FOUND).tags


def test_not_found_page_links_and_script_are_root_absolute(built: Path) -> None:
    links = _links(built / NOT_FOUND)
    local = [h for h in links.hrefs if not h.startswith(EXTERNAL_PREFIXES)]
    assert local
    assert all(h.startswith(("/", "#")) for h in local), local
    for page in PAGES:
        assert _clean(page) in local, page
    assert "#main" in links.hrefs
    assert links.script_srcs == [UMAMI_SCRIPT, "/docs.js"]
    assert _local_stylesheets(links) == [f"/docs.css?v={_built_stylesheet_hash(built)}"]


@pytest.mark.parametrize("name", ["guide.html", "operations.html"])
def test_markdown_pages_link_pages_by_clean_url(built: Path, name: str) -> None:
    links = _links(built / name)
    assert "base" not in links.tags
    assert "#main" in links.hrefs
    for page in PAGES:
        assert _clean(page) in links.hrefs, page
        assert page not in links.hrefs, page
    assert links.script_srcs == [UMAMI_SCRIPT, "docs.js"]
    assert _local_stylesheets(links) == [f"docs.css?v={_built_stylesheet_hash(built)}"]


def _clean_url(name: str) -> str:
    """The address nginx serves: `guide.html` is `/guide`, the API reference the site root."""
    return CANONICAL_BASE + ("" if name == "index.html" else name.removesuffix(".html"))


def test_sitemap_lists_exactly_the_published_pages(built: Path) -> None:
    root = ElementTree.fromstring((built / SITEMAP).read_text(encoding="utf-8"))
    ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    locs = [el.text for el in root.findall("s:url/s:loc", ns)]
    expected = [_clean_url(name) for name in PAGES]
    assert sorted(str(loc) for loc in locs) == sorted(expected)
    assert len(locs) == len(set(locs))
    for name in PAGES:
        text = (built / name).read_text(encoding="utf-8")
        canonical = _clean_url(name)
        assert f'<link rel="canonical" href="{canonical}">' in text
        assert ".html" not in canonical
    assert not any(str(loc).endswith(NOT_FOUND) for loc in locs)


def test_robots_allows_all_and_names_the_sitemap(built: Path) -> None:
    lines = (built / ROBOTS).read_text(encoding="utf-8").splitlines()
    assert "User-agent: *" in lines
    assert "Disallow:" in lines
    assert [ln for ln in lines if ln.startswith("Sitemap:")] == [
        f"Sitemap: {CANONICAL_BASE}{SITEMAP}"
    ]


def test_llms_txt_lists_every_published_page_and_the_spec(built: Path) -> None:
    text = (built / LLMS).read_text(encoding="utf-8")
    lines = text.splitlines()
    assert text.startswith("# Sandfort")
    assert lines[0] == "# Sandfort documentation"
    assert any(ln.startswith("> ") for ln in lines)
    assert "## Pages" in lines
    assert "## Reference" in lines
    for name in PAGES:
        assert f"]({_clean_url(name)}):" in text, name
    assert f"({CANONICAL_BASE}openapi.json)" in text
    assert "(https://sandfort.dev/llms.txt)" in text
    assert "(https://github.com/malinele/sandfort)" in text
    assert NOT_FOUND not in text


def test_llms_txt_prose_has_no_semicolons_or_dashes(built: Path) -> None:
    text = (built / LLMS).read_text(encoding="utf-8")
    assert ";" not in text
    assert "—" not in text and "–" not in text
    assert "open source" not in text.lower()


class _HtmlTag(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.html_attrs: dict[str, str | None] = {}
        self.theme_colors: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "html":
            self.html_attrs = values
        elif tag == "meta" and values.get("name") == "theme-color":
            self.theme_colors.append(values)


def _inspect(path: Path) -> _HtmlTag:
    parser = _HtmlTag()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser


def test_api_page_is_always_dark_and_guide_is_not(built: Path) -> None:
    api_classes = (_inspect(built / "index.html").html_attrs.get("class") or "").split()
    guide_classes = (_inspect(built / "guide.html").html_attrs.get("class") or "").split()
    assert "always-dark" in api_classes
    assert "always-dark" not in guide_classes


@pytest.mark.parametrize("name", (*MARKDOWN_PAGES, NOT_FOUND))
def test_pages_declare_dark_and_light_theme_color(built: Path, name: str) -> None:
    metas = _inspect(built / name).theme_colors
    assert len(metas) == 2
    by_media = {m.get("media"): m.get("content") for m in metas}
    assert by_media == {
        "(prefers-color-scheme: dark)": "#0b0d11",
        "(prefers-color-scheme: light)": "#ffffff",
    }


def test_always_dark_api_page_carries_the_dark_theme_color_for_both_schemes(built: Path) -> None:
    metas = _inspect(built / "index.html").theme_colors
    assert len(metas) == 2
    by_media = {m.get("media"): m.get("content") for m in metas}
    assert by_media == {
        "(prefers-color-scheme: dark)": "#0b0d11",
        "(prefers-color-scheme: light)": "#0b0d11",
    }


def _configmap_sizes(built: Path) -> dict[str, int]:
    """Bytes of the files each deployed ConfigMap holds, from the deploy script's lists."""
    parts = {PAGES_CONFIGMAP: _deploy_pages_keys(), SPEC_CONFIGMAP: _deploy_spec_keys()}
    return {
        name: sum((built / path).stat().st_size for path in keys.values())
        for name, keys in parts.items()
    }


@needs_private_ops
def test_each_configmap_stays_under_the_budget(built: Path) -> None:
    for name, size in _configmap_sizes(built).items():
        assert 0 < size < MAX_BUILT_BYTES, f"{name} is {size} bytes, limit {MAX_BUILT_BYTES}"


@needs_private_ops
def test_each_configmap_keeps_a_margin_under_the_limit(built: Path) -> None:
    for name, size in _configmap_sizes(built).items():
        assert size < MARGIN_BUILT_BYTES, (
            f"{name} is {size} bytes, margin {MARGIN_BUILT_BYTES}: "
            "update the size comment in deploy/redeploy-beta.sh"
        )


@needs_private_ops
def test_pages_configmap_has_room_for_more_documentation(built: Path) -> None:
    room = MARGIN_BUILT_BYTES - _configmap_sizes(built)[PAGES_CONFIGMAP]
    assert room >= 150_000, f"only {room} bytes of room left in {PAGES_CONFIGMAP}"


@needs_private_ops
def test_configmaps_share_no_key_and_cover_every_page(built: Path) -> None:
    pages, spec = _deploy_pages_keys(), _deploy_spec_keys()
    assert not set(pages) & set(spec)  # a projected volume rejects a key from two sources
    # The spec and the largest page (the guide) live in the second ConfigMap (round 63).
    assert set(spec) == {"openapi.json", "guide.html"}
    assert set(PAGES) <= {*pages, *spec}
    assert {*pages, *spec} == {p.name for p in built.iterdir() if p.is_file()} - {SPEC_SIDECAR}


def test_stylesheet_is_one_shared_file_not_inlined(built: Path) -> None:
    css = (built / STYLESHEET).read_text(encoding="utf-8")
    assert css.strip()
    assert "<" not in css
    for name in (*PAGES, NOT_FOUND):
        text = (built / name).read_text(encoding="utf-8")
        assert "<style" not in text, name
        assert len(_local_stylesheets(_links(built / name))) == 1, name
        assert 'rel="icon" href="data:image/svg+xml' in text, name  # favicon stays inline


def test_site_openapi_copy_is_compact_and_equal_to_the_source(built: Path) -> None:
    source_text = SPEC_SOURCE.read_text(encoding="utf-8")
    site_text = (built / "openapi.json").read_text(encoding="utf-8")
    source = json.loads(source_text)
    assert json.loads(site_text) == source
    assert len(site_text.encode("utf-8")) < len(source_text.encode("utf-8"))
    assert "\n" not in site_text
    assert site_text == json.dumps(source, separators=(",", ":"), ensure_ascii=False)
    assert list(json.loads(site_text)["paths"]) == list(source["paths"])
    assert "\n  " in source_text  # the repository specification stays pretty-printed


def test_api_page_loads_redoc_with_spec_and_integrity(built: Path) -> None:
    page = (built / "index.html").read_text(encoding="utf-8")
    assert "openapi.json" in page
    assert "redoc@2.2.0/bundles/redoc.standalone.js" in page
    assert 'integrity="sha384-' in page


@pytest.mark.parametrize("name", MARKDOWN_PAGES)
def test_markdown_pages_have_h1(built: Path, name: str) -> None:
    assert "<h1" in (built / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("name", PAGES)
def test_pages_are_well_formed_and_share_chrome(built: Path, name: str) -> None:
    text = (built / name).read_text(encoding="utf-8")
    parser = _TagBalance()
    parser.feed(text)
    assert parser.errors == []
    assert parser.stack == []
    assert "sandfort.dev</a>" in text  # back link
    assert "Polygon Consulting doo, Beograd, Serbia" in text
    assert "21466352" in text  # APR matični broj (ZPD čl. 25 / ZET čl. 6 footer data)
    assert "111345107" in text  # PIB
    assert 'name="viewport"' in text


@pytest.mark.parametrize("name", PAGES)
def test_pages_have_no_relative_markdown_links(built: Path, name: str) -> None:
    text = (built / name).read_text(encoding="utf-8")
    assert MD_LINK.findall(text) == []


@pytest.mark.parametrize("name", PAGES)
def test_footer_lists_every_doc_page(built: Path, name: str) -> None:
    text = (built / name).read_text(encoding="utf-8")
    footer = text[text.index("<footer>") :]
    for page in PAGES:
        assert f'href="{_clean(page)}"' in footer, page


def test_inline_markup_is_escaped_not_passed_through() -> None:
    html_out = Renderer().render("# T\n\nuse `<b>` and <script>x</script> **bold**\n")
    assert "<script>" not in html_out
    assert "<code>&lt;b&gt;</code>" in html_out
    assert "<strong>bold</strong>" in html_out


def test_nested_lists_tables_and_fences() -> None:
    md = (
        "## Heading\n\n- a\n  - b\n\n"
        "| x | y |\n|---|---|\n| `p|q` | 2 |\n\n"
        "```bash\necho <hi>\n```\n"
    )
    renderer = Renderer()
    out = renderer.render(md)
    assert "<ul>\n<li>a\n<ul>" in out
    assert "<code>p|q</code>" in out
    assert "echo &lt;hi&gt;" in out
    assert 'id="heading"' in out
    assert "#heading" in toc_html(renderer.headings)


def test_slugify_matches_github_style() -> None:
    slug = slugify("Recovering a lost API key (`create-key`)")
    assert slug == "recovering-a-lost-api-key-create-key"
    assert slugify("1. What you receive") == "1-what-you-receive"


@pytest.mark.parametrize("name", [*PAGES, NOT_FOUND])
def test_no_link_ends_in_html(built: Path, name: str) -> None:
    """Nav, footer, skip link, the 404 list and content links use clean URLs only."""
    hrefs = _links(built / name).hrefs
    assert [h for h in hrefs if re.search(r"\.html(?:[#?]|$)", h)] == []


def test_not_found_skip_link_is_the_fragment_not_a_page_address(built: Path) -> None:
    links = _links(built / NOT_FOUND)
    assert "#main" in links.hrefs
    assert "/404.html#main" not in links.hrefs
    assert "/404#main" not in links.hrefs


def _tagged_repo(tmp_path: Path) -> tuple[Path, str]:
    env = {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
    }
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args: str) -> str:
        done = subprocess.run(
            ["git", *args], cwd=repo, env=env, capture_output=True, text=True, check=True
        )
        return done.stdout.strip()

    git("init", "-q")
    (repo / "f").write_text("x")
    git("add", "f")
    git("commit", "-q", "-m", "one")
    git("tag", "v9.9.9-beta.1")
    (repo / "f").write_text("y")
    git("commit", "-q", "-am", "two")
    git("tag", "v9.9.9-beta.2")
    tagged = git("rev-parse", "HEAD")
    (repo / "f").write_text("z")
    git("commit", "-q", "-am", "three")
    return repo, tagged


def test_release_source_uses_a_placeholder_not_a_hardcoded_tag() -> None:
    text = (ROOT / "docs" / "release.md").read_text(encoding="utf-8")
    assert "{{CURRENT_RELEASE}}" in text
    assert "current tag `v0.1.0-beta." not in text


def test_release_page_shows_the_current_tag_and_commit_from_git(built: Path) -> None:
    tag = subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    commit = subprocess.run(
        ["git", "rev-list", "-n1", tag], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    page = (built / "release.html").read_text(encoding="utf-8")
    assert f"<code>{tag}</code> (commit <code>{commit}</code>)" in page
    assert "{{CURRENT_RELEASE}}" not in page


def test_current_release_text_reads_tag_and_commit_at_build_time(tmp_path: Path) -> None:
    import build_docs_site

    repo, tagged = _tagged_repo(tmp_path)
    text = build_docs_site.current_release_text(repo)
    assert text == f"the current tag `v9.9.9-beta.2` (commit `{tagged}`)"


def test_current_release_text_falls_back_without_git_or_tags(tmp_path: Path) -> None:
    import build_docs_site

    bare = tmp_path / "bare"
    bare.mkdir()
    assert build_docs_site.current_release_text(bare) == build_docs_site.RELEASE_FALLBACK
    assert build_docs_site.current_release_text(tmp_path / "missing") == (
        build_docs_site.RELEASE_FALLBACK
    )


def test_security_page_explains_that_repository_paths_are_not_pages(built: Path) -> None:
    page = (built / "security.html").read_text(encoding="utf-8")
    assert "repository paths, not" in page
    assert "published pages" in page


THIRD_PARTY_FONTS = ("fonts.googleapis.com", "fonts.gstatic.com", "Geist", "JetBrains")


@pytest.mark.parametrize("name", [*PAGES, NOT_FOUND, STYLESHEET, "redoc-init.js"])
def test_docs_site_makes_no_font_requests_and_names_no_web_fonts(built: Path, name: str) -> None:
    text = (built / name).read_text(encoding="utf-8")
    for needle in THIRD_PARTY_FONTS:
        assert needle not in text, (name, needle)


def test_docs_stylesheet_uses_system_font_stacks_with_a_monospace_stack(built: Path) -> None:
    css = (built / STYLESHEET).read_text(encoding="utf-8")
    assert re.search(r"--sans:ui-sans-serif,system-ui", css)
    assert re.search(r"--mono:ui-monospace,[^;]*monospace;", css)


def test_docs_csp_has_no_font_hosts() -> None:
    conf = (ROOT / "deploy" / "static-nginx" / "docs.conf").read_text(encoding="utf-8")
    code = "\n".join(ln for ln in conf.splitlines() if not ln.strip().startswith("#"))
    assert "googleapis" not in code and "gstatic" not in code
    assert "cdn.jsdelivr.net" in code and "cdn.redoc.ly" in code


def test_every_docs_page_carries_the_umami_tracker_for_the_docs_host(built: Path) -> None:
    pages = sorted(built.glob("*.html"))
    assert pages
    for page in pages:
        text = page.read_text(encoding="utf-8")
        assert text.count(f'<script defer src="{UMAMI_SCRIPT}"') == 1, page.name
        assert 'data-domains="docs.sandfort.dev"' in text, page.name
        assert "data-website-id=" in text, page.name


def test_docs_beta_request_links_carry_umami_events(built: Path) -> None:
    text = (built / "guide.html").read_text(encoding="utf-8")
    assert text.count('data-umami-event="beta_request"') == 2
    assert 'data-umami-event-placement="nav"' in text
    assert 'data-umami-event-placement="footer"' in text
