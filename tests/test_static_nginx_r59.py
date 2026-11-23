"""Round 59: nginx server blocks of the docs and landing sites, and the nginx deploy target."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NGINX_DIR = ROOT / "deploy" / "static-nginx"
DEPLOY_SCRIPT = ROOT / "deploy" / "redeploy-beta.sh"

needs_private_ops = pytest.mark.skipif(
    not DEPLOY_SCRIPT.is_file(),
    reason="private ops script not present in public tree",
)
MAX_LINE = 100

DOCS = NGINX_DIR / "docs.conf"
LANDING = NGINX_DIR / "landing.conf"

SECURITY_HEADERS = (
    'add_header X-Content-Type-Options "nosniff" always;',
    'add_header X-Frame-Options "DENY" always;',
    'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    "add_header Content-Security-Policy $csp always;",
    "server_tokens off;",
)

DOCS_POLICY = (
    "script-src 'self' https://cdn.jsdelivr.net https://umami.sandfort.dev;",
    "worker-src blob:;",
    "style-src 'self' 'unsafe-inline';",
    "font-src data:;",
    "img-src 'self' data: https://cdn.redoc.ly;",
    "connect-src 'self' https://umami.sandfort.dev;",
    "base-uri 'none';",
    "form-action 'none';",
    "frame-ancestors 'none'",
)

LANDING_POLICY = (
    "script-src 'self' https://umami.sandfort.dev;",
    "style-src 'self' 'unsafe-inline';",
    "font-src 'self';",
    "img-src 'self' data:;",
    "connect-src 'self' https://umami.sandfort.dev;",
    "base-uri 'none';",
    "form-action 'none';",
    "frame-ancestors 'none'",
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _code(path: Path) -> str:
    """The file without comment lines."""
    return "\n".join(
        line for line in _text(path).splitlines() if not line.strip().startswith("#")
    )


def _deploy_nginx_body() -> str:
    text = _text(DEPLOY_SCRIPT)
    block = text[text.index("deploy_nginx() {") :]
    return block[: block.index("\n}\n")]


@pytest.mark.parametrize("path", [DOCS, LANDING], ids=["docs", "landing"])
class TestBothServerBlocks:
    def test_file_exists_and_lines_are_short(self, path: Path) -> None:
        assert path.is_file()
        for number, line in enumerate(_text(path).splitlines(), start=1):
            assert len(line) <= MAX_LINE, f"{path.name}:{number} is {len(line)} chars"

    def test_is_exactly_one_balanced_server_block(self, path: Path) -> None:
        code = _code(path)
        assert len(re.findall(r"^\s*server\s*\{", code, flags=re.MULTILINE)) == 1
        assert code.count("{") == code.count("}")
        depth = 0
        for char in code:
            depth += (char == "{") - (char == "}")
            assert depth >= 0, "closing brace before its opening brace"
        assert depth == 0
        assert code.rstrip().endswith("}")

    def test_listens_on_port_80_with_html_root_and_index(self, path: Path) -> None:
        code = _code(path)
        assert re.search(r"^\s*listen\s+80;", code, flags=re.MULTILINE)
        assert "root /usr/share/nginx/html;" in code
        assert "index index.html;" in code

    def test_security_headers(self, path: Path) -> None:
        code = _code(path)
        for header in SECURITY_HEADERS:
            assert header in code, f"{path.name} lacks {header}"

    def test_html_is_never_cached(self, path: Path) -> None:
        no_cache = re.search(r"location\s+~\*\s+\\\.html\$\s*\{([^}]*)\}", _code(path))
        assert no_cache is not None
        assert "expires epoch;" in no_cache.group(1)
        assert "add_header" not in no_cache.group(1)

    def test_cache_rules_do_not_reset_inherited_headers(self, path: Path) -> None:
        # add_header inside a location drops every add_header inherited from the server block,
        # so a location that adds one must repeat all of the security headers.
        code = _code(path)
        for location in re.findall(r"location[^{]*\{([^}]*)\}", code):
            if "add_header" not in location:
                continue
            for header in SECURITY_HEADERS:
                if header.startswith("add_header"):
                    assert header in location, f"{path.name}: location lacks {header}"


class TestDocsServer:
    def test_csp_directives(self) -> None:
        code = _code(DOCS)
        for fragment in DOCS_POLICY:
            assert fragment in code, f"docs.conf lacks {fragment}"

    def test_clean_urls_try_path_then_html_suffix_then_not_found(self) -> None:
        code = _code(DOCS)
        # $uri/ keeps the index directive working for the site root (a bare try_files $uri
        # on a directory is a miss, so the root answered 404 after the first deploy).
        assert re.search(r"try_files\s+\$uri\s+\$uri/\s+\$uri\.html\s+=404;", code)
        assert re.search(r"location\s+/\s*\{[^}]*try_files", code)

    def test_error_page_is_the_not_found_page_the_build_writes(self) -> None:
        assert "error_page 404 /404.html;" in _code(DOCS)

    def test_direct_requests_for_the_not_found_page_answer_404(self) -> None:
        code = _code(DOCS)
        # Internal locations refuse outside requests with 404; error_page still reaches them.
        assert re.search(r"location\s+=\s+/404\s*\{[^}]*\binternal;", code)
        page = re.search(r"location\s+=\s+/404\.html\s*\{([^}]*)\}", code)
        assert page is not None
        assert re.search(r"\binternal;", page.group(1))
        assert "error_page 404 /404.html;" in code

    def _asset_location(self) -> tuple[set[str], str]:
        match = re.search(r"location\s+~\*\s+\\\.\(([^)]*)\)\$\s*\{([^}]*)\}", _code(DOCS))
        assert match is not None
        return set(match.group(1).split("|")), match.group(2)

    def test_stylesheet_scripts_and_spec_share_the_short_revalidating_policy(self) -> None:
        extensions, body = self._asset_location()
        assert extensions == {"json", "js", "css"}
        assert 'add_header Cache-Control "max-age=300, must-revalidate";' in body

    def test_assets_have_no_day_long_expiry(self) -> None:
        _, body = self._asset_location()
        assert "expires 1d" not in body
        assert "86400" not in body
        assert "expires " not in body  # a second Cache-Control header would conflict

    def test_asset_location_repeats_the_security_headers_it_would_otherwise_drop(self) -> None:
        _, body = self._asset_location()
        for header in SECURITY_HEADERS:
            if header.startswith("add_header"):
                assert header in body, header

    def test_header_comment_names_the_external_deployments_and_configmap(self) -> None:
        header = "\n".join(
            line for line in _text(DOCS).splitlines() if line.startswith("#")
        )
        for name in ("sandfort-static-nginx", "docs.conf", "landing.conf"):
            assert name in header, name
        for name in ("sandfort-docs", "sandfort-landing"):
            assert name in header, name
        assert "outside the repo" in header


class TestLandingServer:
    def test_csp_directives(self) -> None:
        code = _code(LANDING)
        for fragment in LANDING_POLICY:
            assert fragment in code, f"landing.conf lacks {fragment}"

    def test_long_cache_for_json_and_js_and_no_add_header_in_locations(self) -> None:
        code = _code(LANDING)
        long_cache = re.search(
            r"location\s+~\*\s+\\\.\(json\|js(?:\|css)?\)\$\s*\{([^}]*)\}", code
        )
        assert long_cache is not None
        assert "expires 1d;" in long_cache.group(1)
        # Round 65: the internal not-found location sets Cache-Control and so repeats the
        # security headers, as docs.conf does; every other location sets none.
        for header, body in re.findall(r"(location[^{]*)\{([^}]*)\}", code):
            if "404.html" in header:
                assert 'add_header Cache-Control "no-store" always;' in body
                for security_header in SECURITY_HEADERS[:3]:
                    assert security_header in body
            else:
                assert "add_header" not in body

    def test_crawler_files_have_explicit_types_and_a_short_cache(self) -> None:
        code = _code(LANDING)
        text_block = re.search(
            r"location\s+~\s+\^/\(robots\|llms\)\\\.txt\$\s*\{(.*?)\n    \}", code, re.S
        )
        xml_block = re.search(
            r"location\s+=\s+/sitemap\.xml\s*\{(.*?)\n    \}", code, re.S
        )
        assert text_block is not None and xml_block is not None
        assert "default_type text/plain;" in text_block.group(1)
        assert "default_type application/xml;" in xml_block.group(1)
        for body in (text_block.group(1), xml_block.group(1)):
            assert "charset utf-8;" in body
            assert "expires 1h;" in body
            assert "add_header" not in body

    def test_landing_policy_has_no_docs_cdns(self) -> None:
        code = _code(LANDING)
        assert "jsdelivr" not in code
        assert "redoc" not in code


@needs_private_ops
class TestDeployScript:
    def test_header_documents_the_nginx_target(self) -> None:
        header = _text(DEPLOY_SCRIPT).split("set -euo pipefail", 1)[0]
        assert "redeploy-beta.sh nginx" in header
        assert "sandfort-static-nginx" in header

    def test_all_includes_nginx_before_landing_and_docs(self) -> None:
        text = _text(DEPLOY_SCRIPT)
        assert "all) TARGETS+=(nginx landing docs api) ;;" in text
        assert re.search(r"api\|egress\|landing\|docs\|nginx\|rollback\)", text)

    def test_nginx_target_is_dispatched(self) -> None:
        assert re.search(r"nginx\) deploy_nginx ;;", _text(DEPLOY_SCRIPT))

    def test_deploy_nginx_replaces_configmap_from_both_files(self) -> None:
        block = _deploy_nginx_body()
        assert "replace_configmap sandfort-static-nginx" in block
        assert "docs.conf=$ROOT/deploy/static-nginx/docs.conf" in block
        assert "landing.conf=$ROOT/deploy/static-nginx/landing.conf" in block

    @pytest.mark.parametrize("name", ["sandfort-docs", "sandfort-landing"])
    def test_deploy_nginx_restarts_both_static_deployments(self, name: str) -> None:
        block = _deploy_nginx_body()
        assert f"rollout restart deploy/{name}" in block
        assert f"rollout status deploy/{name}" in block

    def test_deploy_landing_ships_and_checks_the_crawler_files(self) -> None:
        text = _text(DEPLOY_SCRIPT)
        block = text[text.index("deploy_landing() {") :]
        block = block[: block.index("\n}\n")]
        for name in ("robots.txt", "sitemap.xml", "llms.txt"):
            assert f'"{name}=$ROOT/site/{name}"' in block
            assert f'wait_live "https://sandfort.dev/{name}" "$ROOT/site/{name}"' in block
            assert (ROOT / "site" / name).is_file()

    def test_help_range_covers_the_whole_header_comment(self) -> None:
        text = _text(DEPLOY_SCRIPT)
        lines = text.splitlines()
        match = re.search(r"sed -n '2,(\d+)p'", text)
        assert match is not None
        last = int(match.group(1))
        # The range ends on the comment line after the last requirement, as it did before.
        assert "a clean HEAD that equals origin/main" in lines[last - 2]
        assert lines[last - 1] == "#"


def test_docs_api_alias_serves_the_index_page() -> None:
    """The API reference is the index page; /api and /api/ are the addresses people guess."""
    code = DOCS.read_text(encoding="utf-8")
    assert re.search(r"location\s+=\s+/api\s*\{[^}]*/index\.html", code)
    # The slash form redirects: the index page's relative assets would otherwise 404 under /api/.
    assert re.search(r"location\s+=\s+/api/\s*\{[^}]*return 301 /;", code)


def test_docs_redirects_are_relative_and_trailing_slashes_redirect() -> None:
    """Round 61: /api/ answered 301 to http:// (TLS ends at the ingress) and /guide/ was 404."""
    code = DOCS.read_text(encoding="utf-8")
    assert re.search(r"^\s*absolute_redirect\s+off;", code, re.M)
    match = re.search(r"location\s+~\s+(\S+)\s*\{\s*return 301 \$1;\s*\}", code)
    assert match is not None
    pattern = re.compile(match.group(1))
    assert pattern.fullmatch("/guide/") and pattern.fullmatch("/guide/").group(1) == "/guide"
    # /api/ also matches the pattern; its exact location (= /api/) wins in nginx.
    for kept in ("/", "/guide", "/openapi.json/", "/a/b/"):
        assert pattern.fullmatch(kept) is None, kept
