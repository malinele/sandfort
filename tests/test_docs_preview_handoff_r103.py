"""Round 103 docs: the handoff design records the decisions, and the docs name what the code does.

Every name the docs must carry is taken from the code (the header, the reserved path, the
cookie, the Vary names and the dropped directives), so a rename in code fails here first.
"""

from pathlib import Path

from sandfort.proxy.caching import VARY_ON
from sandfort.proxy.handoff import MAX_FORM_BYTES, POLICY
from sandfort.proxy.tokens import COOKIE_NAME, HANDOFF_PATH, TOKEN_HEADER, TOKEN_PARAM

ROOT = Path(__file__).resolve().parents[1]
HEADER = "Sandfort-Preview-Token"
DROPPED = ("public", "s-maxage", "proxy-revalidate")


def flat(name: str) -> str:
    return " ".join((ROOT / "docs" / name).read_text(encoding="utf-8").split())


def between(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    return text[begin : text.index(end, begin)]


def assert_cache_rule(text: str) -> None:
    assert "`private`" in text or "`Cache-Control: private`" in text
    for name in (*VARY_ON, *DROPPED, "CDN-Cache-Control", "Surrogate-Control", "no-store"):
        assert f"`{name}`" in text or f"`Cache-Control: {name}`" in text, name


def test_the_header_name_in_the_docs_is_the_one_the_proxy_reads() -> None:
    assert HEADER.lower() == TOKEN_HEADER
    assert [name.lower() for name in VARY_ON] == ["cookie", TOKEN_HEADER]
    assert "frame-ancestors 'none'" in POLICY


def test_the_design_note_is_marked_implemented() -> None:
    text = flat("preview-token-handoff-design.md")

    assert text.startswith("# Preview token handoff: design and decisions Status: implemented")
    assert "Status: implemented in round 103" in text
    assert "Nothing here is implemented" not in text
    assert "## 10. Open questions for the owner" not in text


def test_the_design_note_records_the_decisions_made_in_code() -> None:
    section = flat("preview-token-handoff-design.md").split("## 10. Decisions as made in code")[1]

    for needle in (
        f"`{HEADER}`",
        "from the header, then the query, then the cookie",
        "checks only the first one present",
        "A header token is never set as a cookie",
        f"`{HANDOFF_PATH}`",
        f"above {MAX_FORM_BYTES} bytes answers 413",
        "`browser_url` is a new field next to an unchanged `url`",
        "present only when `SANDFORT_PUBLIC_PREVIEW_URL` is an https origin",
        "Query tokens are not refused",
        "always opens `/`",
        "`sandfort preview --browser`",
        "`src/sandfort/proxy/caching.py`",
        "Still open:",
    ):
        assert needle in section, needle
    assert_cache_rule(section)


def test_architecture_lists_the_optional_browser_url() -> None:
    rows = [
        line
        for line in (ROOT / "docs" / "architecture.md").read_text(encoding="utf-8").splitlines()
        if "`/v1/sandboxes/{id}/preview-tokens`" in line
    ]

    assert len(rows) == 1
    assert "`{token, url, browser_url?, port, expires_at}`" in rows[0]
    assert f"`{HANDOFF_PATH}`" in rows[0]
    assert "https origin" in rows[0]


def test_operations_names_the_carriers_the_handoff_and_the_cache_rule() -> None:
    section = between(flat("operations.md"), "## Behind a TLS-terminating proxy", "## Edge")

    for needle in (f"`{HEADER}`", f"`{TOKEN_PARAM}`", f"`{COOKIE_NAME}`", f"`{HANDOFF_PATH}`"):
        assert needle in section, needle
    assert "checks only the first one present" in section
    assert "`browser_url`" in section
    assert_cache_rule(section)


def test_operations_says_the_keep_alive_pool_follows_the_per_sandbox_cap() -> None:
    text = flat("operations.md")

    assert "The proxy keeps up to 768 idle upstream connections" not in text
    assert "keeps as many idle upstream connections as the per-sandbox cap" in text
    assert "when that cap is `0`" in text


def test_security_names_the_handoff_page_policy_and_the_cache_rule() -> None:
    section = between(flat("security.md"), "### Preview content", "## 4. Control plane")

    assert "Only the web terminal page carries a policy" not in section
    assert "`src/sandfort/proxy/handoff.py`" in section
    assert f"`{HANDOFF_PATH}`" in section
    assert f"`{HEADER}`" in section
    assert "checks only the first one present" in section
    assert "`src/sandfort/proxy/caching.py`" in section
    assert_cache_rule(section)
