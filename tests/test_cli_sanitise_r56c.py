"""CLI round 56, review fixes for the bare-credential masks.

* The across-breaks bare pattern bounds the password, and ``mask_raw_userinfo`` cuts its input
  to the raw cap itself, so hostile text (``:a<TAB>`` repeated) is not quadratic.
* The empty-user form (``:secret@host:8443``) needs a host that reads as one (a port, a bracketed
  or dotted host, or a name), so ``ratio :3@2/3`` stays; a leading ``key=`` is kept.
* Every non-space Unicode White_Space character inside a bare password keeps it whole.
"""

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli.sanitise import (  # noqa: E402
    BARE_ACROSS_BREAKS_RE,
    MAX_RAW_CHARS,
    mask_raw_userinfo,
    mask_userinfo,
    sanitise_text,
)

TIME_BUDGET_S = 0.5
HOSTILE = ":a\t" * 2000
# The non-space White_Space characters the round-56 alphabet did not cover.
MISSING_BREAK_CHARS = [
    *(chr(code) for code in range(0x1C, 0x20)),
    *(chr(code) for code in range(0x2001, 0x2009)),
    " ",
]


def show(text: str) -> str:
    return sanitise_text(text, limit=10_000)


def test_mask_raw_userinfo_is_fast_on_repeated_colon_tab() -> None:
    started = time.perf_counter()
    mask_raw_userinfo(HOSTILE)

    assert time.perf_counter() - started < TIME_BUDGET_S


def test_across_breaks_pattern_alone_is_fast_on_repeated_colon_tab() -> None:
    started = time.perf_counter()
    BARE_ACROSS_BREAKS_RE.sub("", HOSTILE)

    assert time.perf_counter() - started < TIME_BUDGET_S


def test_mask_raw_userinfo_cuts_its_input_to_the_raw_cap() -> None:
    assert len(mask_raw_userinfo("x" * (MAX_RAW_CHARS * 3))) == MAX_RAW_CHARS


def test_mask_raw_userinfo_drops_a_credential_cut_by_the_raw_cap() -> None:
    text = "x " * ((MAX_RAW_CHARS - 10) // 2) + "user:hunter2hunter2@host:8443"

    shown = mask_raw_userinfo(text)

    assert "hunter" not in shown


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (":secret@host:8443", "host:8443"),
        ("x=:secret@host:8443", "x=host:8443"),
        ("x=user:secret@host:8443", "x=host:8443"),
        (":secret@[::1]/x", "[::1]/x"),
        (":secret@10.0.0.1/x", "10.0.0.1/x"),
    ],
)
def test_empty_user_credential_with_a_real_host_is_masked(text: str, expected: str) -> None:
    assert show(text) == expected
    assert mask_userinfo(text) == expected
    assert mask_raw_userinfo(text) == expected


@pytest.mark.parametrize("text", [":3@2/3", "ratio :3@2/3", "ratio :3@2/3 and :1@4/5"])
def test_empty_user_before_a_numeric_host_stays(text: str) -> None:
    assert show(text) == text
    assert mask_userinfo(text) == text
    assert mask_raw_userinfo(text) == text


def test_empty_user_label_before_a_dotted_host_with_a_path_is_dropped() -> None:
    # Deliberate trade-off (module docstring of sanitise.py): this reads as a credential, so the
    # label ``:name@`` is lost although it was prose.
    text = "see :name@host.com/page"

    assert show(text) == "see host.com/page"


@pytest.mark.parametrize(
    "space", MISSING_BREAK_CHARS, ids=[f"U+{ord(char):04X}" for char in MISSING_BREAK_CHARS]
)
@pytest.mark.parametrize("user", ["user", ""])
def test_password_split_by_any_white_space_is_masked(user: str, space: str) -> None:
    text = f"{user}:hunter{space}two@host:8443"

    assert show(text) == "host:8443"
    assert mask_raw_userinfo(text) == "host:8443"
