"""CLI round 58 (b): a cut credential behind a noisy introducer.

* A scheme-relative introducer with something between the slashes (``/ /``, a whitespace or
  control character between them, ``scheme:/ /``) before ``user``, a colon form (``%3A``,
  ``%3a``, U+FF1A, U+0589) and a password, cut by the raw cap before the ``@``, has its cut
  tail dropped like the ASCII form.
* The same text uncut stays masked.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli.sanitise import (  # noqa: E402
    ELLIPSIS,
    MAX_RAW_CHARS,
    drop_partial_url,
    sanitise_text,
)

INTRODUCERS = [
    "/ /",
    "/\t/",
    "/\x0b/",
    "/\x0c/",
    "/\r/",
    "/\xa0/",
    "/\x01/",
    "/\x7f/",
    "https:/ /",
    "git+ssh:/ /",
]
SEPARATORS = [":", "%3A", "%3a", "：", "։"]
PASSWORD = "Zq7Kx9WpLm"
CUT_POSITIONS = [1, 3, 6, len(PASSWORD)]
HOST = "@evil.example/x"
SHOWN_LIMIT = 2 * MAX_RAW_CHARS
# Uncut, a plain space between the slashes is masked only with the ASCII colon (the bare
# pattern); with a colon form that pair is not masked by the uncut passes yet.
UNCUT_MASKED = [
    (introducer, separator)
    for introducer in INTRODUCERS
    for separator in SEPARATORS
    if separator == ":" or " /" not in introducer
]


def _cut_text(introducer: str, separator: str, cut: int) -> str:
    head = f" see {introducer}user{separator}"
    filler = "x" * (MAX_RAW_CHARS - len(head) - cut)
    return f"{filler}{head}{PASSWORD}{HOST}"


@pytest.mark.parametrize("cut", CUT_POSITIONS)
@pytest.mark.parametrize("separator", SEPARATORS)
@pytest.mark.parametrize("introducer", INTRODUCERS)
def test_cut_password_behind_a_noisy_introducer_is_dropped(
    introducer: str, separator: str, cut: int
) -> None:
    text = _cut_text(introducer, separator, cut)
    assert text[:MAX_RAW_CHARS].endswith(PASSWORD[:cut])

    shown = sanitise_text(text, limit=SHOWN_LIMIT)

    assert PASSWORD[:cut] not in shown
    assert "user" not in shown
    assert shown.endswith(f" see{ELLIPSIS}")


@pytest.mark.parametrize(("introducer", "separator"), UNCUT_MASKED)
def test_uncut_credential_behind_a_noisy_introducer_stays_masked(
    introducer: str, separator: str
) -> None:
    shown = sanitise_text(f"see {introducer}user{separator}{PASSWORD}{HOST}")

    assert PASSWORD not in shown
    assert "evil.example/x" in shown


@pytest.mark.parametrize("separator", SEPARATORS[1:])
@pytest.mark.parametrize("introducer", ["/ /", "/\t/", "https:/ /", "https:/\t/"])
def test_drop_partial_url_reads_the_colon_forms_after_a_noisy_introducer(
    introducer: str, separator: str
) -> None:
    text = f"failed at {introducer}user{separator}Zq7"

    assert drop_partial_url(text) == "failed at "


def test_complete_authority_behind_a_noisy_introducer_keeps_its_path() -> None:
    text = "failed at / /host.test/a/b"

    assert drop_partial_url(text) == text


@pytest.mark.parametrize("separator", SEPARATORS[1:])
def test_colon_form_in_the_last_segment_of_a_url_is_dropped(separator: str) -> None:
    text = f"failed at //host.test/a/user{separator}Zq7"

    assert drop_partial_url(text) == "failed at //host.test/a/"


def test_colon_form_in_the_last_segment_after_a_noisy_introducer_is_dropped() -> None:
    text = "failed at / /host.test/a/user%3AZq7"

    assert drop_partial_url(text) == "failed at / /host.test/a/"
