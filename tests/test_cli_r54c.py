"""CLI round 54, batch c: label-key collisions, grapheme-safe table cells, labels in the field view.

1. When two label keys collide after sanitising, the key that was already clean keeps the plain
   name in ``--json`` and the key that sanitising changed gets the ``#<n>`` suffix, whatever the
   order of the server's map; a genuine key shaped like ``env#2`` keeps its exact name.
2. A table cell is cut at an extended grapheme cluster boundary: no dangling joiner, lone mark or
   virama, split keycap, lone regional indicator or broken tag sequence before the ellipsis, and
   the cell is still at most ``TABLE_CELL_MAX`` characters.
3. ``sandbox get`` in text mode has a ``labels`` row: every label, sanitised, never width-cut.
"""

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config, output  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import (  # noqa: E402
    ELLIPSIS,
    TABLE_CELL_MAX,
    AppState,
    clean_key_names,
    cut_at_cluster,
    grapheme_clusters,
    truncate_cell,
)
from sandfort_sdk import SandboxInfo  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
PROFILE_KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOX_URL = f"/v1/sandboxes/{SID}"
RUNNER = CliRunner()
# A key with a leading control character, and one with a zero width space: both clean to "env".
CONTROL_ENV = "\x01env"
HIDDEN_ENV = "​env"
BOX_DRAWING_RE = re.compile("[─-╿]")

ZWJ = "‍"
WOMAN_TECHNOLOGIST = "\U0001f469‍\U0001f4bb"
E_TWO_MARKS = "é̂"
KSSA = "क्ष"  # Devanagari ka, virama, ssa: one conjunct
KEYCAP_ONE = "1️⃣"
FLAG_RS = "\U0001f1f7\U0001f1f8"
FLAG_DE = "\U0001f1e9\U0001f1ea"
FLAG_SCOTLAND = "\U0001f3f4\U000e0067\U000e0062\U000e0073\U000e0063\U000e0074\U000e007f"
THUMBS_UP_MEDIUM = "\U0001f44d\U0001f3fd"
HANGUL_GA_JAMO = "각"


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def sandbox_json(labels: dict[str, str]) -> dict[str, Any]:
    return {
        "id": SID,
        "name": "demo",
        "state": "started",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
        "labels": labels,
    }


def invoke(args: list[str], *, as_json: bool) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, PROFILE_KEY)


@pytest.fixture
def router() -> Any:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


def json_labels(router: Any, labels: dict[str, str]) -> dict[str, str]:
    router.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json(labels)))
    result = invoke(["sandbox", "get", SID], as_json=True)
    assert result.exit_code == 0, result.output
    shown: dict[str, str] = json.loads(result.stdout)["labels"]
    return shown


# 1. label-key collisions in json


@pytest.mark.parametrize(
    "labels",
    [
        {"env": "prod", CONTROL_ENV: "evil"},
        {CONTROL_ENV: "evil", "env": "prod"},
    ],
    ids=["clean-first", "changed-first"],
)
def test_the_clean_key_keeps_the_plain_name_in_either_order(
    router: Any, labels: dict[str, str]
) -> None:
    shown = json_labels(router, labels)

    assert shown == {"env": "prod", "env#2": "evil"}


def test_several_changed_keys_are_numbered_in_order_after_the_clean_one(router: Any) -> None:
    shown = json_labels(router, {CONTROL_ENV: "first", HIDDEN_ENV: "second", "env": "prod"})

    assert shown == {"env": "prod", "env#2": "first", "env#3": "second"}


def test_a_genuine_suffixed_looking_key_keeps_its_exact_name(router: Any) -> None:
    shown = json_labels(router, {CONTROL_ENV: "evil", "env#2": "real two", "env": "prod"})

    assert shown == {"env": "prod", "env#2": "real two", "env#3": "evil"}


def test_changed_keys_alone_number_in_the_maps_order(router: Any) -> None:
    shown = json_labels(router, {HIDDEN_ENV: "first", CONTROL_ENV: "second"})

    assert shown == {"env": "first", "env#2": "second"}


def test_a_changed_key_without_a_collision_takes_its_cleaned_name(router: Any) -> None:
    shown = json_labels(router, {CONTROL_ENV: "only", "team": "ml"})

    assert shown == {"env": "only", "team": "ml"}


def test_clean_key_names_keeps_the_maps_order() -> None:
    names = clean_key_names([CONTROL_ENV, "env#2", "env", HIDDEN_ENV], "")

    assert names == ["env#3", "env#2", "env", "env#4"]


# 2. table cells cut at grapheme cluster boundaries


@pytest.mark.parametrize(
    ("text", "kept"),
    [
        ("a" * 29 + WOMAN_TECHNOLOGIST + "zz", "a" * 29),
        ("a" * 29 + E_TWO_MARKS + "zz", "a" * 29),
        ("a" * 29 + KSSA + "zz", "a" * 29),
        ("a" * 29 + KEYCAP_ONE + "zz", "a" * 29),
        ("a" * 30 + FLAG_RS + FLAG_DE, "a" * 30),
        ("a" * 26 + FLAG_SCOTLAND + "zz", "a" * 26),
        ("a" * 30 + THUMBS_UP_MEDIUM + "zz", "a" * 30),
        ("a" * 29 + HANGUL_GA_JAMO + "zz", "a" * 29),
    ],
    ids=["zwj", "marks", "virama", "keycap", "regional", "tag", "modifier", "jamo"],
)
def test_a_cut_cell_ends_on_a_cluster_boundary(text: str, kept: str) -> None:
    cell = truncate_cell(text)

    assert cell == kept + ELLIPSIS
    assert len(cell) <= TABLE_CELL_MAX
    assert text.startswith(cell[: -len(ELLIPSIS)])


def test_regional_indicators_pair_from_the_start_of_the_run() -> None:
    text = "a" * 27 + FLAG_RS + FLAG_DE + "zz"

    cell = truncate_cell(text)

    assert cell == "a" * 27 + FLAG_RS + FLAG_DE + ELLIPSIS
    assert len(cell) == TABLE_CELL_MAX


def test_a_whole_cluster_that_fits_is_kept() -> None:
    text = "a" * 28 + WOMAN_TECHNOLOGIST + "zz"

    assert truncate_cell(text) == "a" * 28 + WOMAN_TECHNOLOGIST + ELLIPSIS


def test_a_value_that_fits_is_not_cut() -> None:
    text = "a" * 25 + FLAG_SCOTLAND

    assert truncate_cell(text) == text


def test_a_single_cluster_longer_than_the_cell_leaves_only_the_ellipsis() -> None:
    text = "e" + "́" * 40

    assert cut_at_cluster(text, TABLE_CELL_MAX) == ELLIPSIS


@pytest.mark.parametrize(
    "cluster",
    [WOMAN_TECHNOLOGIST, E_TWO_MARKS, KSSA, KEYCAP_ONE, FLAG_RS, FLAG_SCOTLAND, THUMBS_UP_MEDIUM],
)
def test_each_shape_is_one_cluster(cluster: str) -> None:
    assert list(grapheme_clusters("x" + cluster + "y")) == ["x", cluster, "y"]


def test_crlf_and_controls_split_clusters() -> None:
    assert list(grapheme_clusters("a\r\nb\x01c")) == ["a", "\r\n", "b", "\x01", "c"]


def test_the_table_labels_cell_ends_on_a_cluster_boundary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    labels = {"note": "a" * 24 + WOMAN_TECHNOLOGIST + "zz"}
    info = SandboxInfo.from_payload(sandbox_json(labels))

    output.render_sandboxes(AppState(), [info])

    out = capsys.readouterr().out
    assert "note=" + "a" * 24 + ELLIPSIS in out
    assert ZWJ + ELLIPSIS not in out


# 3. the labels row of the field view


def text_get(router: Any, labels: dict[str, str]) -> str:
    router.get(SANDBOX_URL).respond(200, json=envelope(sandbox_json(labels)))
    result = invoke(["sandbox", "get", SID], as_json=False)
    assert result.exit_code == 0, result.output
    stdout: str = result.stdout
    return stdout


def squeezed(text: str) -> str:
    """``text`` without table borders and whitespace, so a folded value reads contiguous."""
    return "".join(BOX_DRAWING_RE.sub("", text).split())


def test_the_field_view_lists_every_label_on_its_own_line(router: Any) -> None:
    out = text_get(router, {"team": "ml", "env": "prod"})

    rows = [line for line in out.splitlines() if "team=ml" in line or "env=prod" in line]
    assert len(rows) == 2
    assert "labels" in rows[0]


def test_the_field_view_label_is_not_width_cut(router: Any) -> None:
    long_value = "x" * 300
    out = text_get(router, {"note": long_value, "team": "ml"})

    assert "note=" + long_value in squeezed(out)
    assert ELLIPSIS not in out


def test_the_field_view_labels_are_sanitised(router: Any) -> None:
    labels = {
        "clip": "\x1b]52;c;ZXZpbA==\x07ok",
        "multi": "line1\nfake=injected",
        "secret": f"token {PROFILE_KEY}",
    }
    out = text_get(router, labels)

    assert "\x1b" not in out
    assert "\x07" not in out
    assert "clip=ok" in out
    assert "multi=line1 fake=injected" in out
    assert PROFILE_KEY not in out


def test_the_field_view_shows_a_dash_without_labels() -> None:
    info = SandboxInfo.from_payload(sandbox_json({}))

    assert output.sandbox_fields(info)["labels"] == "-"


def test_the_labels_field_keeps_a_label_longer_than_the_table_cell() -> None:
    value = "v" * (TABLE_CELL_MAX * 2)
    info = SandboxInfo.from_payload(sandbox_json({"k": value, "team": "ml"}))

    assert output.sandbox_fields(info)["labels"] == f"k={value}\nteam=ml"
