"""CLI round 51, batch 3: success-path sanitisation.

A hostile server can put terminal escapes and secrets into SUCCESS output as well as into
errors. Every server string that reaches a success renderer now goes through the sanitiser:

* table cells (``sandbox list``, ``sandbox isolation``) and field views (``get``, ``create``,
  ``stop``): ids, names, states, isolation, snapshot, error reason and code;
* the string values of ``--json`` success output (numbers, booleans and null stay typed);
* the malformed-timestamp message (``key list``, ``sandbox get``), whose repr of the bad value
  is evaluated back, sanitised and written again, so a key split by a literal escape sequence
  cannot survive it.

The exec relay strips the string sequences a terminal acts on (OSC with the clipboard write,
DCS, SOS, PM, APC and the C1 introducers) and otherwise relays program output as it is:
nothing is masked.
"""

import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import strip_dangerous_terminal  # noqa: E402
from sandfort_cli.sanitise import MASK  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SANDBOXES_URL = "/v1/sandboxes"
SANDBOX_URL = f"{SANDBOXES_URL}/{SID}"
EXEC_URL = f"{SANDBOX_URL}/toolbox/process/execute"
ISOLATION_URL = "/v1/isolation"
KEYS_URL = "/v1/api-keys"
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])

ESC = "\x1b"
OSC_TITLE = f"{ESC}]0;pwned-title\x07"
OSC_CLIPBOARD = f"{ESC}]52;c;c2VjcmV0LWNsaXA=\x07"
PASSWORD = "Zx9Qm4Lv7Tn2Bk8Rw5Hd"
CREDENTIAL_URL = f"https://admin:{PASSWORD}@host.test/repo"
FOREIGN_KEY = "sf_" + "abcdefghijklmnop"
# What must never reach the terminal or a script reading the json.
LEAKS = ("\x1b", "pwned-title", "c2VjcmV0", PASSWORD, KEY, FOREIGN_KEY)


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def hostile_sandbox(**extra: Any) -> dict[str, Any]:
    """A sandbox whose server-provided strings carry an OSC, a credential url and keys."""
    base = {
        "id": f"{SID}{OSC_TITLE}",
        "name": f"web{OSC_TITLE}-{CREDENTIAL_URL}-{KEY}",
        "state": f"started{OSC_CLIPBOARD}",
        "isolation": f"gvisor{OSC_TITLE}{FOREIGN_KEY}",
        "snapshot": f"img{OSC_TITLE}:{CREDENTIAL_URL}",
        "error_reason": f"boom{OSC_TITLE} {CREDENTIAL_URL} {KEY}",
        "error_code": f"E_{OSC_TITLE}{FOREIGN_KEY}",
        "labels": {f"k{OSC_TITLE}": f"v-{KEY}"},
        "resources": {"cpu_millicores": 1500, "memory_mib": 256, "disk_gib": 4},
        "public": False,
    }
    return {**base, **extra}


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def assert_clean(*texts: str) -> None:
    for text in texts:
        for leak in LEAKS:
            assert leak not in text, f"{leak!r} leaked into {text!r}"


@pytest.fixture(autouse=True)
def profile_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def api() -> Iterator[Any]:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router


# --- sandbox list --------------------------------------------------------------------------


def test_a_list_answer_is_clean_in_the_table(api: Any) -> None:
    api.get(SANDBOXES_URL).respond(200, json=envelope([hostile_sandbox()]))

    result = invoke(["sandbox", "list"])

    assert result.exit_code == 0, result.output
    assert_clean(result.stdout, result.stderr)
    assert SID in result.stdout  # the id keeps its real part
    assert "web" in result.stdout and "started" in result.stdout and "gvisor" in result.stdout


def test_a_list_answer_is_masked_in_the_json_values(api: Any) -> None:
    api.get(SANDBOXES_URL).respond(200, json=envelope([hostile_sandbox()]))

    result = invoke(["sandbox", "list"], as_json=True)

    assert result.exit_code == 0, result.output
    assert_clean(result.stdout)
    (item,) = json.loads(result.stdout)
    assert item["id"] == SID
    assert item["name"].startswith("web-") and MASK in item["name"]
    assert item["state"] == "started"
    assert item["isolation"].startswith("gvisor") and MASK in item["isolation"]
    assert item["error_reason"].startswith("boom") and MASK in item["error_reason"]
    assert item["error_code"].startswith("E_") and MASK in item["error_code"]
    assert item["snapshot"].startswith("img")
    assert [MASK in value for value in item["labels"].values()] == [True]
    assert all("\x1b" not in label for label in item["labels"])


def test_non_string_json_values_stay_typed(api: Any) -> None:
    api.get(SANDBOXES_URL).respond(200, json=envelope([hostile_sandbox()]))

    (item,) = json.loads(invoke(["sandbox", "list"], as_json=True).stdout)

    assert item["resources"] == {"cpu_millicores": 1500, "memory_mib": 256, "disk_gib": 4}
    assert item["public"] is False
    assert item["block_network"] is False
    assert item["job_id"] is None
    assert isinstance(item["auto_stop_minutes"], int)


def test_two_labels_that_sanitise_to_one_key_are_both_kept(api: Any) -> None:
    labels = {f"k{OSC_TITLE}": "first", "k": "second"}
    api.get(SANDBOXES_URL).respond(200, json=envelope([hostile_sandbox(labels=labels)]))

    (item,) = json.loads(invoke(["sandbox", "list"], as_json=True).stdout)

    assert sorted(item["labels"].values()) == ["first", "second"]


def test_the_isolation_tiers_are_clean_in_both_modes(api: Any) -> None:
    tiers = {"default": f"gvisor{OSC_TITLE}", "available": [f"container{OSC_CLIPBOARD}", "gvisor"]}
    api.get(ISOLATION_URL).respond(200, json=envelope(tiers))

    table = invoke(["sandbox", "isolation"])
    data = invoke(["sandbox", "isolation"], as_json=True)

    assert_clean(table.stdout, data.stdout)
    assert "container" in table.stdout and "gvisor" in table.stdout
    assert json.loads(data.stdout) == {"default": "gvisor", "available": ["container", "gvisor"]}


# --- field views ---------------------------------------------------------------------------


def _field_view(args: list[str], api: Any, *, as_json: bool) -> Any:
    hostile = hostile_sandbox()
    api.get(SANDBOX_URL).respond(200, json=envelope(hostile))
    api.post(f"{SANDBOX_URL}/stop").respond(200, json=envelope(hostile))
    api.post(SANDBOXES_URL).respond(201, json=envelope(hostile))
    return invoke(args, as_json=as_json)


@BOTH_MODES
@pytest.mark.parametrize(
    "args",
    [
        ["sandbox", "get", SID],
        ["sandbox", "stop", SID],
        ["sandbox", "create", "demo"],
    ],
    ids=["get", "stop", "create"],
)
def test_a_field_view_is_clean(api: Any, args: list[str], as_json: bool) -> None:
    result = _field_view(args, api, as_json=as_json)

    assert result.exit_code == 0, result.output
    assert_clean(result.stdout, result.stderr)
    if as_json:
        payload = json.loads(result.stdout)
        assert payload["id"] == SID and MASK in payload["name"]
        assert payload["resources"]["cpu_millicores"] == 1500
    else:
        assert "web" in result.stdout and "gvisor" in result.stdout
        assert "1500" in result.stdout  # typed values print as before


def test_the_text_field_view_masks_the_name_and_the_error_reason(api: Any) -> None:
    result = _field_view(["sandbox", "get", SID], api, as_json=False)

    rows = {
        line.split("│")[1].strip(): line.split("│")[2].strip()
        for line in result.stdout.splitlines()
        if line.count("│") >= 3
    }
    assert MASK in rows["name"] and MASK in rows["error_reason"]
    assert rows["state"] == "started" and rows["id"] == SID


# --- the malformed timestamp message -------------------------------------------------------


def split_by_escape(secret: str) -> str:
    """``secret`` cut in the middle by a real terminal sequence."""
    middle = len(secret) // 2
    return f"{secret[:middle]}{ESC}[0m{secret[middle:]}"


def key_info(**extra: Any) -> dict[str, Any]:
    base = {
        "id": "key_1",
        "name": "ci",
        "prefix": "sf_abcd",
        "scopes": ["sandboxes:read"],
        "sandbox_labels": None,
        "max_sandboxes": None,
        "created_at": "2026-10-30T19:26:00Z",
        "last_used_at": None,
        "expires_at": None,
        "revoked_at": None,
        "created_by": None,
    }
    return {**base, **extra}


@BOTH_MODES
@pytest.mark.parametrize("secret", [KEY, FOREIGN_KEY], ids=["callers-key", "key-shaped"])
def test_a_malformed_key_timestamp_with_a_split_key_is_masked(
    api: Any, as_json: bool, secret: str
) -> None:
    bad = f"yesterday {split_by_escape(secret)}"
    api.get(KEYS_URL).respond(200, json=envelope([key_info(created_at=bad)]))

    result = invoke(["key", "list"], as_json=as_json)

    shown = result.stdout + result.stderr
    assert result.exit_code == 1
    assert "invalid timestamp" in shown and "yesterday" in shown
    assert secret not in shown
    assert secret[: len(secret) // 2] not in shown.replace(MASK, "")
    assert "\\x1b" not in shown and "\x1b" not in shown
    assert MASK in shown


@BOTH_MODES
def test_a_malformed_sandbox_timestamp_with_a_split_key_is_masked(api: Any, as_json: bool) -> None:
    bad = f"later {split_by_escape(KEY)}"
    body = hostile_sandbox(created_at=bad, id=SID, name="demo", error_reason=None)
    api.get(SANDBOX_URL).respond(200, json=envelope(body))

    result = invoke(["sandbox", "get", SID], as_json=as_json)

    shown = result.stdout + result.stderr
    assert result.exit_code == 1
    assert "invalid timestamp" in shown and "later" in shown
    assert KEY not in shown and KEY[: len(KEY) // 2] not in shown.replace(MASK, "")
    assert "\\x1b" not in shown and "\x1b" not in shown


# --- the exec relay ------------------------------------------------------------------------


def exec_answer(stdout: str, stderr: str = "") -> dict[str, Any]:
    return {
        "exit_code": 0,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": False,
        "truncated": False,
        "duration_ms": 3,
    }


def run_exec(api: Any, stdout: str, stderr: str = "") -> Any:
    sandbox = {"id": SID, "name": "demo", "state": "started"}
    api.get(SANDBOX_URL).respond(200, json=envelope(sandbox))
    api.post(EXEC_URL).respond(200, json=envelope(exec_answer(stdout, stderr)))
    return invoke(["exec", SID, "true"])


def test_exec_strips_an_osc_52_clipboard_write_and_keeps_the_text(api: Any) -> None:
    result = run_exec(api, f"before {OSC_CLIPBOARD}after\n", f"warn {OSC_TITLE}done\n")

    assert result.exit_code == 0
    assert result.stdout == "before after\n"
    assert result.stderr == "warn done\n"


@pytest.mark.parametrize(
    ("sent", "relayed"),
    [
        (f"a{ESC}]52;c;AAAA{ESC}\\b", "ab"),  # OSC ended by the 7-bit string terminator
        ("a\x9d52;c;AAAA\x9cb", "ab"),  # C1 OSC introducer and C1 terminator
        (f"a{ESC}Pq data{ESC}\\b", "ab"),  # DCS
        (f"a{ESC}_Gdata{ESC}\\b", "ab"),  # APC
        (f"a{ESC}^note{ESC}\\b", "ab"),  # PM
        (f"a{ESC}Xnote{ESC}\\b", "ab"),  # SOS
        ("a\x90q\x9cb", "ab"),  # C1 DCS
        (f"a{ESC}]0;never ends", "a"),  # swallows the rest, as a terminal does
    ],
    ids=["osc-st", "c1-osc", "dcs", "apc", "pm", "sos", "c1-dcs", "unterminated"],
)
def test_exec_strips_every_dangerous_string_sequence(api: Any, sent: str, relayed: str) -> None:
    result = run_exec(api, sent)

    assert result.exit_code == 0
    assert result.stdout == relayed
    assert "\x1b" not in result.stdout and "\x9d" not in result.stdout


def test_exec_leaves_ordinary_text_and_csi_stripped_content_unchanged(api: Any) -> None:
    text = "plain text\nsecond line\ttabbed — ünïcode ✓\n$ echo '[1;2m'\n"

    result = run_exec(api, text, text)

    assert result.stdout == text
    assert result.stderr == text
    assert strip_dangerous_terminal(text) == text


def test_exec_does_not_mask_a_key_shaped_token_in_program_output(api: Any) -> None:
    output = f"token={FOREIGN_KEY} key={KEY} {CREDENTIAL_URL}\n"

    result = run_exec(api, output)

    assert result.stdout == output
    assert MASK not in result.stdout
