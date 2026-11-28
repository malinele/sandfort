"""Round 103 (B27, client side): ``browser_url`` in the Python SDK, the CLI, the TS SDK and docs."""

import json
import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli import cmd_cmd  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import shown  # noqa: E402
from sandfort_cli.preview_browser import HANDOFF_PARAM, browser_view  # noqa: E402
from sandfort_sdk.exceptions import InvalidResponseError  # noqa: E402
from sandfort_sdk.models import PreviewInfo  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
KEY = "sf_test_key_do_not_print"
PLAIN_TOKEN = "pvt_AbC123xyz"
# Key-shaped: the sanitiser masks it, so it is "altered" and must never be spliced into a url.
ALTERED_TOKEN = "sf_" + "A" * 24
EXPIRES = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
HOST = f"https://3000-{SID}.preview.test"
QUERY_URL = f"{HOST}/?{HANDOFF_PARAM}={PLAIN_TOKEN}"
BROWSER_URL = f"{HOST}/__sandfort/preview#{HANDOFF_PARAM}={PLAIN_TOKEN}"
RUNNER = CliRunner()
TS_OPS = ROOT / "sdk" / "typescript" / "src" / "sandbox-ops.ts"
GUIDE = ROOT / "docs" / "connect-guide.md"
CMD_CMD = ROOT / "cli" / "src" / "sandfort_cli" / "cmd_cmd.py"
PREVIEW_BROWSER = ROOT / "cli" / "src" / "sandfort_cli" / "preview_browser.py"
CMD_CMD_MAX_LINES = 465  # its size before round 103: the browser logic lives in preview_browser


def payload(**extra: Any) -> dict[str, Any]:
    return {
        "url": QUERY_URL,
        "token": PLAIN_TOKEN,
        "port": 3000,
        "expires_at": "2026-11-05T12:00:00+00:00",
        **extra,
    }


# 1) Python SDK ---------------------------------------------------------------------------------


def test_browser_url_is_read_when_the_server_sends_it() -> None:
    info = PreviewInfo.from_payload(payload(browser_url=BROWSER_URL))

    assert info.browser_url == BROWSER_URL
    assert info.url == QUERY_URL
    assert info.token == PLAIN_TOKEN


def test_browser_url_is_none_when_absent_or_null() -> None:
    assert PreviewInfo.from_payload(payload()).browser_url is None
    assert PreviewInfo.from_payload(payload(browser_url=None)).browser_url is None


def test_a_browser_url_that_is_not_a_string_is_an_invalid_response() -> None:
    with pytest.raises(InvalidResponseError, match="browser_url"):
        PreviewInfo.from_payload(payload(browser_url=5))


def test_the_four_positional_fields_still_build_a_preview_info() -> None:
    info = PreviewInfo(QUERY_URL, PLAIN_TOKEN, 3000, EXPIRES)

    assert info.browser_url is None


# 2) CLI: browser_view --------------------------------------------------------------------------


def test_browser_view_puts_the_token_back_into_the_fragment() -> None:
    assert browser_view(BROWSER_URL, PLAIN_TOKEN, KEY) == (BROWSER_URL, True)


def test_browser_view_masks_a_fragment_that_is_not_the_token_pair() -> None:
    other = f"{HOST}/__sandfort/preview#other={PLAIN_TOKEN}"

    text, carried = browser_view(other, PLAIN_TOKEN, KEY)

    assert not carried
    assert PLAIN_TOKEN not in text


def test_browser_view_never_splices_an_altered_token() -> None:
    assert shown(ALTERED_TOKEN, KEY) != ALTERED_TOKEN  # the premise: the sanitiser alters it
    url = f"{HOST}/__sandfort/preview#{HANDOFF_PARAM}={ALTERED_TOKEN}"

    text, carried = browser_view(url, ALTERED_TOKEN, KEY)

    assert not carried
    assert ALTERED_TOKEN not in text


def test_browser_view_sanitises_the_host_and_path() -> None:
    hostile = f"https://h.test/\x1b[31mpath#{HANDOFF_PARAM}={PLAIN_TOKEN}"

    text, carried = browser_view(hostile, PLAIN_TOKEN, KEY)

    assert carried
    assert "\x1b" not in text
    assert text.endswith(f"#{HANDOFF_PARAM}={PLAIN_TOKEN}")


def test_the_handoff_parameter_is_the_query_parameter_of_the_cli() -> None:
    assert HANDOFF_PARAM == cmd_cmd.TOKEN_PARAM


# 3) CLI: the preview command -------------------------------------------------------------------


class FakeSandbox:
    state = "started"

    def __init__(self, info: PreviewInfo) -> None:
        self._info = info

    def preview(self, port: int, *, ttl_seconds: int | None = None) -> PreviewInfo:
        return self._info


def serve(monkeypatch: pytest.MonkeyPatch, info: PreviewInfo) -> None:
    sandbox = FakeSandbox(info)

    @contextmanager
    def opened() -> Iterator[Any]:
        yield SimpleNamespace(get=lambda sandbox_id: sandbox)

    monkeypatch.setattr(cmd_cmd, "open_client", opened)


def preview_run(*, as_json: bool = False, browser: bool = False) -> Any:
    args = (["--json"] if as_json else []) + ["preview", SID, "3000"]
    result = RUNNER.invoke(create_app(None), args + (["--browser"] if browser else []))
    assert result.exit_code == 0, result.output
    return result


def test_text_mode_prints_the_scriptable_url_even_when_a_browser_url_was_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serve(monkeypatch, PreviewInfo(QUERY_URL, PLAIN_TOKEN, 3000, EXPIRES, BROWSER_URL))

    assert preview_run().stdout == QUERY_URL + "\n"  # what curl "$(sandfort preview ...)" needs


def test_the_browser_flag_prints_the_browser_url_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serve(monkeypatch, PreviewInfo(QUERY_URL, PLAIN_TOKEN, 3000, EXPIRES, BROWSER_URL))

    assert preview_run(browser=True).stdout == BROWSER_URL + "\n"


@pytest.mark.parametrize("browser", [False, True])
def test_text_mode_prints_the_query_url_when_there_is_no_browser_url(
    monkeypatch: pytest.MonkeyPatch, browser: bool
) -> None:
    serve(monkeypatch, PreviewInfo(QUERY_URL, PLAIN_TOKEN, 3000, EXPIRES))

    assert preview_run(browser=browser).stdout == QUERY_URL + "\n"


def test_a_url_without_the_token_gets_a_token_line_unless_the_browser_url_carries_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serve(monkeypatch, PreviewInfo(f"{HOST}/", PLAIN_TOKEN, 3000, EXPIRES, BROWSER_URL))

    assert preview_run().stdout.splitlines() == [f"{HOST}/", f"token: {PLAIN_TOKEN}"]
    assert preview_run(browser=True).stdout == BROWSER_URL + "\n"


def test_the_browser_flag_falls_back_when_the_browser_url_cannot_carry_the_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    other = f"{HOST}/__sandfort/preview#other={PLAIN_TOKEN}"
    serve(monkeypatch, PreviewInfo(QUERY_URL, PLAIN_TOKEN, 3000, EXPIRES, other))

    flagged = preview_run(browser=True).stdout

    assert flagged == QUERY_URL + "\n"  # the same as without the flag, never a #*** link
    assert flagged == preview_run().stdout


def test_json_carries_both_urls_the_token_and_the_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serve(monkeypatch, PreviewInfo(QUERY_URL, PLAIN_TOKEN, 3000, EXPIRES, BROWSER_URL))

    assert json.loads(preview_run(as_json=True).stdout) == {
        "url": QUERY_URL,
        "browser_url": BROWSER_URL,
        "token": PLAIN_TOKEN,
        "port": 3000,
        "expires_at": "2026-11-05T12:00:00+00:00",
    }


def test_json_has_no_browser_url_key_when_the_server_sent_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serve(monkeypatch, PreviewInfo(QUERY_URL, PLAIN_TOKEN, 3000, EXPIRES))

    document = json.loads(preview_run(as_json=True).stdout)

    assert sorted(document) == ["expires_at", "port", "token", "url"]


def test_an_altered_token_is_not_spliced_into_the_browser_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser = f"{HOST}/__sandfort/preview#{HANDOFF_PARAM}={ALTERED_TOKEN}"
    query = f"{HOST}/?{HANDOFF_PARAM}={ALTERED_TOKEN}"
    serve(monkeypatch, PreviewInfo(query, ALTERED_TOKEN, 3000, EXPIRES, browser))

    lines = preview_run().stdout.splitlines()
    document = json.loads(preview_run(as_json=True).stdout)

    assert ALTERED_TOKEN not in lines[0]
    assert "#" not in lines[0]
    assert lines[1:] == [f"token: {ALTERED_TOKEN}"]
    assert preview_run(browser=True).stdout.splitlines() == lines
    assert ALTERED_TOKEN not in document["browser_url"]
    assert document["token"] == ALTERED_TOKEN


def test_json_ignores_the_browser_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    serve(monkeypatch, PreviewInfo(QUERY_URL, PLAIN_TOKEN, 3000, EXPIRES, BROWSER_URL))

    flagged = json.loads(preview_run(as_json=True, browser=True).stdout)

    assert flagged == json.loads(preview_run(as_json=True).stdout)
    assert flagged["url"] == QUERY_URL
    assert flagged["browser_url"] == BROWSER_URL


def test_the_preview_command_stays_small_and_keeps_its_logic_apart() -> None:
    cmd_lines = CMD_CMD.read_text(encoding="utf-8").splitlines()
    browser_lines = PREVIEW_BROWSER.read_text(encoding="utf-8").splitlines()

    assert len(cmd_lines) <= CMD_CMD_MAX_LINES
    assert len(browser_lines) < 400
    assert all(len(line) <= 100 for line in cmd_lines + browser_lines)


# 4) TypeScript SDK (source shape: the pytest gates cannot run vitest) --------------------------


def ts_ops_between(start: str, end: str) -> str:
    src = TS_OPS.read_text(encoding="utf-8")
    return src[src.index(start) : src.index(end)]


def test_the_ts_preview_token_declares_an_optional_browser_url_and_keeps_url() -> None:
    declaration = ts_ops_between("export interface PreviewToken", "export interface IsolationInfo")

    assert "  browserUrl?: string;" in declaration
    assert "  url: string;" in declaration
    assert "readonly token: string;" in declaration


def test_the_ts_decoder_reads_browser_url_and_still_hides_the_token() -> None:
    decoder = ts_ops_between(
        "export function previewTokenFromPayload", "export function isolationFromPayload"
    )
    src = TS_OPS.read_text(encoding="utf-8")

    assert 'optionalString(raw, "browser_url")' in decoder
    assert "...(browserUrl === undefined ? {} : { browserUrl })," in decoder
    assert 'withHiddenSecret(info, "token", token)' in decoder
    assert re.search(r'import \{[^}]*\boptionalString\b[^}]*\} from "\./models\.js"', src)


# 5) docs ---------------------------------------------------------------------------------------


def test_connect_guide_section_4_says_which_url_to_open_and_which_to_script() -> None:
    guide = " ".join(GUIDE.read_text(encoding="utf-8").split())
    section = guide[guide.index("## 4. Preview URLs") : guide.index("## 5. Beta limits")]

    for needle in (
        "`browser_url`",
        "`sandfort preview` prints `url`",
        "`sandfort preview --browser` prints `browser_url` when the reply has it",
        "/__sandfort/preview",
        "needs JavaScript",
        "`Sandfort-Preview-Token`",
        "uses only the first of the header, the query and the cookie, in that order",
        "plain-HTTP preview origin",
        "Treat `url` and `browser_url` as credentials",
    ):
        assert needle in section
    assert "It is not implemented." not in section
