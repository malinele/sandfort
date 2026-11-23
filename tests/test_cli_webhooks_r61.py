"""CLI r61: webhook polish (stubbed client).

``update --enable --disable`` is a usage error; a 404 on a webhook command appends the
shared-prefix hint; a delivery list that was never attempted prints a stale-dispatcher note.
"""

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import typer  # noqa: E402
from sandfort_cli import config, webhooks  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import DeliveryPage, WebhookDelivery, WebhookEndpoint  # noqa: E402
from sandfort_sdk.exceptions import error_for  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
PROFILE_KEY = "sf_test_key_do_not_print"
RUNNER = CliRunner()
EXIT_USAGE = 2
EXIT_FAILURE = 1
ORDER_HINT = (
    "webhook endpoint ids and delivery ids share the whk_ prefix; "
    "check the argument order (endpoint first, then delivery)"
)
ONE_ID_HINT = (
    "endpoint ids and delivery ids share the whk_ prefix; check that you passed an endpoint id"
)
NOTE_HEAD = "deliveries have not been attempted for "
NOTE_TAIL = " min; the server's dispatcher may be disabled or failing, ask the operator"
NOW = datetime.now(UTC)


def endpoint():
    return WebhookEndpoint(
        id="whk_e1",
        url="https://hooks.example.com/sandfort",
        enabled=True,
        event_types=("sandbox.*",),
        failure_count=0,
        created_at=NOW,
    )


def delivery(delivery_id="whk_d1", *, age_min=10, state="pending", attempts=0):
    created = NOW - timedelta(minutes=age_min)
    return WebhookDelivery(
        id=delivery_id,
        endpoint_id="whk_e1",
        event_id="evt_1",
        state=state,
        attempts=attempts,
        event_type="sandbox.started",
        next_attempt_at=None,
        last_status=None,
        last_error=None,
        payload_sha256="ab" * 32,
        attempt_history=(),
        created_at=created,
        updated_at=created,
    )


class FakeWebhooks:
    def __init__(self):
        self.calls = []
        self.error = None
        self.page = DeliveryPage((delivery(),), None)

    def _answer(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        if self.error is not None:
            raise self.error

    def get(self, endpoint_id):
        self._answer("get", endpoint_id)
        return endpoint()

    def update(self, endpoint_id, **kwargs):
        self._answer("update", endpoint_id, **kwargs)
        return endpoint()

    def delete(self, endpoint_id):
        self._answer("delete", endpoint_id)
        return endpoint()

    def create(self, url, events):
        self._answer("create", url, list(events))
        return endpoint()

    def list(self):
        self._answer("list")
        return (endpoint(),)

    def deliveries(self, endpoint_id, **kwargs):
        self._answer("deliveries", endpoint_id, **kwargs)
        return self.page

    def iter_deliveries(self, endpoint_id, **kwargs):
        yield from self.deliveries(endpoint_id, cursor=None, **kwargs).deliveries

    def get_delivery(self, endpoint_id, delivery_id):
        self._answer("get_delivery", endpoint_id, delivery_id)
        return delivery(delivery_id)

    def redeliver(self, endpoint_id, delivery_id):
        self._answer("redeliver", endpoint_id, delivery_id)
        return delivery(delivery_id)


class FakeClient:
    def __init__(self, hooks):
        self.webhooks = hooks

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture(autouse=True)
def profile(monkeypatch, tmp_path):
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, PROFILE_KEY)


class FrozenDatetime(datetime):
    """``datetime`` whose ``now`` is the module's ``NOW``, the instant the fixtures are built at."""

    @classmethod
    def now(cls, tz=None):
        return NOW if tz is None else NOW.astimezone(tz)


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch):
    """The stale-note age is measured against ``NOW``, not the wall clock of a long test run."""
    monkeypatch.setattr(webhooks, "datetime", FrozenDatetime)


@pytest.fixture
def hooks(monkeypatch):
    fake = FakeWebhooks()
    monkeypatch.setattr(webhooks, "open_client", lambda: FakeClient(fake))
    return fake


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(), (["--json"] if as_json else []) + ["webhook", *args])


def not_found(request_id=None):
    return error_for("NOT_FOUND", "webhook not found", status_code=404, request_id=request_id)


# --- 1. --enable and --disable are exclusive -------------------------------------------------


@pytest.mark.parametrize("flags", [["--enable", "--disable"], ["--disable", "--enable"]])
def test_update_enable_and_disable_together_is_a_usage_error(hooks, flags):
    result = invoke(["update", "whk_e1", *flags])

    assert result.exit_code == EXIT_USAGE
    assert "--enable" in result.output and "--disable" in result.output
    assert hooks.calls == []


def test_update_enable_alone_still_sends_true(hooks):
    result = invoke(["update", "whk_e1", "--enable"])

    assert result.exit_code == 0, result.output
    assert hooks.calls == [("update", ("whk_e1",), {"enabled": True})]


def test_update_disable_alone_still_sends_false(hooks):
    result = invoke(["update", "whk_e1", "--disable"])

    assert result.exit_code == 0, result.output
    assert hooks.calls == [("update", ("whk_e1",), {"enabled": False})]


def test_update_with_no_flag_is_still_a_usage_error(hooks):
    result = invoke(["update", "whk_e1"])

    assert result.exit_code == EXIT_USAGE
    assert hooks.calls == []


# --- 2. the 404 hint --------------------------------------------------------------------------

ONE_ID_COMMANDS = [
    ["get", "whk_d1"],
    ["rm", "whk_d1"],
    ["update", "whk_d1", "--enable"],
    ["deliveries", "whk_d1"],
    ["deliveries", "whk_d1", "--all"],
]
TWO_ID_COMMANDS = [
    ["deliveries", "whk_e1", "--show", "whk_e1"],
    ["redeliver", "whk_d1", "whk_e1"],
]
ID_COMMANDS = [*ONE_ID_COMMANDS, *TWO_ID_COMMANDS]


def expected_hint(args):
    return ONE_ID_HINT if args in ONE_ID_COMMANDS else ORDER_HINT


@pytest.mark.parametrize("args", ID_COMMANDS)
def test_a_404_appends_the_hint_line_after_the_error(hooks, args):
    hooks.error = not_found()

    result = invoke(args)

    assert result.exit_code == EXIT_FAILURE
    lines = result.stderr.strip().splitlines()
    assert lines[0].startswith("error: ") and "NOT_FOUND" in lines[0]
    assert lines[1:] == [expected_hint(args)]


@pytest.mark.parametrize("args", ONE_ID_COMMANDS)
def test_a_one_id_command_does_not_talk_about_argument_order(hooks, args):
    hooks.error = not_found()

    result = invoke(args)

    assert "argument order" not in result.output
    assert "check that you passed an endpoint id" in result.stderr


@pytest.mark.parametrize("args", TWO_ID_COMMANDS)
def test_a_two_id_command_keeps_the_argument_order_wording(hooks, args):
    hooks.error = not_found()

    assert "check the argument order (endpoint first, then delivery)" in invoke(args).stderr


def test_the_hint_keeps_the_request_id_suffix_on_the_error_line(hooks):
    hooks.error = not_found(request_id="req_abc123")

    result = invoke(["redeliver", "whk_d1", "whk_e1"])

    lines = result.stderr.strip().splitlines()
    assert lines[0].endswith("(request id req_abc123)")
    assert lines[1] == ORDER_HINT
    assert "req_abc123" not in lines[1]


def test_a_404_in_json_carries_the_hint_in_the_error_object(hooks):
    hooks.error = not_found(request_id="req_abc123")

    result = invoke(["get", "whk_d1"], as_json=True)

    assert result.exit_code == EXIT_FAILURE
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "NOT_FOUND"
    assert error["request_id"] == "req_abc123"
    assert error["hint"] == ONE_ID_HINT


def test_a_404_in_json_of_a_two_id_command_carries_the_order_hint(hooks):
    hooks.error = not_found()

    result = invoke(["redeliver", "whk_d1", "whk_e1"], as_json=True)

    assert json.loads(result.stdout)["error"]["hint"] == ORDER_HINT


@pytest.mark.parametrize(
    "error",
    [
        error_for("CONFLICT", "not failed", status_code=409),
        error_for("FORBIDDEN", "no scope", status_code=403),
        error_for("INTERNAL", "boom", status_code=500),
    ],
)
def test_other_errors_get_no_hint(hooks, error):
    hooks.error = error

    text = invoke(["redeliver", "whk_e1", "whk_d1"])
    as_json = invoke(["redeliver", "whk_e1", "whk_d1"], as_json=True)

    assert text.exit_code == EXIT_FAILURE
    assert "whk_ prefix" not in text.output
    assert "hint" not in json.loads(as_json.stdout)["error"]


@pytest.mark.parametrize("args", [["list"], ["create", "https://h.example/x", "--event", "*"]])
def test_commands_without_an_id_get_no_hint(hooks, args):
    hooks.error = not_found()

    result = invoke(args)

    assert result.exit_code == EXIT_FAILURE
    assert "whk_ prefix" not in result.output


# --- 3. deliveries that were never attempted --------------------------------------------------


def stale_note(result):
    return [line for line in result.stderr.splitlines() if line.startswith(NOTE_HEAD)]


def test_old_pending_unattempted_deliveries_print_one_note_after_the_table(hooks):
    items = (delivery("whk_d1", age_min=12), delivery("whk_d2", age_min=3))
    hooks.page = DeliveryPage(items, None)

    result = invoke(["deliveries", "whk_e1"])

    assert result.exit_code == 0, result.output
    notes = stale_note(result)
    assert len(notes) == 1 and notes[0].endswith(NOTE_TAIL)
    minutes = notes[0].removeprefix(NOTE_HEAD).removesuffix(NOTE_TAIL)
    assert minutes.isdigit() and int(minutes) >= 12  # the oldest, whole minutes
    assert "whk_d1" in result.stdout and "ask the operator" not in result.stdout


def test_the_note_follows_the_next_cursor_line(hooks):
    hooks.page = DeliveryPage((delivery(),), "c1")

    result = invoke(["deliveries", "whk_e1"])

    lines = result.stderr.strip().splitlines()
    assert lines[0] == "next cursor: c1"
    assert lines[1].startswith(NOTE_HEAD) and lines[1].endswith(NOTE_TAIL)


def test_the_note_also_follows_all_pages(hooks):
    result = invoke(["deliveries", "whk_e1", "--all"])

    assert result.exit_code == 0, result.output
    assert len(stale_note(result)) == 1


def test_the_note_is_not_printed_with_json(hooks):
    result = invoke(["deliveries", "whk_e1"], as_json=True)

    assert result.exit_code == 0, result.output
    assert result.stderr == ""
    assert "deliveries" in json.loads(result.stdout)


@pytest.mark.parametrize(
    "items",
    [
        (delivery(age_min=4),),
        (delivery(age_min=0),),
        (delivery(attempts=1),),
        (delivery(state="failed"),),
        (delivery(age_min=30), delivery("whk_d2", age_min=30, state="delivered", attempts=1)),
        (delivery(age_min=30), delivery("whk_d2", age_min=1, attempts=2)),
        (),
    ],
)
def test_no_note_unless_all_pending_unattempted_and_the_oldest_is_over_five_min(hooks, items):
    hooks.page = DeliveryPage(items, None)

    result = invoke(["deliveries", "whk_e1"])

    assert result.exit_code == 0, result.output
    assert stale_note(result) == []


def test_show_prints_no_note(hooks):
    result = invoke(["deliveries", "whk_e1", "--show", "whk_d1"])

    assert result.exit_code == 0, result.output
    assert stale_note(result) == []


# --- 4. cli_errors takes a hint callback; rm reuses the app state -----------------------------


def test_the_webhook_module_has_no_error_renderer_of_its_own():
    assert not hasattr(webhooks, "id_hint_on_not_found")


def run_with_hint(hint, error, *, as_json):
    from sandfort_cli import output

    output.set_json_errors(as_json)
    try:
        with pytest.raises(typer.Exit) as exit_info, output.cli_errors(hint=hint):
            raise error
    finally:
        output.set_json_errors(False)
    return exit_info.value.exit_code


def test_cli_errors_prints_the_callback_hint_in_text(capsys):
    code = run_with_hint(lambda exc: "try this", not_found(), as_json=False)

    assert code == EXIT_FAILURE
    lines = capsys.readouterr().err.strip().splitlines()
    assert lines[0].startswith("error: ") and lines[1:] == ["try this"]


def test_cli_errors_puts_the_callback_hint_in_the_json_error(capsys):
    run_with_hint(lambda exc: "try this", not_found(), as_json=True)

    assert json.loads(capsys.readouterr().out)["error"]["hint"] == "try this"


def test_a_callback_returning_none_adds_no_hint(capsys):
    run_with_hint(lambda exc: None, not_found(), as_json=True)

    assert "hint" not in json.loads(capsys.readouterr().out)["error"]


def test_rm_builds_the_app_state_once(hooks, monkeypatch):
    calls = []
    real = webhooks.app_state
    monkeypatch.setattr(webhooks, "app_state", lambda ctx: calls.append(1) or real(ctx))

    result = invoke(["rm", "whk_e1"])

    assert result.exit_code == 0, result.output
    assert len(calls) == 1
