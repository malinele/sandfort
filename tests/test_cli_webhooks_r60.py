"""CLI r60: the `webhook` command group over `client.webhooks` (stubbed client).

create, list, get, update, rm, deliveries (one page, --all, --show) and redeliver; the
signing secret never reaches the output unless --json and --show-secret are both given.
"""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
from sandfort_cli import config, webhooks  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    DeliveryAttempt,
    DeliveryPage,
    WebhookDelivery,
    WebhookEndpoint,
)
from sandfort_sdk.exceptions import error_for  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
PROFILE_KEY = "sf_test_key_do_not_print"
SECRET = "whsec_QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU="
RUNNER = CliRunner()
EXIT_USAGE = 2
EXIT_FAILURE = 1
ESC = "\x1b"
WHEN = datetime(2026, 11, 10, 8, 30, tzinfo=UTC)


def endpoint(endpoint_id="whe_1", **extra):
    base = {
        "id": endpoint_id,
        "url": "https://hooks.example.com/sandfort",
        "enabled": True,
        "event_types": ("sandbox.*",),
        "failure_count": 0,
        "created_at": WHEN,
    }
    return WebhookEndpoint(**{**base, **extra})


def attempt(**extra):
    base = {"attempted_at": WHEN, "status": 503, "error": "http 503", "duration_ms": 41}
    return DeliveryAttempt(**{**base, **extra})


def delivery(delivery_id="whd_1", **extra):
    base = {
        "id": delivery_id,
        "endpoint_id": "whe_1",
        "event_id": "evt_1",
        "state": "failed",
        "attempts": 2,
        "event_type": "sandbox.started",
        "next_attempt_at": None,
        "last_status": 503,
        "last_error": "http 503",
        "payload_sha256": "ab" * 32,
        "attempt_history": (attempt(), attempt(status=None, error="connect timeout")),
        "created_at": WHEN,
        "updated_at": WHEN,
    }
    return WebhookDelivery(**{**base, **extra})


class FakeWebhooks:
    """Records every SDK call; answers from the configured values or raises ``error``."""

    def __init__(self):
        self.calls = []
        self.endpoint = endpoint()
        self.endpoints = (endpoint(), endpoint("whe_2", enabled=False, event_types=()))
        self.pages = {None: DeliveryPage((delivery(),), None)}
        self.delivery = delivery()
        self.error = None

    def _answer(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        if self.error is not None:
            raise self.error

    def create(self, url, events, **kwargs):
        self._answer("create", url, list(events), **kwargs)
        return self.endpoint

    def list(self):
        self._answer("list")
        return self.endpoints

    def get(self, endpoint_id):
        self._answer("get", endpoint_id)
        return self.endpoint

    def update(self, endpoint_id, **kwargs):
        events = kwargs.get("events")
        if events is not None:
            kwargs["events"] = list(events)
        self._answer("update", endpoint_id, **kwargs)
        return self.endpoint

    def delete(self, endpoint_id):
        self._answer("delete", endpoint_id)
        return self.endpoint

    def deliveries(self, endpoint_id, **kwargs):
        self._answer("deliveries", endpoint_id, **kwargs)
        return self.pages[kwargs.get("cursor")]

    def iter_deliveries(self, endpoint_id, **kwargs):
        self.calls.append(("iter_deliveries", (endpoint_id,), kwargs))
        cursor = None
        while True:
            page = self.deliveries(endpoint_id, cursor=cursor, **kwargs)
            yield from page.deliveries
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    def get_delivery(self, endpoint_id, delivery_id):
        self._answer("get_delivery", endpoint_id, delivery_id)
        return self.delivery

    def redeliver(self, endpoint_id, delivery_id):
        self._answer("redeliver", endpoint_id, delivery_id)
        return self.delivery


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


@pytest.fixture
def hooks(monkeypatch):
    fake = FakeWebhooks()
    monkeypatch.setattr(webhooks, "open_client", lambda: FakeClient(fake))
    return fake


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(), (["--json"] if as_json else []) + ["webhook", *args])


def names(hooks):
    return [call[0] for call in hooks.calls]


# --- create ---------------------------------------------------------------------------------


def test_create_passes_url_and_every_event_to_the_sdk(hooks):
    result = invoke(["create", "https://h.example/x", "--event", "sandbox.*", "--event", "*"])

    assert result.exit_code == 0, result.output
    assert hooks.calls == [("create", ("https://h.example/x", ["sandbox.*", "*"]), {})]


def test_create_text_never_prints_the_secret(hooks):
    hooks.endpoint = endpoint(secret=SECRET)

    result = invoke(["create", "https://h.example/x", "--event", "*"])

    assert result.exit_code == 0, result.output
    assert SECRET not in result.output
    assert "whe_1" in result.stdout
    assert "--show-secret" in result.stderr


def test_create_json_without_show_secret_leaves_the_secret_out(hooks):
    hooks.endpoint = endpoint(secret=SECRET)

    result = invoke(["create", "https://h.example/x", "--event", "*"], as_json=True)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert "secret" not in payload
    assert SECRET not in result.output
    assert payload["event_types"] == ["sandbox.*"]


def test_create_json_with_show_secret_prints_it_exactly(hooks):
    hooks.endpoint = endpoint(secret=SECRET)

    args = ["create", "https://h.example/x", "--event", "*", "--show-secret"]
    result = invoke(args, as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["secret"] == SECRET


def test_create_refuses_a_secret_that_is_not_printable(hooks):
    hooks.endpoint = endpoint(secret=f"whsec_{ESC}]52;c;x")

    args = ["create", "https://h.example/x", "--event", "*", "--show-secret"]
    result = invoke(args, as_json=True)

    assert result.exit_code == EXIT_FAILURE
    assert ESC not in result.output
    assert "whsec_" not in result.output


def test_show_secret_without_json_is_a_usage_error(hooks):
    result = invoke(["create", "https://h.example/x", "--event", "*", "--show-secret"])

    assert result.exit_code == EXIT_USAGE
    assert hooks.calls == []


@pytest.mark.parametrize(
    "event", ["", "  ", "Sandbox.Started", "sandbox", "sandbox.started.x", "*.*", "a b.c"]
)
def test_create_rejects_a_bad_event_before_any_call(hooks, event):
    result = invoke(["create", "https://h.example/x", "--event", event])

    assert result.exit_code == EXIT_USAGE
    assert hooks.calls == []


def test_create_needs_at_least_one_event(hooks):
    result = invoke(["create", "https://h.example/x"])

    assert result.exit_code == EXIT_USAGE
    assert hooks.calls == []


def test_create_rejects_a_blank_url(hooks):
    result = invoke(["create", " ", "--event", "*"])

    assert result.exit_code == EXIT_USAGE
    assert hooks.calls == []


# --- list, get, rm --------------------------------------------------------------------------


def test_list_text_shows_every_endpoint(hooks):
    result = invoke(["list"])

    assert result.exit_code == 0, result.output
    assert names(hooks) == ["list"]
    assert "whe_1" in result.stdout and "whe_2" in result.stdout


def test_list_json_is_a_list_of_endpoint_objects(hooks):
    result = invoke(["list"], as_json=True)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert [item["id"] for item in payload] == ["whe_1", "whe_2"]
    assert payload[1]["enabled"] is False
    assert payload[0]["created_at"] == WHEN.isoformat()


def test_get_calls_the_sdk_with_the_id(hooks):
    result = invoke(["get", "whe_9"], as_json=True)

    assert result.exit_code == 0, result.output
    assert hooks.calls == [("get", ("whe_9",), {})]


@pytest.mark.parametrize("command", ["get", "rm", "deliveries"])
def test_a_blank_endpoint_id_is_a_usage_error(hooks, command):
    result = invoke([command, "  "])

    assert result.exit_code == EXIT_USAGE
    assert hooks.calls == []


def test_rm_deletes_without_a_prompt_and_prints_the_id(hooks):
    result = invoke(["rm", "whe_1"])

    assert result.exit_code == 0, result.output
    assert hooks.calls == [("delete", ("whe_1",), {})]
    assert result.stdout.strip() == "whe_1"


def test_rm_json_prints_the_deleted_endpoint(hooks):
    result = invoke(["rm", "whe_1"], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["id"] == "whe_1"


# --- update ---------------------------------------------------------------------------------


def test_update_passes_only_the_given_fields(hooks):
    args = ["update", "whe_1", "--url", "https://n.example", "--event", "sandbox.stopped"]
    result = invoke([*args, "--disable"])

    assert result.exit_code == 0, result.output
    expected = {"url": "https://n.example", "events": ["sandbox.stopped"], "enabled": False}
    assert hooks.calls == [("update", ("whe_1",), expected)]


def test_update_enable_alone(hooks):
    result = invoke(["update", "whe_1", "--enable"])

    assert result.exit_code == 0, result.output
    assert hooks.calls == [("update", ("whe_1",), {"enabled": True})]


def test_update_with_nothing_to_change_is_a_usage_error(hooks):
    result = invoke(["update", "whe_1"])

    assert result.exit_code == EXIT_USAGE
    assert hooks.calls == []


def test_update_rejects_a_bad_event(hooks):
    result = invoke(["update", "whe_1", "--event", "SANDBOX.*"])

    assert result.exit_code == EXIT_USAGE
    assert hooks.calls == []


# --- deliveries -----------------------------------------------------------------------------


def test_deliveries_maps_filters_and_paging_to_the_sdk(hooks):
    hooks.pages = {"c0": DeliveryPage((delivery(),), "c1")}

    args = ["deliveries", "whe_1", "--event-type", "sandbox.started", "--state", "failed"]
    result = invoke([*args, "--limit", "7", "--cursor", "c0"])

    assert result.exit_code == 0, result.output
    kwargs = {"event_type": "sandbox.started", "state": "failed", "cursor": "c0", "limit": 7}
    assert hooks.calls == [("deliveries", ("whe_1",), kwargs)]


def test_deliveries_text_table_and_next_cursor(hooks):
    hooks.pages = {None: DeliveryPage((delivery(),), "c1")}

    result = invoke(["deliveries", "whe_1"])

    assert result.exit_code == 0, result.output
    for header in ("CREATED", "EVENT TYPE", "STATE", "ATTEMPTS", "LAST STATUS", "NEXT ATTEMPT"):
        assert header in result.stdout
    assert "2026-11-10 08:30:00" in result.stdout
    assert "next cursor: c1" in result.stderr


def test_deliveries_json_one_page_has_the_deliveries_and_next_cursor_shape(hooks):
    hooks.pages = {None: DeliveryPage((delivery(),), "c1")}

    result = invoke(["deliveries", "whe_1"], as_json=True)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert set(payload) == {"deliveries", "next_cursor"}
    assert payload["next_cursor"] == "c1"
    assert payload["deliveries"][0]["id"] == "whd_1"
    assert payload["deliveries"][0]["attempt_history"][0]["status"] == 503


def test_deliveries_all_pages_through_and_prints_a_plain_list(hooks):
    hooks.pages = {
        None: DeliveryPage((delivery("whd_1"),), "c1"),
        "c1": DeliveryPage((), "c2"),
        "c2": DeliveryPage((delivery("whd_2"),), None),
    }

    result = invoke(["deliveries", "whe_1", "--all", "--state", "failed"], as_json=True)

    assert result.exit_code == 0, result.output
    assert [item["id"] for item in json.loads(result.stdout)] == ["whd_1", "whd_2"]
    cursors = [call[2]["cursor"] for call in hooks.calls if call[0] == "deliveries"]
    assert cursors == [None, "c1", "c2"]
    assert hooks.calls[0][2] == {"event_type": None, "state": "failed", "limit": 50}


def test_deliveries_all_text_lists_every_page(hooks):
    hooks.pages = {
        None: DeliveryPage((delivery("whd_1"),), "c1"),
        "c1": DeliveryPage((delivery("whd_2"),), None),
    }

    result = invoke(["deliveries", "whe_1", "--all"])

    assert result.exit_code == 0, result.output
    assert "whd_1" in result.stdout and "whd_2" in result.stdout
    assert "next cursor" not in result.output


def test_deliveries_all_with_cursor_is_a_usage_error(hooks):
    result = invoke(["deliveries", "whe_1", "--all", "--cursor", "c1"])

    assert result.exit_code == EXIT_USAGE
    assert hooks.calls == []


@pytest.mark.parametrize(
    "extra", [["--state", "lost"], ["--limit", "0"], ["--limit", "101"], ["--event-type", " "]]
)
def test_deliveries_bad_options_are_usage_errors(hooks, extra):
    result = invoke(["deliveries", "whe_1", *extra])

    assert result.exit_code == EXIT_USAGE
    assert hooks.calls == []


def test_deliveries_show_prints_one_delivery_with_its_attempts(hooks):
    result = invoke(["deliveries", "whe_1", "--show", "whd_1"])

    assert result.exit_code == 0, result.output
    assert hooks.calls == [("get_delivery", ("whe_1", "whd_1"), {})]
    assert "attempts" in result.stdout
    assert "connect timeout" in result.stdout
    assert "41" in result.stdout


def test_deliveries_show_json_is_the_delivery_object(hooks):
    result = invoke(["deliveries", "whe_1", "--show", "whd_1"], as_json=True)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["id"] == "whd_1"
    assert [entry["error"] for entry in payload["attempt_history"]] == [
        "http 503",
        "connect timeout",
    ]


@pytest.mark.parametrize("extra", [["--all"], ["--cursor", "c1"], ["--state", "failed"]])
def test_deliveries_show_does_not_combine_with_list_options(hooks, extra):
    result = invoke(["deliveries", "whe_1", "--show", "whd_1", *extra])

    assert result.exit_code == EXIT_USAGE
    assert hooks.calls == []


def test_deliveries_show_blank_delivery_id_is_a_usage_error(hooks):
    result = invoke(["deliveries", "whe_1", "--show", " "])

    assert result.exit_code == EXIT_USAGE
    assert hooks.calls == []


# --- redeliver ------------------------------------------------------------------------------


def test_redeliver_prints_the_refreshed_delivery(hooks):
    hooks.delivery = delivery(state="pending", next_attempt_at=WHEN)

    result = invoke(["redeliver", "whe_1", "whd_1"], as_json=True)

    assert result.exit_code == 0, result.output
    assert hooks.calls == [("redeliver", ("whe_1", "whd_1"), {})]
    assert json.loads(result.stdout)["state"] == "pending"


def test_redeliver_text_shows_the_delivery_view(hooks):
    result = invoke(["redeliver", "whe_1", "whd_1"])

    assert result.exit_code == 0, result.output
    assert "whd_1" in result.stdout
    assert "attempts" in result.stdout


def test_redeliver_refusal_shows_the_server_message_and_the_conflict_exit(hooks):
    message = "delivery whd_1 is delivered; only failed or disabled can be redelivered"
    hooks.error = error_for("CONFLICT", message, status_code=409)

    result = invoke(["redeliver", "whe_1", "whd_1"])

    assert result.exit_code == EXIT_FAILURE
    assert message in result.stderr


def test_redeliver_refusal_in_json_is_one_error_object(hooks):
    hooks.error = error_for("CONFLICT", "not failed", status_code=409)

    result = invoke(["redeliver", "whe_1", "whd_1"], as_json=True)

    assert result.exit_code == EXIT_FAILURE
    assert json.loads(result.stdout)["error"]["code"] == "CONFLICT"


@pytest.mark.parametrize("args", [[" ", "whd_1"], ["whe_1", ""]])
def test_redeliver_blank_ids_are_usage_errors(hooks, args):
    result = invoke(["redeliver", *args])

    assert result.exit_code == EXIT_USAGE
    assert hooks.calls == []


# --- sanitisation ---------------------------------------------------------------------------


def test_server_strings_are_sanitised_in_text_and_json(hooks):
    hooks.endpoint = endpoint(url=f"https://h.example/{ESC}[31mred", secret=SECRET)
    hooks.delivery = delivery(last_error=f"bad {PROFILE_KEY}")

    for as_json in (False, True):
        shown_endpoint = invoke(["get", "whe_1"], as_json=as_json)
        shown_delivery = invoke(["deliveries", "whe_1", "--show", "whd_1"], as_json=as_json)

        for result in (shown_endpoint, shown_delivery):
            assert result.exit_code == 0, result.output
            assert ESC not in result.output
            assert PROFILE_KEY not in result.output
            assert SECRET not in result.output
