"""Round 61: the usage report in the SDK (``client.usage``) and the CLI (``sandfort usage``).

SDK side: query building, validation before any request, typed models, cursor paging and the
async twin. CLI side: options, date forms, tables, json, ``--all`` and sanitising. The SDK
transport is an ``httpx.MockTransport``; the CLI runs against ``respx``. No socket is opened.
"""

import json
import math
import shlex
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
import sandfort_sdk  # noqa: E402
import sandfort_sdk.usage as usage_module  # noqa: E402
from sandfort_cli import config, usage_cmd  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import AsyncClient, Client, InvalidResponseError  # noqa: E402
from sandfort_sdk._transport import AsyncTransport, SyncTransport, client_kwargs  # noqa: E402
from sandfort_sdk.usage import (  # noqa: E402
    AsyncUsage,
    Usage,
    UsageGroup,
    UsageReport,
    UsageTotal,
)
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key"
PROFILE_KEY = "sf_test_key_do_not_print"
TIMEOUT_S = 30.0
PATH = "/v1/org/usage"
T0 = datetime(2026, 11, 1, tzinfo=UTC)
T1 = datetime(2026, 11, 8, tzinfo=UTC)
ESC = "\x1b"
EXIT_USAGE = 2
RUNNER = CliRunner()
Handler = Callable[[httpx.Request], httpx.Response]


def envelope_body(data: Any, cursor: str | None = None, note: str | None = None) -> dict[str, Any]:
    meta = None if cursor is None else {"next_cursor": cursor}
    if note is not None:  # r65: the optional ``meta.note`` warning
        meta = {**(meta or {"next_cursor": None}), "note": note}
    return {"success": True, "data": data, "error": None, "meta": meta}


def reply(data: Any, cursor: str | None = None) -> httpx.Response:
    return httpx.Response(200, json=envelope_body(data, cursor))


def total(dimension: str, amount: float, unit: str = "unit-s") -> dict[str, Any]:
    return {"dimension": dimension, "unit": unit, "total": amount}


def totals_json() -> list[dict[str, Any]]:
    return [total("vcpu", 3600.0, "vcpu-s"), total("memory_mib", 1.5e6, "mib-s")]


def group_json(number: int, **extra: Any) -> dict[str, Any]:
    base = {
        "group_key": "sandbox",
        "group_value": f"sbx_{number}",
        "name": f"box-{number}",
        "labels": {"team": "core"},
        "totals": [total("vcpu", 100.0 * number, "vcpu-s"), total("disk_gib", 2.5, "gib-s")],
    }
    return {**base, **extra}


class Server:
    """Answers each request from a queue (the last answer repeats); records every request."""

    def __init__(self, *replies: httpx.Response) -> None:
        self.replies = list(replies)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]

    def params(self, index: int = -1) -> dict[str, str]:
        return dict(self.requests[index].url.params)


def sync_usage(handler: Handler) -> Usage:
    transport = SyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http.close()
    transport._http = httpx.Client(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return Usage(transport)


def async_usage(handler: Handler) -> AsyncUsage:
    transport = AsyncTransport(BASE, KEY, TIMEOUT_S, max_retries=0)
    transport._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), **client_kwargs(BASE, KEY, TIMEOUT_S)
    )
    return AsyncUsage(transport)


# --- SDK: get --------------------------------------------------------------------------------


def test_get_without_group_by_returns_typed_totals_and_sends_only_the_period() -> None:
    server = Server(reply(totals_json()))

    report = sync_usage(server).get(from_=T0, to=T1)

    assert server.params() == {"from": T0.isoformat(), "to": T1.isoformat()}
    assert server.requests[0].url.path == PATH
    assert report == UsageReport(
        totals=(UsageTotal("vcpu", "vcpu-s", 3600.0), UsageTotal("memory_mib", "mib-s", 1.5e6)),
        groups=(),
        next_cursor=None,
    )


def test_get_grouped_parses_groups_and_the_next_cursor() -> None:
    labelled = group_json(2, group_key="team", group_value=None, name=None, labels=None)
    server = Server(reply([group_json(1), labelled], cursor="cur_2"))

    report = sync_usage(server).get(from_=T0, to=T1, group_by="sandbox", limit=2)

    assert server.params() == {
        "from": T0.isoformat(), "to": T1.isoformat(), "group_by": "sandbox", "limit": "2",
    }  # fmt: skip
    assert report.totals == ()
    assert report.next_cursor == "cur_2"
    first, second = report.groups
    assert first == UsageGroup(
        group_key="sandbox",
        group_value="sbx_1",
        totals=(UsageTotal("vcpu", "vcpu-s", 100.0), UsageTotal("disk_gib", "gib-s", 2.5)),
        name="box-1",
        labels={"team": "core"},
    )
    assert (second.group_value, second.name, second.labels) == (None, None, None)


def test_get_sends_the_cursor_and_a_label_group_with_an_offset_date() -> None:
    server = Server(reply([]))
    start = datetime(2026, 11, 1, 2, 0, tzinfo=timezone(timedelta(hours=2)))

    report = sync_usage(server).get(from_=start, to=T1, group_by="label:team", cursor="c1")

    assert server.params()["from"] == "2026-11-01T02:00:00+02:00"
    assert server.params()["group_by"] == "label:team"
    assert server.params()["cursor"] == "c1"
    assert report == UsageReport(totals=(), groups=(), next_cursor=None)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"from_": datetime(2026, 11, 1)},
        {"to": datetime(2026, 11, 8)},
        {"group_by": ""},
        {"group_by": "volume"},
        {"group_by": "label"},
        {"group_by": "label:"},
        {"group_by": "label:  "},
        {"cursor": "c1"},
        {"limit": 5},
        {"group_by": "sandbox", "cursor": " "},
        {"group_by": "sandbox", "limit": 0},
        {"group_by": "sandbox", "limit": 101},
        {"group_by": "sandbox", "limit": True},
    ],
)
def test_get_rejects_bad_arguments_before_any_request(kwargs: dict[str, Any]) -> None:
    server = Server(reply([]))
    arguments: dict[str, Any] = {"from_": T0, "to": T1, **kwargs}

    with pytest.raises(ValueError):
        sync_usage(server).get(**arguments)

    assert server.requests == []


def test_get_refuses_a_reply_of_the_wrong_shape() -> None:
    with pytest.raises(InvalidResponseError):
        sync_usage(Server(reply({"vcpu": 1}))).get(from_=T0, to=T1)
    with pytest.raises(InvalidResponseError):
        sync_usage(Server(reply([{"dimension": "vcpu", "unit": "s", "total": "lots"}]))).get(
            from_=T0, to=T1
        )
    with pytest.raises(InvalidResponseError):
        sync_usage(Server(reply([{"dimension": "vcpu", "unit": "s"}]))).get(from_=T0, to=T1)
    with pytest.raises(InvalidResponseError):
        sync_usage(Server(reply([{"group_key": "sandbox"}]))).get(
            from_=T0, to=T1, group_by="sandbox"
        )


def test_get_refuses_a_boolean_total() -> None:
    body = reply([{"dimension": "vcpu", "unit": "s", "total": True}])

    with pytest.raises(InvalidResponseError):
        sync_usage(Server(body)).get(from_=T0, to=T1)


# --- SDK: iter -------------------------------------------------------------------------------


def test_iter_walks_every_page_with_the_cursor_of_the_one_before() -> None:
    server = Server(
        reply([group_json(1), group_json(2)], cursor="c2"),
        reply([group_json(3)], cursor="c3"),
        reply([group_json(4)]),
    )

    groups = list(sync_usage(server).iter(from_=T0, to=T1, group_by="sandbox", limit=2))

    assert [group.group_value for group in groups] == ["sbx_1", "sbx_2", "sbx_3", "sbx_4"]
    assert [request.url.params.get("cursor") for request in server.requests] == [None, "c2", "c3"]
    assert {request.url.params.get("limit") for request in server.requests} == {"2"}
    assert {request.url.params.get("group_by") for request in server.requests} == {"sandbox"}


def test_iter_needs_group_by_and_sends_nothing_without_it() -> None:
    server = Server(reply([]))

    with pytest.raises(ValueError, match="group_by"):
        list(sync_usage(server).iter(from_=T0, to=T1))

    assert server.requests == []


# --- SDK: async ------------------------------------------------------------------------------


async def test_async_get_and_iter_match_the_sync_facade() -> None:
    server = Server(
        reply([group_json(1)], cursor="c2"), reply([group_json(2)]), reply(totals_json())
    )
    usage = async_usage(server)

    groups = [group async for group in usage.iter(from_=T0, to=T1, group_by="sandbox")]
    plain = await usage.get(from_=T0, to=T1)

    assert [group.group_value for group in groups] == ["sbx_1", "sbx_2"]
    assert server.params(1)["cursor"] == "c2"
    assert [item.dimension for item in plain.totals] == ["vcpu", "memory_mib"]


async def test_async_validation_happens_before_any_request() -> None:
    server = Server(reply([]))
    usage = async_usage(server)

    with pytest.raises(ValueError):
        await usage.get(from_=datetime(2026, 11, 1), to=T1)
    with pytest.raises(ValueError, match="group_by"):
        _ = [group async for group in usage.iter(from_=T0, to=T1)]

    assert server.requests == []


def test_client_exposes_the_usage_facade() -> None:
    client = Client(BASE, KEY)
    try:
        assert isinstance(client.usage, Usage)
        assert client.usage is client.usage
    finally:
        client.close()


# --- CLI -------------------------------------------------------------------------------------


@pytest.fixture
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, PROFILE_KEY)


@pytest.fixture
def router(profile: None) -> Any:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(), (["--json"] if as_json else []) + ["usage", *args])


def query_of(route: Any, call: int = -1) -> dict[str, str]:
    return dict(route.calls[call].request.url.params)


def ok(data: Any, cursor: str | None = None, note: str | None = None) -> dict[str, Any]:
    return envelope_body(data, cursor, note)


def test_cli_totals_table_with_the_period_in_the_query(router: Any) -> None:
    route = router.get(PATH).respond(200, json=ok(totals_json()))

    result = invoke(["--from", "2026-11-01", "--to", "2026-11-08T12:00:00+02:00"])

    assert result.exit_code == 0, result.output
    assert query_of(route) == {
        "from": "2026-11-01T00:00:00+00:00", "to": "2026-11-08T12:00:00+02:00",
    }  # fmt: skip
    for text in ("DIMENSION", "UNIT", "TOTAL", "vcpu", "memory_mib", "3600", "1500000"):
        assert text in result.stdout


def test_cli_dates_default_to_the_utc_month_so_far(
    router: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(usage_cmd, "utc_now", lambda: datetime(2026, 11, 11, 9, 30, tzinfo=UTC))
    route = router.get(PATH).respond(200, json=ok([]))

    result = invoke([])

    assert result.exit_code == 0, result.output
    assert query_of(route) == {
        "from": "2026-11-01T00:00:00+00:00", "to": "2026-11-11T09:30:00+00:00",
    }  # fmt: skip


def test_cli_grouped_sandbox_table_and_the_summed_totals(router: Any) -> None:
    route = router.get(PATH).respond(
        200, json=ok([group_json(1), group_json(2, name=None, labels={})], cursor="c2")
    )

    result = invoke(["--from", "2026-11-01", "--to", "2026-11-08", "--group-by", "sandbox"])

    assert result.exit_code == 0, result.output
    assert query_of(route)["group_by"] == "sandbox"
    for text in ("SANDBOX", "NAME", "LABELS", "VCPU", "DISK_GIB", "sbx_1", "box-1", "team=core"):
        assert text in result.stdout
    assert "sbx_2" in result.stdout
    assert "300" in result.stdout  # 100 + 200 vcpu-s summed over the shown groups
    assert "next cursor: c2" in result.stderr


def test_cli_label_grouping_marks_the_unlabelled_group(router: Any) -> None:
    unlabelled = group_json(0, group_key="team", group_value=None, name=None, labels=None)
    team = group_json(1, group_key="team", group_value="core", name=None, labels=None)
    route = router.get(PATH).respond(200, json=ok([team, unlabelled]))

    result = invoke(["--from", "2026-11-01", "--to", "2026-11-08", "--group-by", "label:team"])

    assert result.exit_code == 0, result.output
    assert query_of(route)["group_by"] == "label:team"
    assert "LABEL" in result.stdout
    assert "core" in result.stdout
    assert "(unlabeled)" in result.stdout


def test_cli_strips_terminal_sequences_from_names_and_labels(router: Any) -> None:
    hostile = group_json(1, name=f"evil{ESC}[31mred", labels={f"k{ESC}[2J": f"v{ESC}]0;x\x07"})
    router.get(PATH).respond(200, json=ok([hostile]))

    text = invoke(["--from", "2026-11-01", "--to", "2026-11-08", "--group-by", "sandbox"])
    raw = invoke(
        ["--from", "2026-11-01", "--to", "2026-11-08", "--group-by", "sandbox"], as_json=True
    )

    assert text.exit_code == 0 and raw.exit_code == 0, text.output + raw.output
    assert ESC not in text.stdout and "\x07" not in text.stdout
    assert ESC not in raw.stdout and "\x07" not in raw.stdout
    assert "evil" in text.stdout


def test_cli_json_totals(router: Any) -> None:
    router.get(PATH).respond(200, json=ok(totals_json()))

    result = invoke(["--from", "2026-11-01", "--to", "2026-11-08"], as_json=True)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["group_by"] is None
    assert payload["from"] == "2026-11-01T00:00:00+00:00"
    assert payload["to"] == "2026-11-08T00:00:00+00:00"
    assert payload["totals"] == totals_json()
    assert payload["groups"] == []
    assert payload["next_cursor"] is None


def test_cli_json_grouped_page_carries_groups_totals_and_the_cursor(router: Any) -> None:
    router.get(PATH).respond(200, json=ok([group_json(1), group_json(2)], cursor="c2"))

    result = invoke(
        ["--from", "2026-11-01", "--to", "2026-11-08", "--group-by", "sandbox"], as_json=True
    )

    payload = json.loads(result.stdout)
    assert payload["group_by"] == "sandbox"
    assert payload["next_cursor"] == "c2"
    assert [group["group_value"] for group in payload["groups"]] == ["sbx_1", "sbx_2"]
    assert payload["groups"][0]["labels"] == {"team": "core"}
    by_dimension = {item["dimension"]: item["total"] for item in payload["totals"]}
    assert by_dimension == {"vcpu": 300.0, "disk_gib": 5.0}


def test_cli_all_follows_the_cursor_and_ends_without_one(router: Any) -> None:
    route = router.get(PATH).mock(
        side_effect=[
            httpx.Response(200, json=ok([group_json(1)], cursor="c2")),
            httpx.Response(200, json=ok([group_json(2)])),
        ]
    )

    result = invoke(
        ["--from", "2026-11-01", "--to", "2026-11-08", "--group-by", "sandbox", "--all"],
        as_json=True,
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert [group["group_value"] for group in payload["groups"]] == ["sbx_1", "sbx_2"]
    assert payload["next_cursor"] is None
    assert route.call_count == 2
    assert query_of(route, 1)["cursor"] == "c2"


def test_cli_cursor_and_limit_continue_a_page(router: Any) -> None:
    route = router.get(PATH).respond(200, json=ok([group_json(3)]))

    result = invoke(
        ["--from", "2026-11-01", "--to", "2026-11-08", "--group-by", "sandbox",
         "--cursor", "c2", "--limit", "5"]
    )  # fmt: skip

    assert result.exit_code == 0, result.output
    assert query_of(route)["cursor"] == "c2"
    assert query_of(route)["limit"] == "5"


@pytest.mark.parametrize(
    "args",
    [
        ["--group-by", "volume"],
        ["--group-by", "label"],
        ["--group-by", "label:"],
        ["--all"],
        ["--cursor", "c1"],
        ["--limit", "5"],
        ["--group-by", "sandbox", "--all", "--cursor", "c1"],
        ["--group-by", "sandbox", "--limit", "0"],
        ["--group-by", "sandbox", "--limit", "101"],
        ["--from", "yesterday"],
        ["--to", "2026-13-45"],
        ["--from", "2026-11-08", "--to", "2026-11-01"],
    ],
)
def test_cli_usage_errors_exit_2_without_a_request(router: Any, args: list[str]) -> None:
    route = router.get(PATH).respond(200, json=ok([]))

    result = invoke(args)

    assert result.exit_code == EXIT_USAGE, result.output
    assert route.call_count == 0


def test_cli_api_error_exits_nonzero_and_never_prints_the_key(router: Any) -> None:
    body = {"success": False, "data": None, "error": {"code": "FORBIDDEN", "message": "no"}}
    router.get(PATH).respond(403, json=body)

    result = invoke(["--from", "2026-11-01", "--to", "2026-11-08"])

    assert result.exit_code != 0
    assert PROFILE_KEY not in result.output


# --- review fixes ----------------------------------------------------------------------------

USAGE_EXPORTS = ("Usage", "AsyncUsage", "UsageReport", "UsageGroup", "UsageTotal")


async def test_async_client_exposes_the_usage_facade() -> None:
    client = AsyncClient(BASE, KEY)
    try:
        assert isinstance(client.usage, AsyncUsage)
        assert client.usage is client.usage
    finally:
        await client.aclose()


@pytest.mark.parametrize("name", USAGE_EXPORTS)
def test_package_exports_the_usage_types(name: str) -> None:
    assert name in sandfort_sdk.__all__
    assert getattr(sandfort_sdk, name) is getattr(usage_module, name)


def test_iter_raises_when_the_server_repeats_the_cursor() -> None:
    server = Server(reply([group_json(1)], cursor="c2"), reply([group_json(2)], cursor="c2"))

    with pytest.raises(InvalidResponseError, match="cursor"):
        list(sync_usage(server).iter(from_=T0, to=T1, group_by="sandbox"))

    assert len(server.requests) == 2


async def test_async_iter_raises_when_the_server_repeats_the_cursor() -> None:
    server = Server(reply([group_json(1)], cursor="c2"), reply([group_json(2)], cursor="c2"))
    usage = async_usage(server)

    with pytest.raises(InvalidResponseError, match="cursor"):
        _ = [group async for group in usage.iter(from_=T0, to=T1, group_by="sandbox")]

    assert len(server.requests) == 2


@pytest.mark.parametrize(
    "period",
    [[], ["--from", "2026-11-01"], ["--to", "2026-11-08"]],
)
def test_cli_cursor_needs_an_explicit_period(router: Any, period: list[str]) -> None:
    route = router.get(PATH).respond(200, json=ok([]))

    result = invoke([*period, "--group-by", "sandbox", "--cursor", "c1"])

    assert result.exit_code == EXIT_USAGE, result.output
    assert "--cursor" in result.output
    assert route.call_count == 0


def test_cli_prints_the_next_page_as_a_ready_to_paste_command(router: Any) -> None:
    router.get(PATH).respond(200, json=ok([group_json(1)], cursor="c2"))

    result = invoke(
        ["--from", "2026-11-01", "--to", "2026-11-08", "--group-by", "sandbox", "--limit", "1"]
    )

    assert result.exit_code == 0, result.output
    assert "next cursor: c2" in result.stderr
    assert (
        "sandfort usage --from 2026-11-01T00:00:00+00:00 --to 2026-11-08T00:00:00+00:00 "
        "--group-by sandbox --cursor c2 --limit 1"
    ) in result.stderr


def test_cli_next_page_command_pins_the_default_period_and_round_trips(
    router: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(usage_cmd, "utc_now", lambda: datetime(2026, 11, 11, 9, 30, tzinfo=UTC))
    route = router.get(PATH).mock(
        side_effect=[
            httpx.Response(200, json=ok([group_json(1)], cursor="c 2")),
            httpx.Response(200, json=ok([group_json(2)])),
        ]
    )

    first = invoke(["--group-by", "label:my team"])
    line = next(row for row in first.stderr.splitlines() if "sandfort usage" in row)
    words = shlex.split(line[line.index("sandfort usage") :])
    monkeypatch.setattr(usage_cmd, "utc_now", lambda: datetime(2026, 11, 12, tzinfo=UTC))
    second = invoke(words[2:])

    assert first.exit_code == 0 and second.exit_code == 0, first.output + second.output
    assert query_of(route, 1) == {
        "from": "2026-11-01T00:00:00+00:00", "to": "2026-11-11T09:30:00+00:00",
        "group_by": "label:my team", "cursor": "c 2",
    }  # fmt: skip


def test_cli_json_has_no_next_page_command(router: Any) -> None:
    router.get(PATH).respond(200, json=ok([group_json(1)], cursor="c2"))

    result = invoke(
        ["--from", "2026-11-01", "--to", "2026-11-08", "--group-by", "sandbox"], as_json=True
    )

    assert result.exit_code == 0, result.output
    assert "sandfort usage" not in result.stderr


@pytest.mark.parametrize(
    ("value", "text"),
    [(-0.001, "0"), (-0.004, "0"), (0.004, "0"), (0.0, "0"), (-1.5, "-1.5"), (2.5, "2.5")],
)
def test_amount_never_prints_negative_zero(value: float, text: str) -> None:
    assert usage_cmd.amount(value) == text


def test_sum_totals_is_exact_and_rounded_to_the_shown_precision() -> None:
    def group(*amounts: float) -> UsageGroup:
        return UsageGroup("sandbox", "sbx", tuple(UsageTotal("vcpu", "s", a) for a in amounts))

    tenths = usage_cmd.sum_totals([group(0.1), group(0.2)])
    cancelled = usage_cmd.sum_totals([group(1e16), group(1.0), group(-1e16)])
    tiny = usage_cmd.sum_totals([group(-0.001)])

    assert tenths == [UsageTotal("vcpu", "s", 0.3)]
    assert cancelled == [UsageTotal("vcpu", "s", 1.0)]
    assert tiny[0].total == 0.0 and math.copysign(1.0, tiny[0].total) == 1.0


def test_cli_json_summed_totals_carry_no_float_noise(router: Any) -> None:
    groups = [
        group_json(n, totals=[total("vcpu", amount, "vcpu-s")])
        for n, amount in enumerate((0.1, 0.2), start=1)
    ]
    router.get(PATH).respond(200, json=ok(groups))

    result = invoke(
        ["--from", "2026-11-01", "--to", "2026-11-08", "--group-by", "sandbox"], as_json=True
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["totals"] == [total("vcpu", 0.3, "vcpu-s")]
    assert "0.30000000000000004" not in result.stdout


def test_epilog_says_both_json_shapes_match() -> None:
    assert '"groups": []' in usage_cmd.USAGE_EPILOG
    assert '"next_cursor": null' in usage_cmd.USAGE_EPILOG


# --- r65: meta.note (a label key no sandbox carried) ---------------------------------------------

NOTE = "label key 'nope' was not found on any sandbox in this window; check the key"


def nope_group() -> dict[str, Any]:
    return group_json(0, group_key="nope", group_value=None, name=None, labels=None)


def test_sdk_report_carries_the_meta_note() -> None:
    server = Server(httpx.Response(200, json=envelope_body([nope_group()], note=NOTE)))

    report = sync_usage(server).get(from_=T0, to=T1, group_by="label:nope")

    assert report.note == NOTE
    assert sync_usage(Server(reply(totals_json()))).get(from_=T0, to=T1).note is None


def test_cli_prints_the_note_on_stderr_in_text_mode(router: Any) -> None:
    router.get(PATH).respond(200, json=ok([nope_group()], note=NOTE))

    result = invoke(["--from", "2026-11-01", "--to", "2026-11-08", "--group-by", "label:nope"])

    assert result.exit_code == 0, result.output
    assert NOTE in result.stderr
    assert NOTE not in result.stdout


def test_cli_json_adds_the_note_key_only_when_there_is_one(router: Any) -> None:
    route = router.get(PATH)
    route.respond(200, json=ok([nope_group()], note=NOTE))
    flagged = json.loads(
        invoke(
            ["--from", "2026-11-01", "--to", "2026-11-08", "--group-by", "label:nope"], as_json=True
        ).stdout
    )
    route.respond(200, json=ok([nope_group()]))
    plain = json.loads(
        invoke(
            ["--from", "2026-11-01", "--to", "2026-11-08", "--group-by", "label:nope"], as_json=True
        ).stdout
    )

    assert flagged["note"] == NOTE
    assert "note" not in plain  # backward compatible: the old keys, nothing else
    assert {key: value for key, value in flagged.items() if key != "note"} == plain
