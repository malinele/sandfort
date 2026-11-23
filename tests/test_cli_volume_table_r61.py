"""Round 61: the volume table shows size_bytes and the limit exactly as ``--json`` does."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
VOL_ID = "vol_1"
CREATED = "2026-11-10T19:26:00Z"
VOLUMES_URL = "/v1/volumes"
VOLUME_URL = f"{VOLUMES_URL}/{VOL_ID}"
GIB = 1024**3
RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def volume_json(**extra):
    base = {
        "id": VOL_ID,
        "name": "data",
        "state": "ready",
        "created_at": CREATED,
        "labels": {},
        "size_bytes": 0,
        "max_bytes": GIB,
        "over_limit": False,
    }
    return {**base, **extra}


@pytest.fixture(autouse=True)
def profile(monkeypatch, tmp_path):
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    monkeypatch.delenv("COLUMNS", raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def router():
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(), (["--json"] if as_json else []) + args)


def body_rows(output):
    """The cells of every table row drawn with the light or heavy vertical bar."""
    rows = []
    for line in output.splitlines():
        bar = "│" if line.count("│") >= 2 else "┃"
        if line.count(bar) >= 2:
            rows.append([cell.strip() for cell in line.split(bar)[1:-1]])
    return rows


def field_value(output, name):
    matches = [row[1] for row in body_rows(output) if len(row) == 2 and row[0] == name]
    assert len(matches) == 1, output
    return matches[0]


def list_cell(output, column):
    header = next(row for row in body_rows(output) if "ID" in row and "NAME" in row)
    data = [row for row in body_rows(output) if row and row[0] == VOL_ID]
    assert len(data) == 1, output
    return data[0][header.index(column)]


def serve_single(router, payload):
    router.post(VOLUMES_URL).respond(201, json=envelope(payload))
    router.get(VOLUME_URL).respond(200, json=envelope(payload))


SINGLE_COMMANDS = [["volume", "create", "data"], ["volume", "get", VOL_ID]]


# --- create and get: text --------------------------------------------------------------------


@pytest.mark.parametrize("args", SINGLE_COMMANDS)
def test_single_view_shows_zero_size_as_zero_and_the_limit_in_human_size(router, args):
    serve_single(router, volume_json())

    result = invoke(args)

    assert result.exit_code == 0, result.output
    assert field_value(result.output, "size_bytes") == "0"
    assert field_value(result.output, "limit") == f"1.0 GiB ({GIB} bytes)"
    assert field_value(result.output, "over_limit") == "false"


@pytest.mark.parametrize("args", SINGLE_COMMANDS)
def test_single_view_shows_the_no_limit_text_only_when_max_bytes_is_null(router, args):
    serve_single(router, volume_json(max_bytes=None, size_bytes=4096))

    result = invoke(args)

    assert result.exit_code == 0, result.output
    assert field_value(result.output, "size_bytes") == "4096"
    assert field_value(result.output, "limit") == "none"


@pytest.mark.parametrize("args", SINGLE_COMMANDS)
def test_single_view_shows_a_zero_limit_as_zero_bytes_not_none(router, args):
    serve_single(router, volume_json(max_bytes=0))

    result = invoke(args)

    assert result.exit_code == 0, result.output
    assert field_value(result.output, "limit") == "0 B (0 bytes)"


@pytest.mark.parametrize(
    ("max_bytes", "text"),
    [
        (1, "1 B (1 byte)"),
        (512, "512 B (512 bytes)"),
        (1536, "1.5 KiB (1536 bytes)"),
        (10 * 1024**2, "10.0 MiB (10485760 bytes)"),
        (5 * 1024**4, f"5.0 TiB ({5 * 1024**4} bytes)"),
    ],
)
def test_limit_human_size_keeps_the_exact_byte_count(router, max_bytes, text):
    serve_single(router, volume_json(max_bytes=max_bytes))

    result = invoke(["volume", "get", VOL_ID])

    assert result.exit_code == 0, result.output
    assert field_value(result.output, "limit") == text


def test_single_view_over_limit_volume(router):
    serve_single(router, volume_json(size_bytes=2 * GIB, over_limit=True))

    result = invoke(["volume", "get", VOL_ID])

    assert result.exit_code == 0, result.output
    assert field_value(result.output, "size_bytes") == str(2 * GIB)
    assert field_value(result.output, "limit") == f"1.0 GiB ({GIB} bytes)"
    assert field_value(result.output, "over_limit") == "true"


def test_single_view_leaves_an_unsampled_size_blank(router):
    serve_single(router, volume_json(size_bytes=None))

    result = invoke(["volume", "get", VOL_ID])

    assert result.exit_code == 0, result.output
    assert field_value(result.output, "size_bytes") == ""


# --- create and get: json --------------------------------------------------------------------


@pytest.mark.parametrize("args", SINGLE_COMMANDS)
def test_single_view_json_keeps_size_and_limit_typed(router, args):
    serve_single(router, volume_json())

    result = invoke(args, as_json=True)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["size_bytes"] == 0
    assert payload["max_bytes"] == GIB
    assert payload["over_limit"] is False


@pytest.mark.parametrize("args", SINGLE_COMMANDS)
def test_single_view_json_null_limit(router, args):
    serve_single(router, volume_json(max_bytes=None))

    result = invoke(args, as_json=True)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["max_bytes"] is None
    assert payload["size_bytes"] == 0


# --- list ------------------------------------------------------------------------------------


def test_list_shows_size_and_limit_as_raw_bytes_in_matching_columns(router):
    router.get(VOLUMES_URL).respond(200, json=envelope([volume_json(size_bytes=4096)]))

    result = invoke(["volume", "list"])

    assert result.exit_code == 0, result.output
    assert list_cell(result.output, "SIZE (B)") == "4096"
    assert list_cell(result.output, "LIMIT (B)") == str(GIB)
    assert list_cell(result.output, "OVER") == ""
    assert "GiB" not in result.output
    assert "(1073741824 bytes)" not in result.output


def test_list_header_has_no_bare_limit_column(router):
    router.get(VOLUMES_URL).respond(200, json=envelope([volume_json()]))

    result = invoke(["volume", "list"])

    header = next(row for row in body_rows(result.output) if "ID" in row)
    assert "SIZE (B)" in header
    assert "LIMIT (B)" in header
    assert "LIMIT" not in header


def test_list_shows_zero_size_and_zero_limit_as_zero(router):
    router.get(VOLUMES_URL).respond(200, json=envelope([volume_json(max_bytes=0)]))

    result = invoke(["volume", "list"])

    assert result.exit_code == 0, result.output
    assert list_cell(result.output, "SIZE (B)") == "0"
    assert list_cell(result.output, "LIMIT (B)") == "0"


def test_list_shows_the_no_limit_text_for_a_null_limit(router):
    router.get(VOLUMES_URL).respond(200, json=envelope([volume_json(max_bytes=None)]))

    result = invoke(["volume", "list"])

    assert result.exit_code == 0, result.output
    assert list_cell(result.output, "SIZE (B)") == "0"
    assert list_cell(result.output, "LIMIT (B)") == "none"


def test_list_cells_equal_the_json_numbers(router):
    payload = volume_json(size_bytes=123456789, max_bytes=5 * GIB)
    router.get(VOLUMES_URL).respond(200, json=envelope([payload]))

    text = invoke(["volume", "list"])
    [as_json] = json.loads(invoke(["volume", "list"], as_json=True).output)

    assert list_cell(text.output, "SIZE (B)") == str(as_json["size_bytes"])
    assert list_cell(text.output, "LIMIT (B)") == str(as_json["max_bytes"])


def test_list_json_keeps_size_and_limit_typed(router):
    router.get(VOLUMES_URL).respond(200, json=envelope([volume_json()]))

    result = invoke(["volume", "list"], as_json=True)

    assert result.exit_code == 0, result.output
    [payload] = json.loads(result.output)
    assert payload["size_bytes"] == 0
    assert payload["max_bytes"] == GIB


def test_table_and_json_agree_for_create(router):
    serve_single(router, volume_json(size_bytes=0, max_bytes=3 * GIB))

    text = invoke(["volume", "create", "data"])
    as_json = json.loads(invoke(["volume", "create", "data"], as_json=True).output)

    assert field_value(text.output, "size_bytes") == str(as_json["size_bytes"])
    limit = field_value(text.output, "limit")
    assert limit == f"3.0 GiB ({as_json['max_bytes']} bytes)"


# --- human_size boundaries -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("count", "text"),
    [
        (0, "0 B"),
        (1, "1 B"),
        (1023, "1023 B"),
        (1024, "1.0 KiB"),
        (1536, "1.5 KiB"),
        (1048524, "1023.9 KiB"),
        (1048525, "1.0 MiB"),
        (1048575, "1.0 MiB"),
        (1048576, "1.0 MiB"),
        (1024**3 - 1, "1.0 GiB"),
        (1024**3, "1.0 GiB"),
        (1024**4 - 1, "1.0 TiB"),
        (1024**5 - 1, "1.0 PiB"),
        (1024**6 - 1, "1.0 EiB"),
        (1024**6, "1.0 EiB"),
        (2**60, "1.0 EiB"),
        (2**63, "8.0 EiB"),
        (2**64 - 1, "16.0 EiB"),
        (2**70, "1,024.0 EiB"),
        (10**30, "867,361,737,988.4 EiB"),
        (-5, "-5 B"),
        (-1536, "-1.5 KiB"),
    ],
)
def test_human_size_rounds_before_picking_the_unit(count, text):
    from sandfort_cli.volume import human_size

    assert human_size(count) == text


def test_human_size_never_shows_a_thousand_and_twenty_four_below_eib():
    from sandfort_cli.volume import human_size

    for unit in range(1, 6):
        text = human_size(1024 ** (unit + 1) - 1)
        assert not text.startswith("1024."), text


# --- snapshot layer_count ----------------------------------------------------------------------


def test_snapshot_layer_count_is_rendered_as_a_plain_scalar(router, monkeypatch):
    import sandfort_cli.snapshot as snapshot_module

    real = snapshot_module.shown
    seen = []

    def strict_shown(value, key):
        seen.append(value)
        assert isinstance(value, str), value
        return real(value, key)

    monkeypatch.setattr(snapshot_module, "shown", strict_shown)
    payload = {
        "id": "snap_1",
        "name": "base",
        "state": "ready",
        "image_ref": "img:1",
        "layer_count": 0,
        "created_at": CREATED,
    }
    router.get("/v1/snapshots/snap_1").respond(200, json=envelope(payload))

    result = invoke(["snapshot", "get", "snap_1"])

    assert result.exit_code == 0, result.output
    assert field_value(result.output, "layer_count") == "0"
    assert seen
