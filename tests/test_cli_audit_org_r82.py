"""CLI r82: `audit verify-head --expect-org` binds the verification to an org.

The json document gains ``org_id`` (the head's), and a genuinely signed head of another org fails
with reason ``expected_org_mismatch`` (exit 3). Fixtures follow ``test_cli_audit_r61.py``.
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
PROFILE_KEY = "sf_test_key_do_not_print"
RUNNER = CliRunner()
EXIT_USAGE = 2
EXIT_FAILED = 3
SIGNED_AT = "2026-11-11T04:00:00+00:00"
SEED_PREV = "00" * 32


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(), (["--json"] if as_json else []) + args)


@pytest.fixture(autouse=True)
def profile(monkeypatch, tmp_path):
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, PROFILE_KEY)


@pytest.fixture
def router():
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


@pytest.fixture
def signer():
    return Ed25519PrivateKey.generate()


def public_text(private_key):
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.urlsafe_b64encode(raw).decode()


def compact(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def row_id(n):
    return f"aud_{n:03d}"


def row_hash(n):
    return hashlib.sha256(f"row-{n}".encode()).hexdigest()


def row(n, org="org_1"):
    return {
        "id": row_id(n),
        "org_id": org,
        "actor_type": "api_key",
        "action": "sandbox.create",
        "occurred_at": "2026-11-11T03:00:00+00:00",
        "details": {},
        "prev_hash": SEED_PREV if n == 1 else row_hash(n - 1),
        "hash": row_hash(n),
    }


def head(private_key, n, org="org_1", drop_org=False):
    record = {
        "type": "audit_head",
        "row_id": row_id(n),
        "hash": row_hash(n),
        "alg": "ed25519",
        "public_key": public_text(private_key),
        "signed_at": SIGNED_AT,
    }
    if not drop_org:
        record["org_id"] = org
    signature = private_key.sign(compact(record).encode())
    record["signature"] = base64.urlsafe_b64encode(signature).decode()
    record["hmac"] = "f" * 64
    return record


@pytest.fixture
def export_file(tmp_path):
    def write(rows, trailer):
        path = tmp_path / "audit.ndjson"
        path.write_text("".join(compact(record) + "\n" for record in [*rows, trailer]))
        return path

    return write


def verify(path, private_key, *extra, as_json=True):
    args = ["audit", "verify-head", str(path), "--public-key", public_text(private_key), *extra]
    return invoke(args, as_json=as_json)


def org_export(export_file, signer, org="org_1"):
    return export_file([row(n, org) for n in (1, 2, 3)], head(signer, 3, org))


# --- org_id in the output ----------------------------------------------------------------------


def test_the_json_document_carries_the_head_org_id(router, signer, export_file):
    result = verify(org_export(export_file, signer), signer)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["org_id"] == "org_1"


def test_the_text_output_shows_the_head_org_id(router, signer, export_file):
    result = verify(org_export(export_file, signer), signer, as_json=False)

    assert result.exit_code == 0, result.output
    assert "org_id" in result.stdout
    assert "org_1" in result.stdout


def test_head_only_json_carries_the_head_org_id(router, signer, export_file):
    result = verify(org_export(export_file, signer), signer, "--head-only")

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["org_id"] == "org_1"


# --- --expect-org ------------------------------------------------------------------------------


def test_expect_org_matching_passes(router, signer, export_file):
    result = verify(org_export(export_file, signer), signer, "--expect-org", "org_1")

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["ok"] is True
    assert document["org_id"] == "org_1"


def test_expect_org_mismatch_exits_3_with_the_reason(router, signer, export_file):
    path = org_export(export_file, signer, "org_b")

    result = verify(path, signer, "--expect-org", "org_a")

    assert result.exit_code == EXIT_FAILED, result.output
    document = json.loads(result.stdout)
    assert document["ok"] is False
    assert document["reason"] == "expected_org_mismatch"
    assert document["org_id"] == "org_b"
    assert "bad_line" not in document


def test_expect_org_mismatch_text_error_explains_the_reason(router, signer, export_file):
    path = org_export(export_file, signer, "org_b")

    result = verify(path, signer, "--expect-org", "org_a", as_json=False)

    assert result.exit_code == EXIT_FAILED
    assert "expected_org_mismatch" in result.stderr
    assert "--expect-org" in result.stderr
    assert "head not verified" in result.stderr


def test_expect_org_mismatch_with_head_only_exits_3(router, signer, export_file):
    path = org_export(export_file, signer, "org_b")

    result = verify(path, signer, "--head-only", "--expect-org", "org_a")

    assert result.exit_code == EXIT_FAILED, result.output
    assert json.loads(result.stdout)["reason"] == "expected_org_mismatch"


def test_expect_org_on_a_head_without_org_id_fails_closed(router, signer, export_file):
    path = export_file([row(n) for n in (1, 2, 3)], head(signer, 3, drop_org=True))

    result = verify(path, signer, "--expect-org", "org_1")

    assert result.exit_code == EXIT_FAILED, result.output
    document = json.loads(result.stdout)
    assert document["reason"] == "expected_org_mismatch"
    assert document["org_id"] is None


def test_an_empty_expect_org_is_a_usage_error(router, signer, export_file):
    result = verify(org_export(export_file, signer), signer, "--expect-org", "", as_json=False)

    assert result.exit_code == EXIT_USAGE, result.output
    assert "--expect-org" in result.stderr


def test_an_unsigned_head_keeps_its_reason_with_expect_org(router, signer, export_file):
    trailer = head(signer, 3, "org_b")
    trailer.pop("signature")
    path = export_file([row(n, "org_b") for n in (1, 2, 3)], trailer)

    result = verify(path, signer, "--expect-org", "org_a")

    assert result.exit_code == EXIT_FAILED, result.output
    assert json.loads(result.stdout)["reason"] == "unsigned"


def test_the_row_level_org_mismatch_reason_is_unchanged(router, signer, export_file):
    rows = [row(1), row(2, "org_x"), row(3)]
    path = export_file(rows, head(signer, 3))

    result = verify(path, signer)

    assert result.exit_code == EXIT_FAILED, result.output
    document = json.loads(result.stdout)
    assert document["reason"] == "org_mismatch"
    assert document["bad_line"] == 2
    assert document["org_id"] == "org_1"


def test_the_success_line_names_the_verified_org(router, signer, export_file):
    path = org_export(export_file, signer)

    result = verify(path, signer, "--expect-org", "org_1", as_json=False)

    assert result.exit_code == 0, result.output
    assert "org_1" in result.stderr
    assert result.stderr.count("\n") >= 1
