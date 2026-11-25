"""SDK round 82: org binding for the verification of a signed ``audit_head``.

``HeadVerification`` and ``ExportVerification`` expose the head's ``org_id``, and
``verify_head`` / ``verify_export`` take ``expected_org_id``: a genuinely signed head of another
org fails with ``"expected_org_mismatch"`` (not to be confused with the row-level
``"org_mismatch"``, where a row's org differs from the head's).
"""

import base64
import hashlib
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SDK_SRC = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
sys.path.insert(0, str(SDK_SRC))

import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from sandfort_sdk import verify_export  # noqa: E402
from sandfort_sdk.audit_head import REASON_EXPECTED_ORG_MISMATCH, verify_head  # noqa: E402

SIGNED_AT = "2026-11-11T04:00:00+00:00"
SEED_PREV = "00" * 32
Signer = Ed25519PrivateKey


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode()


def public_text(private: Signer) -> str:
    return b64(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def compact(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def row_hash(n: int) -> str:
    return hashlib.sha256(f"row-{n}".encode()).hexdigest()


def row(n: int, org: str = "org_1") -> dict[str, Any]:
    return {
        "id": f"aud_{n:03d}",
        "org_id": org,
        "actor_type": "api_key",
        "actor_id": "key_1",
        "action": "sandbox.create",
        "outcome": "success",
        "occurred_at": "2026-11-11T03:00:00+00:00",
        "details": {"n": n},
        "prev_hash": SEED_PREV if n == 1 else row_hash(n - 1),
        "hash": row_hash(n),
    }


def row_lines(rows: Iterable[dict[str, Any]]) -> list[str]:
    return [compact(record) + "\n" for record in rows]


def signed_head(
    private: Signer, rows: list[dict[str, Any]], *, org: Any = "org_1", drop_org: bool = False
) -> dict[str, Any]:
    """A signed, content-binding head for ``rows``; ``org`` is the head's ``org_id``."""
    text = row_lines(rows)
    record: dict[str, Any] = {
        "type": "audit_head",
        "row_id": rows[-1]["id"],
        "hash": rows[-1]["hash"],
        "alg": "ed25519",
        "public_key": public_text(private),
        "signed_at": SIGNED_AT,
        "row_count": len(text),
        "first_row_id": rows[0]["id"],
        "export_sha256": hashlib.sha256("".join(text).encode("utf-8")).hexdigest(),
    }
    if not drop_org:
        record["org_id"] = org
    record["signature"] = b64(private.sign(compact(record).encode()))
    record["hmac"] = "cd" * 32
    return record


def export(private: Signer, org: str = "org_1", **head_kwargs: Any) -> list[str]:
    rows = [row(n, org) for n in (1, 2, 3)]
    return [*row_lines(rows), compact(signed_head(private, rows, org=org, **head_kwargs)) + "\n"]


@pytest.fixture
def signer() -> Signer:
    return Ed25519PrivateKey.generate()


# --- the head ----------------------------------------------------------------------------------


def test_verify_head_exposes_the_org_id_of_an_ok_head(signer: Signer) -> None:
    head = signed_head(signer, [row(1)])

    result = verify_head(head, public_text(signer))

    assert result.ok is True
    assert result.org_id == "org_1"


def test_verify_head_accepts_the_expected_org(signer: Signer) -> None:
    head = signed_head(signer, [row(1)])

    result = verify_head(head, public_text(signer), expected_org_id="org_1")

    assert result.ok is True
    assert result.reason is None
    assert result.org_id == "org_1"


def test_verify_head_refuses_a_signed_head_of_another_org(signer: Signer) -> None:
    head = signed_head(signer, [row(1, "org_b")], org="org_b")

    result = verify_head(head, public_text(signer), expected_org_id="org_a")

    assert result.ok is False
    assert result.reason == REASON_EXPECTED_ORG_MISMATCH == "expected_org_mismatch"
    assert result.org_id == "org_b"


def test_a_head_without_org_id_fails_closed_when_an_org_is_expected(signer: Signer) -> None:
    head = signed_head(signer, [row(1)], drop_org=True)

    result = verify_head(head, public_text(signer), expected_org_id="org_1")

    assert result.ok is False
    assert result.reason == "expected_org_mismatch"
    assert result.org_id is None


@pytest.mark.parametrize("bad", ["", 7, None, ["org_1"]])
def test_a_non_text_or_empty_head_org_is_not_exposed_and_fails_closed(
    signer: Signer, bad: Any
) -> None:
    head = signed_head(signer, [row(1)], org=bad)

    plain = verify_head(head, public_text(signer))
    expected = verify_head(head, public_text(signer), expected_org_id="org_1")

    assert plain.ok is True
    assert plain.org_id is None
    assert expected.ok is False
    assert expected.reason == "expected_org_mismatch"


def test_a_head_without_org_id_still_verifies_when_no_org_is_expected(signer: Signer) -> None:
    head = signed_head(signer, [row(1)], drop_org=True)

    result = verify_head(head, public_text(signer))

    assert result.ok is True
    assert result.org_id is None


def test_an_empty_expected_org_id_raises_value_error(signer: Signer) -> None:
    head = signed_head(signer, [row(1)])

    with pytest.raises(ValueError, match="expected_org_id"):
        verify_head(head, public_text(signer), expected_org_id="")


def test_an_unsigned_head_keeps_its_reason_when_an_org_is_expected(signer: Signer) -> None:
    head = signed_head(signer, [row(1, "org_b")], org="org_b")
    head.pop("signature")

    result = verify_head(head, public_text(signer), expected_org_id="org_a")

    assert result.ok is False
    assert result.reason == "unsigned"
    assert result.org_id == "org_b"


def test_a_tampered_head_keeps_the_signature_reason_when_an_org_is_expected(
    signer: Signer,
) -> None:
    head = signed_head(signer, [row(1)])
    head["org_id"] = "org_b"

    result = verify_head(head, public_text(signer), expected_org_id="org_a")

    assert result.reason == "signature"


def test_the_org_check_comes_before_the_undated_check(signer: Signer) -> None:
    head = signed_head(signer, [row(1, "org_b")], org="org_b")
    head.pop("signature")
    head.pop("signed_at")
    undated = {**head}
    undated["signature"] = b64(
        signer.sign(
            compact({k: v for k, v in undated.items() if k not in ("signature", "hmac")}).encode()
        )
    )

    result = verify_head(undated, public_text(signer), expected_org_id="org_a")

    assert result.reason == "expected_org_mismatch"


# --- the export --------------------------------------------------------------------------------


def test_verify_export_exposes_the_org_id(signer: Signer) -> None:
    result = verify_export(export(signer), public_text(signer))

    assert result.ok is True
    assert result.org_id == "org_1"


def test_verify_export_accepts_the_expected_org(signer: Signer) -> None:
    result = verify_export(export(signer), public_text(signer), expected_org_id="org_1")

    assert result.ok is True
    assert result.org_id == "org_1"


def test_a_genuine_export_of_org_b_is_refused_as_org_a(signer: Signer) -> None:
    result = verify_export(export(signer, "org_b"), public_text(signer), expected_org_id="org_a")

    assert result.ok is False
    assert result.reason == "expected_org_mismatch"
    assert result.org_id == "org_b"
    assert result.bad_line is None


def test_the_row_level_org_mismatch_reason_is_unchanged(signer: Signer) -> None:
    rows = [row(1), row(2, "org_x"), row(3)]
    lines = [*row_lines(rows), compact(signed_head(signer, rows)) + "\n"]

    result = verify_export(lines, public_text(signer))

    assert result.ok is False
    assert result.reason == "org_mismatch"
    assert result.bad_line == 2
    assert result.org_id == "org_1"


def test_a_row_org_mismatch_is_reported_when_the_expected_org_matches_the_head(
    signer: Signer,
) -> None:
    rows = [row(1), row(2, "org_x"), row(3)]
    lines = [*row_lines(rows), compact(signed_head(signer, rows)) + "\n"]

    result = verify_export(lines, public_text(signer), expected_org_id="org_1")

    assert result.reason == "org_mismatch"


def test_an_export_without_a_trailer_has_no_org_id(signer: Signer) -> None:
    result = verify_export(row_lines([row(1)]), public_text(signer))

    assert result.reason == "no_trailer"
    assert result.org_id is None


def test_verify_export_rejects_an_empty_expected_org_id(signer: Signer) -> None:
    with pytest.raises(ValueError, match="expected_org_id"):
        verify_export(export(signer), public_text(signer), expected_org_id="")


def test_an_unsigned_export_head_keeps_its_reason_with_an_expected_org(signer: Signer) -> None:
    rows = [row(n, "org_b") for n in (1, 2, 3)]
    head = signed_head(signer, rows, org="org_b")
    head.pop("signature")
    lines = [*row_lines(rows), compact(head) + "\n"]

    result = verify_export(lines, public_text(signer), expected_org_id="org_a")

    assert result.reason == "unsigned"
