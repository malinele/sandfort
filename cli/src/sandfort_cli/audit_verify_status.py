"""Helpers of ``audit verify-head``: the public key from the server status (no login needed)
and the success line that states what was proven."""

import os
from datetime import UTC, datetime

import httpx
from sandfort_sdk.audit_export import ExportVerification
from sandfort_sdk.audit_head import HeadVerification, public_key_from_status

from sandfort_cli.config import BASE_URL_ENV, read_profile, stored_base_url, validate_base_url
from sandfort_cli.output import CliError, cli_errors
from sandfort_cli.sandboxes import strip_userinfo

EXIT_USAGE = 2
STATUS_PATH = "/v1/status"
STATUS_TIMEOUT_S = 15.0
NOT_PROVEN = (
    "not verified: the keyed row hashes (only the chain key proves them: sandfort audit "
    "verify) and that this is the newest export"
)
SECONDS_PER = (("d", 86400), ("h", 3600), ("m", 60))


def status_url() -> str:
    """The ``/v1/status`` url of the configured server; needs no api key (the route is public)."""
    base = os.environ.get(BASE_URL_ENV) or stored_base_url(read_profile())
    if not base:
        raise CliError(
            "no server url to read the public key from; pass --public-key, or run "
            f"'sandfort login' or set {BASE_URL_ENV}",
            client=True,
        )
    return validate_base_url(strip_userinfo(base)) + STATUS_PATH


def server_public_key() -> str:
    """``audit_public_key`` of the server status, fetched without credentials; a usage error
    when the server has none."""
    with cli_errors(EXIT_USAGE):
        url = status_url()
    with cli_errors():
        try:
            reply = httpx.get(url, timeout=STATUS_TIMEOUT_S, headers={"Accept": "application/json"})
            reply.raise_for_status()
            body = reply.json()
            key = public_key_from_status(body.get("data") if isinstance(body, dict) else None)
        except (httpx.HTTPError, ValueError) as exc:
            raise CliError(
                f"cannot read the public key from {STATUS_PATH}: {type(exc).__name__}"
            ) from None
    if key is None:
        with cli_errors(EXIT_USAGE):
            raise CliError(
                "the server publishes no audit_public_key; pass --public-key or ask the "
                "operator to set SANDFORT_AUDIT_SIGNING_KEY together with "
                "SANDFORT_AUDIT_CHAIN_KEY",
                client=True,
            )
    return key


def age_text(moment: datetime | None) -> str:
    """How long ago ``moment`` was, in the largest whole unit (``3h``); ``unknown`` without one."""
    if moment is None:
        return "unknown"
    seconds = max(0, int((datetime.now(UTC) - moment).total_seconds()))
    for unit, size in SECONDS_PER:
        if seconds >= size:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def proof_line(result: HeadVerification, expected_org: str | None = None) -> str:
    """One line on success: what the check proved (with the age of ``signed_at``) and what not.

    With ``expected_org`` the line also says that the signed head names that org.
    """
    signed = f"the Ed25519 signature (signed {age_text(result.signed_at)} ago)"
    if expected_org is not None:
        signed += f" and the signed head's org ({result.org_id})"
    if not isinstance(result, ExportVerification):
        return f"verified: {signed} only (--head-only); {NOT_PROVEN}"
    parts = [signed]
    if result.content_bound:
        parts.append("the SHA-256, count and first row of the exported lines")
    parts.append("each row's org and the last row")
    if not result.filtered:
        parts.append("the linkage between neighbouring rows")
    if result.new_rows is not None:
        parts.append(f"the earlier export as a prefix ({result.new_rows} new rows)")
    return f"verified: {', '.join(parts)}; {NOT_PROVEN}"
