"""``/v1/audit-events``: read-only, org-scoped, ``audit:read`` scope.

``GET ""`` lists events (cursor-paginated); ``GET /export`` streams the org's chained rows
as ndjson (the admin ``audit-export`` line format, hash fields included); ``GET /verify``
walks the org's whole hash chain, or the part from an anchor row on (``from_id``). All are
GETs, so none of them writes an audit row.

Audit events are org-wide (a label scope only limits sandboxes), so every route here refuses a
label-scoped key with 403.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import AfterValidator

from sandfort.api.deps import get_settings, get_uow
from sandfort.api.envelope import Envelope, ok
from sandfort.api.pagination import AUDIT_EVENTS, decode_cursor, encode_cursor
from sandfort.api.query_guard import KnownQuery, single_valued
from sandfort.api.schemas.audit import (
    MAX_FINDINGS,
    AuditVerifyResponse,
    finding_response,
    reanchor_response,
)
from sandfort.api.schemas.common import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, Meta
from sandfort.auth.label_scope import current_label_scope
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import require_scopes
from sandfort.config import Settings
from sandfort.db.repositories.ports import ChainedAuditEvent, SortOrder, UnitOfWorkPort
from sandfort.domain.events import AuditEvent, AuditOutcome
from sandfort.domain.org import Scope
from sandfort.errors import Forbidden, NotFound, Unprocessable
from sandfort.services.audit_chain import (
    ChainPolicy,
    ChainVerifier,
    export_line,
    find_latest_reanchor,
)
from sandfort.services.audit_chain_head import export_trailer
from sandfort.services.audit_export_digest import ExportDigest
from sandfort.services.audit_head_signing import HeadSigner

router = APIRouter(prefix="/v1/audit-events", tags=["audit"])

AUDIT_LABEL_SCOPED_MESSAGE = "audit events are org-wide; use an API key without sandbox labels"


async def _org_wide_reader(
    principal: Annotated[Principal, Depends(require_scopes(Scope.AUDIT_READ))],
) -> Principal:
    """The principal, once it holds ``audit:read`` and carries no sandbox label scope."""
    if current_label_scope() is not None:
        raise Forbidden(AUDIT_LABEL_SCOPED_MESSAGE)
    return principal


AuditReader = Annotated[Principal, Depends(_org_wide_reader)]
Uow = Annotated[UnitOfWorkPort, Depends(get_uow)]
ServerSettings = Annotated[Settings, Depends(get_settings)]
ListOnce = Annotated[
    None,
    Depends(
        single_valued(
            "limit",
            "cursor",
            "order",
            "actor_id",
            "action",
            "target_id",
            "request_id",
            "outcome",
            "from",
            "to",
        )
    ),
]
ExportOnce = Annotated[None, Depends(single_valued("request_id", "outcome", "from", "to"))]
VerifyOnce = Annotated[None, Depends(single_valued("from_id"))]

CHAIN_PAGE_SIZE = 500
NDJSON = "application/x-ndjson"
EXPORT_200 = "One chained audit row per line, then one trailer line"
OUT_OF_RANGE_MESSAGE = "datetime is out of range once converted to UTC"


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _utc_bound(value: datetime | None) -> datetime | None:
    """A ``from``/``to`` filter as aware UTC (naive is taken as UTC).

    An aware value at the edge of the representable range can leave it during the conversion
    (``9999-12-31T23:00:00-23:00``); that is a validation error (422 naming the parameter),
    not an internal one (round 52).
    """
    if value is None:
        return None
    try:
        return _utc(value)
    except OverflowError as exc:
        raise ValueError(OUT_OF_RANGE_MESSAGE) from exc


From = Annotated[datetime | None, Query(alias="from"), AfterValidator(_utc_bound)]
To = Annotated[datetime | None, Query(alias="to"), AfterValidator(_utc_bound)]
# Required variants, shared with the usage report route (same bound, same 422).
RequiredFrom = Annotated[datetime, Query(alias="from"), AfterValidator(_utc_bound)]
RequiredTo = Annotated[datetime, Query(alias="to"), AfterValidator(_utc_bound)]
PERIOD_ORDER_MESSAGE = "`to` must be after `from`"


def _check_period(since: datetime | None, until: datetime | None) -> None:
    """422 UNPROCESSABLE when both bounds are given and ``to`` is not after ``from``.

    One contract for the list and the export (round 54): an empty period is a caller error,
    not an empty result. Both bounds arrive as aware UTC (``_utc_bound``).
    """
    if since is not None and until is not None and until <= since:
        raise Unprocessable(PERIOD_ORDER_MESSAGE)


@router.get("")
async def list_audit_events(
    principal: AuditReader,
    uow: Uow,
    _known: KnownQuery,
    _once: ListOnce,
    actor_id: str | None = None,
    action: str | None = None,
    target_id: str | None = None,
    request_id: str | None = None,
    outcome: AuditOutcome | None = None,
    since: From = None,
    until: To = None,
    order: Annotated[
        SortOrder,
        Query(
            description=(
                "Sort by id, which follows creation time: `asc` (default) lists the oldest "
                "first, `desc` the newest first. `next_cursor` continues in the chosen order, "
                "so page through with the same `order` on every request."
            )
        ),
    ] = "asc",
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
) -> Envelope[list[AuditEvent]]:
    """List the org's audit events, cursor-paginated.

    Filters (all optional, exact match, combined with AND): `actor_id`, `action`,
    `target_id`, `request_id` (the `X-Request-ID` of the request that wrote the row),
    `outcome` (`success`, `denied` or `error`), `from` (inclusive) and `to` (exclusive)
    bounding `occurred_at`. Paging uses `order`, `cursor` and `limit`. Any other query
    parameter is rejected with 422 naming it. When both `from` and `to` are given, `to` must
    be after `from`, else 422 UNPROCESSABLE (as in the export).

    A cursor is bound to this list and to the filters and `order` that issued it: a cursor from
    another list, or one presented with other filters, answers 422 (`ctx.fields` names each
    differing field). An older unbound audit-events cursor is still accepted.

    A label-scoped API key gets 403 Forbidden: audit events are org-wide, not scoped to
    sandboxes.
    """
    _check_period(since, until)
    bound = {
        "actor_id": actor_id,
        "action": action,
        "target_id": target_id,
        "request_id": request_id,
        "outcome": outcome,
        "from": since,
        "to": until,
        "order": order,
    }
    after = None if cursor is None else decode_cursor(cursor, bound, resource=AUDIT_EVENTS)
    async with uow:
        # Fetch one extra row to learn whether another page exists.
        rows = await uow.audit.list(
            principal.org_id,
            actor_id=actor_id,
            action=action,
            target_id=target_id,
            request_id=request_id,
            outcome=outcome,
            since=since,
            until=until,
            cursor=after,
            limit=limit + 1,
            order=order,
        )
    page = list(rows[:limit])
    last = page[-1].id if len(rows) > limit else None
    next_cursor = None if last is None else encode_cursor(last, bound, resource=AUDIT_EVENTS)
    return ok(page, meta=Meta(next_cursor=next_cursor))


async def _chain_rows(
    uow: UnitOfWorkPort,
    org_id: str,
    after: str | None = None,
    *,
    request_id: str | None = None,
    outcome: AuditOutcome | None = None,
) -> AsyncIterator[ChainedAuditEvent]:
    """One org's chained rows in id order (those after ``after`` if given), a page at a time
    (as ``audit-export`` reads them); optionally only those matching ``request_id``/``outcome``."""
    cursor = after
    while True:
        page = await uow.audit.list_chained(
            org_id, cursor=cursor, limit=CHAIN_PAGE_SIZE, request_id=request_id, outcome=outcome
        )
        for row in page:
            yield row
        if len(page) < CHAIN_PAGE_SIZE:
            return
        cursor = page[-1].event.id


def _in_period(row: ChainedAuditEvent, since: datetime | None, until: datetime | None) -> bool:
    occurred = row.event.occurred_at
    if since is not None and occurred < since:
        return False
    return until is None or occurred < until


async def _export_lines(
    uow: UnitOfWorkPort,
    org_id: str,
    key: bytes | None,
    since: datetime | None,
    until: datetime | None,
    request_id: str | None,
    outcome: AuditOutcome | None,
    signer: HeadSigner | None = None,
) -> AsyncIterator[str]:
    """The exported rows, then one trailer line, all read in the same unit of work.

    The trailer is a head signed over the last row this walk yielded (so it never names a row
    the export did not include) and over the digest of the lines yielded; with a ``request_id``
    or ``outcome`` filter it is marked ``filtered``. An empty export, or a server without a
    chain key, gets the unsigned summary. ``signer`` is ``Settings.audit_signer()``.
    """
    exported = 0
    digest = ExportDigest()
    last: ChainedAuditEvent | None = None
    async with uow:
        async for row in _chain_rows(uow, org_id, request_id=request_id, outcome=outcome):
            if not _in_period(row, since, until):
                continue
            exported += 1
            last = row
            line = export_line(row) + "\n"
            digest.add(row.event.id, line)
            yield line
        given = {"from": since, "to": until, "request_id": request_id, "outcome": outcome}
        filters = [name for name, value in given.items() if value is not None]
        narrowed = request_id is not None or outcome is not None
        values = {name: _filter_text(value) for name, value in given.items() if value is not None}
        trailer = export_trailer(
            key, org_id, last, exported, filters, signer, digest.binding(),
            values if narrowed else None,
        )  # fmt: skip
        yield trailer + "\n"


def _filter_text(value: datetime | str | AuditOutcome) -> str:
    """A filter value as the text the filtered head records."""
    if isinstance(value, datetime):
        return value.isoformat()
    return value.value if isinstance(value, AuditOutcome) else value


@router.get(
    "/export",
    response_class=StreamingResponse,
    responses={200: {"content": {NDJSON: {}}, "description": EXPORT_200}},
)
async def export_audit_events(
    principal: AuditReader,
    uow: Uow,
    settings: ServerSettings,
    _known: KnownQuery,
    _once: ExportOnce,
    since: From = None,
    until: To = None,
    request_id: str | None = None,
    outcome: AuditOutcome | None = None,
) -> StreamingResponse:
    """Export the org's audit events as NDJSON, one chained row per line.

    Each line carries the event plus its ``prev_hash`` and ``hash``, in chain order.
    The optional ``from`` (inclusive) and ``to`` (exclusive) bound ``occurred_at``; the
    optional ``request_id`` and ``outcome`` keep only rows that match exactly, as in the list
    route. Any other query parameter is rejected with 422 naming it.

    The last line is always a trailer, told apart from rows by its `type` field:

    - `audit_head` (the line the operator `audit-export` writes: `org_id`, `row_id`, `hash`,
      `hmac`) when the server has an audit chain key and the export holds at least one row. It
      names the LAST ROW OF THIS EXPORT (`row_id`, `hash`), which is the org's newest chain row
      unless a `to` bound cut the export earlier. `hmac` is HMAC-SHA256 with the chain key over
      the row id and its hash (and the content fields below), so a holder of the key can detect
      a truncated export and anchor `audit-verify --head` on it. The head also binds the
      content of this export: `row_count` (the number of event lines above it), `first_row_id`
      (the id of the first one) and `export_sha256` (hex SHA-256 over the exact UTF-8 bytes of
      every event line, each with its trailing newline, in order; not the trailer). They are
      covered by the HMAC and by the signature, so an auditor can recompute them from the file
      and detect any added, removed, reordered or edited line. With a `request_id` or `outcome`
      filter the export is not a contiguous run of the chain, so the head carries `filtered:
      true` and `filters` (the filter values given, as text): a reader checks the content
      binding but not the neighbour linkage of the rows.
      When the server also has an audit signing key (an Ed25519 key), the head carries `alg`
      (`ed25519`), `public_key` and `signature` (urlsafe base64) and `signed_at` (when the
      server signed it, UTC ISO 8601 to the second, e.g. `2026-11-11T04:52:33+00:00`): a
      signature over the canonical JSON (keys sorted, compact) of the head without `signature`
      and `hmac`, so `signed_at` and the content fields are covered. An auditor checks it with
      the public key alone (`audit_public_key` of `GET /v1/status`, the same key that signs),
      which proves the export has the content the server signed at `signed_at`; of two signed
      heads, the later `signed_at` is the newer one. The keyed row hashes themselves can only be
      recomputed with the chain key.
    - `export_summary` (`rows`, the number of rows in this export, and `filters`, the sorted
      names of the filters given) otherwise: an empty export, or a server without a chain key.
      It names no row and is not signed.

    Rows and trailer are read in one unit of work, so the head never names a row the export
    did not include.

    A label-scoped API key gets 403 Forbidden: audit events are org-wide, not scoped to
    sandboxes.
    """
    _check_period(since, until)
    key = ChainPolicy.from_env().key
    signer = settings.audit_signer()
    lines = _export_lines(uow, principal.org_id, key, since, until, request_id, outcome, signer)
    return StreamingResponse(lines, media_type=NDJSON, headers={"Cache-Control": "no-store"})


async def _verified_rows(
    uow: UnitOfWorkPort, org_id: str, from_id: str | None
) -> AsyncIterator[ChainedAuditEvent]:
    """The rows a verify walks: the whole chain, or the anchor row and every row after it."""
    if from_id is None:
        async for row in _chain_rows(uow, org_id):
            yield row
        return
    anchor = await uow.audit.get_chained(org_id, from_id)
    if anchor is None:
        raise NotFound(f"audit event {from_id} not found")
    yield anchor
    async for row in _chain_rows(uow, org_id, after=anchor.event.id):
        yield row


async def _bounded_verifier(uow: UnitOfWorkPort, org_id: str, from_id: str | None) -> ChainVerifier:
    """A verifier seeded with the org's latest re-anchor (for an anchored walk, the latest
    one at or after the anchor row)."""
    reanchor = await find_latest_reanchor(uow, org_id, not_before=from_id)
    return ChainVerifier(max_findings=MAX_FINDINGS, reanchor=reanchor)


@router.get("/verify", response_model=Envelope[AuditVerifyResponse])
async def verify_audit_chain(
    principal: AuditReader,
    uow: Uow,
    _known: KnownQuery,
    _once: VerifyOnce,
    from_id: Annotated[
        str | None,
        Query(min_length=1, description="Audit event id of the caller's org to start the walk at"),
    ] = None,
) -> Envelope[AuditVerifyResponse]:
    """Verify the caller org's audit hash chain.

    Takes only ``from_id``; any other query parameter is rejected with 422 naming it.

    Walks the whole chain, page by page, as ``audit-verify`` does for one org, and
    reports the rows checked, the first and last ids and any findings.

    With ``from_id`` the walk starts at that row: its own hash is still recomputed and
    checked, but its link to the row before it is taken as the trust anchor, and every
    later row is checked as in a full walk. Such a verify proves the chain from that row
    on, not the history before it; the response names the row in ``anchor_id``. An id
    that is unknown or belongs to another org answers 404.

    A label-scoped API key gets 403 Forbidden: audit events are org-wide, not scoped to
    sandboxes.

    Re-anchor: an operator can run `audit-reanchor` to acknowledge historical breaks. It
    appends an `audit.chain_reanchored` event naming the last row with a finding
    (`acknowledged_through`). Findings on rows at or before that row are counted in
    `acknowledged_findings`, named by `reanchored_by`, and no longer make `ok` false.
    `reanchor` carries that event's operator, reason code, note, finding count and time
    (left out when there is none), so the verify alone tells who acknowledged what and why.
    It acknowledges, it never hides: no row is changed or removed, the full history stays
    in the export, and a break after that row, in the re-anchor event itself or after it
    still makes `ok` false. `findings` lists only unacknowledged findings.
    """
    # The incremental form of ``verify_chain``: state spans pages. The first row it sees
    # seeds the link (its prev_hash is not checked), so feeding the anchor first anchors it.
    # The latest re-anchor is looked up first, so the verifier stores at most MAX_FINDINGS.
    checked = 0
    first: ChainedAuditEvent | None = None
    last: ChainedAuditEvent | None = None
    async with uow:
        verifier = await _bounded_verifier(uow, principal.org_id, from_id)
        async for row in _verified_rows(uow, principal.org_id, from_id):
            first = first or row
            last = row
            checked += 1
            verifier.check(row)
    verdict = verifier.verdict()
    findings = verdict.findings
    result = AuditVerifyResponse(
        ok=verdict.ok,
        checked=checked,
        first_id=None if first is None else first.event.id,
        last_id=None if last is None else last.event.id,
        last_hash=None if last is None else last.entry_hash,
        findings=[finding_response(finding) for finding in findings],
        findings_truncated=verdict.findings_total > len(findings),
        acknowledged_findings=verdict.acknowledged,
        reanchored_by=verdict.reanchored_by,
        reanchor=reanchor_response(verdict.reanchor),
        anchor_id=from_id,
    )
    return ok(result)
