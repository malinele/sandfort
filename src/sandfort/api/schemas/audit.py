"""Response schema of ``GET /v1/audit-events/verify``: the org's hash chain check result."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from sandfort.services.audit_chain import ChainFinding, FindingKind, Reanchor, ReanchorReason

MAX_FINDINGS = 100


class AuditFindingResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: FindingKind
    event_id: str
    detail: str


ANCHOR_DESCRIPTION = (
    "The `from_id` the walk started at. A verify from an anchor proves the chain from that row"
    " on (its own hash is checked, its link to the row before it is trusted), not the history"
    " before it. Absent for a full walk."
)


ACKNOWLEDGED_DESCRIPTION = (
    "Findings on rows at or before the `acknowledged_through` row of the latest"
    " `audit.chain_reanchored` event. They are still in the history and the export; they no"
    " longer make `ok` false and are not listed in `findings`."
)
REANCHORED_BY_DESCRIPTION = (
    "Id of the latest `audit.chain_reanchored` event seen in the walk, or null."
)


REANCHOR_DESCRIPTION = (
    "The `audit.chain_reanchored` event named by `reanchored_by`, read from its details: who"
    " ran it (`operator`), why (`reason_code`, `note`), the last row it acknowledges and how"
    " many findings it acknowledged. Left out while null (the walk has no re-anchor)."
)
REASON_CODES = ", ".join(f"`{reason.value}`" for reason in ReanchorReason)


class AuditReanchorResponse(BaseModel):
    """The effective re-anchor event of a verify; older events carry no operator or reason."""

    model_config = ConfigDict(frozen=True)

    event_id: str
    operator: str | None = Field(
        description="Operator name given to `audit-reanchor --operator`; null on older events."
    )
    reason_code: str | None = Field(
        description=f"One of {REASON_CODES}; null on older events."
    )
    acknowledged_through: str = Field(
        description="Last audit row id whose findings the event acknowledges."
    )
    findings: int | None = Field(
        description="Number of findings the operator acknowledged when running the command."
    )
    note: str | None = Field(description="Free-text note the operator gave.")
    occurred_at: datetime


def reanchor_response(reanchor: Reanchor | None) -> AuditReanchorResponse | None:
    if reanchor is None:
        return None
    return AuditReanchorResponse(
        event_id=reanchor.event_id,
        operator=reanchor.operator,
        reason_code=reanchor.reason_code,
        acknowledged_through=reanchor.through,
        findings=reanchor.findings,
        note=reanchor.note,
        occurred_at=reanchor.occurred_at,
    )


def _is_none(value: object) -> bool:
    return value is None


def _is_zero(value: object) -> bool:
    return value == 0


class AuditVerifyResponse(BaseModel):
    """``first_id``/``last_id``/``last_hash`` are null when the org has no audit rows.

    ``anchor_id`` is set only for a walk from an anchor; a full walk leaves it out.
    ``findings`` lists only unacknowledged findings; ``acknowledged_findings`` counts the
    ones an operator re-anchor covers. Like ``anchor_id``, ``acknowledged_findings`` and
    ``reanchored_by`` are left out of the body while they are 0 and null (no re-anchor);
    so is ``reanchor``, the re-anchor event in full.
    """

    model_config = ConfigDict(frozen=True)

    ok: bool
    checked: int
    first_id: str | None
    last_id: str | None
    last_hash: str | None
    findings: list[AuditFindingResponse]
    findings_truncated: bool
    acknowledged_findings: int = Field(
        default=0, exclude_if=_is_zero, description=ACKNOWLEDGED_DESCRIPTION
    )
    reanchored_by: str | None = Field(
        default=None, exclude_if=_is_none, description=REANCHORED_BY_DESCRIPTION
    )
    reanchor: AuditReanchorResponse | None = Field(
        default=None, exclude_if=_is_none, description=REANCHOR_DESCRIPTION
    )
    anchor_id: str | None = Field(
        default=None, exclude_if=_is_none, description=ANCHOR_DESCRIPTION
    )


def finding_response(finding: ChainFinding) -> AuditFindingResponse:
    return AuditFindingResponse(kind=finding.kind, event_id=finding.row_id, detail=finding.detail)
