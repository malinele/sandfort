"""Response model of ``GET /v1/org/quota``: the org view and, for a scoped key, its own scope.

One model serves both kinds of key. ``scope`` is ``null`` for an org-wide key (the answer is
exactly the org snapshot); for a key limited to labelled sandboxes it holds the key's own cap
and count, and ``reserved`` then covers only the sandboxes inside that scope.
"""

from pydantic import BaseModel, Field

from sandfort.api.schemas.orgs import QuotaResponse, quota_response
from sandfort.services.quota import QuotaUsage, ScopedQuotaUsage


class ScopeQuotaBody(BaseModel):
    """A label-scoped key's own view of its sandbox cap."""

    labels: dict[str, str] = Field(description="The key's label scope.")
    max_sandboxes: int | None = Field(
        description="The key's cap on live sandboxes inside its scope; null when it has none."
    )
    sandboxes: int = Field(description="Live sandboxes inside the scope; they count to the cap.")
    remaining: int | None = Field(
        description="Sandboxes the key may still create under its cap; null without a cap."
    )


class QuotaView(QuotaResponse):
    scope: ScopeQuotaBody | None = Field(
        default=None,
        description="Set only for a key limited to labelled sandboxes; null for an org-wide key.",
    )


def org_quota_view(usage: QuotaUsage) -> QuotaView:
    base = quota_response(usage)
    return QuotaView(limits=base.limits, reserved=base.reserved)


def scoped_quota_view(usage: ScopedQuotaUsage) -> QuotaView:
    base = quota_response(QuotaUsage(limits=usage.limits, reserved=usage.reserved))
    cap = usage.max_sandboxes
    remaining = None if cap is None else max(cap - usage.sandboxes, 0)
    scope = ScopeQuotaBody(
        labels=dict(usage.labels),
        max_sandboxes=cap,
        sandboxes=usage.sandboxes,
        remaining=remaining,
    )
    return QuotaView(limits=base.limits, reserved=base.reserved, scope=scope)
