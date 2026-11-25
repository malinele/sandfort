"""PATCH rules for a sandbox's egress allowlist (docs/egress-v2-design.md section 3.4).

``plan_egress_update`` decides, for the sandbox as stored, whether a requested allowlist is
refused (403, 409 or 422), changes nothing (``None``) or replaces the stored list. It never
touches the driver: the new list is written to the database with the other PATCH fields and the
proxy converges within its cache window, so the 200 means the policy is stored, not applied.
The caller records ``EgressUpdate.note`` in the same unit of work as the write.
"""

from dataclasses import dataclass

from sandfort.config import Settings
from sandfort.domain.sandbox import Sandbox, check_egress_allowlist
from sandfort.errors import Forbidden, InvalidState, Unprocessable
from sandfort.services.sandbox_jobs import AuditNote

EGRESS_UPDATED_ACTION = "sandbox.egress_updated"
NETWORK_POLICY_MESSAGE = "network egress is disabled by operator policy"
NULL_REFUSED_MESSAGE = (
    "egress_allowlist cannot be removed from a sandbox, create a new sandbox for open egress"
)
LEGACY_RESET_MESSAGE = "reset the sandbox to upgrade its egress credential"
NO_ALLOWLIST_MESSAGE = (
    "the sandbox was created without an egress_allowlist; create a new sandbox to restrict egress"
)
BLOCKED_MESSAGE = (
    "the sandbox was created with an empty egress_allowlist (network blocked); "
    "create a new sandbox to allow hosts"
)


@dataclass(frozen=True, slots=True)
class EgressUpdate:
    """An effective allowlist change: the new list, the new generation and its audit row."""

    allowlist: tuple[str, ...]
    generation: int
    note: AuditNote


def plan_egress_update(
    current: Sandbox, entries: tuple[str, ...], actor_id: str | None, settings: Settings
) -> EgressUpdate | None:
    """The change that replaces ``current``'s allowlist with ``entries``, or ``None`` (no-op).

    Raises ``Forbidden`` under ``enforce_block_network``, ``InvalidState`` (409) when the sandbox
    cannot take an allowlist (none was set at create, the create stored an empty one, or the
    credential is a legacy v1 token) and ``Unprocessable`` when an entry is invalid.
    """
    if settings.enforce_block_network:
        raise Forbidden(NETWORK_POLICY_MESSAGE)
    stored = current.egress_allowlist
    if stored is None:
        raise InvalidState(NO_ALLOWLIST_MESSAGE)
    if not stored and current.network.block_all:
        raise InvalidState(BLOCKED_MESSAGE)
    if current.egress_policy_generation == 0:
        raise InvalidState(LEGACY_RESET_MESSAGE)
    check_egress_allowlist(
        entries,
        current.network,
        settings.egress_allowlist_max_entries,
        Unprocessable,
        denied=settings.egress_denied_cidrs,
    )
    if entries == stored:
        return None
    generation = current.egress_policy_generation + 1
    details = {
        "old_allowlist": list(stored),
        "new_allowlist": list(entries),
        "old_generation": current.egress_policy_generation,
        "new_generation": generation,
    }
    return EgressUpdate(entries, generation, AuditNote(actor_id, EGRESS_UPDATED_ACTION, details))
