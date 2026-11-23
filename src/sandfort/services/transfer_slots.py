"""Admission slots for volume exports and restores: a cap per org and one for the process.

Every export and restore holds one slot from the moment it is admitted until its stream is closed
or its restore has ended, so a client cannot keep an unbounded number of helper containers, daemon
extractions and decompressors busy. The same idea as the per-org terminal and async command
caps (``toolbox.pty.OrgSlots``), but a refusal is 409 ``CONFLICT`` with a reason of its own
(``org_transfer_limit`` or ``transfer_limit``), as the toolbox package cannot be imported from
services. The count is per process; a cap of 0 admits any number.
"""

from sandfort.errors import Conflict

ORG_TRANSFER_LIMIT = "org_transfer_limit"
TRANSFER_LIMIT = "transfer_limit"


class TransferSlots:
    """Slots held by transfer keys; ``hold`` is idempotent per key, ``release`` too."""

    def __init__(self, per_org: int = 0, total: int = 0) -> None:
        self._per_org = per_org
        self._total = total
        self._owners: dict[str, str] = {}  # transfer key -> org id

    def __len__(self) -> int:
        return len(self._owners)

    def hold(self, org_id: str, key: str) -> None:
        """Take a slot for ``key``; ``Conflict`` when the org or the process is full."""
        if key in self._owners:
            return
        held = sum(1 for owner in self._owners.values() if owner == org_id)
        if 0 < self._per_org <= held:
            raise Conflict(
                f"the org already has {self._per_org} volume transfers running; "
                "a slot frees when one finishes",
                reason=ORG_TRANSFER_LIMIT,
                details={"limit": self._per_org},
            )
        if 0 < self._total <= len(self._owners):
            raise Conflict(
                f"the server is already running {self._total} volume transfers; "
                "try again when one finishes",
                reason=TRANSFER_LIMIT,
                details={"limit": self._total},
            )
        self._owners[key] = org_id

    def release(self, key: str) -> None:
        self._owners.pop(key, None)
