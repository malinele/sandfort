"""Reading the ``sandbox.reset`` audit events: which container does a reset replace.

A reset audits ``sandbox.reset`` with the ``driver_ref`` of the container it removes, and only
afterwards points the row at the new container. These pure functions answer, for the details of
the reset events of one sandbox, whether a row's ``driver_ref`` is (or may be) one of the
containers a reset replaced.
"""

from collections.abc import Mapping, Sequence
from typing import Any

# Key of the ``sandbox.reset`` audit details holding the driver_ref the reset replaces.
PREVIOUS_DRIVER_REF = "previous_driver_ref"


def may_point_at_replaced(details: Sequence[Mapping[str, Any]], driver_ref: str | None) -> bool:
    """Whether a row with ``driver_ref`` may still point at a container a reset is replacing.

    ``True`` when ``driver_ref`` is ``None``, when any event lacks ``previous_driver_ref``
    (written before the key existed, so what it replaced is unknown), or when any event's
    ``previous_driver_ref`` equals ``driver_ref``. ``False`` for an empty sequence.
    """
    if not details:
        return False
    if driver_ref is None:
        return True
    for event in details:
        if PREVIOUS_DRIVER_REF not in event or event[PREVIOUS_DRIVER_REF] == driver_ref:
            return True
    return False


def has_reset_in_window(details: Sequence[Mapping[str, Any]]) -> bool:
    """Whether any ``sandbox.reset`` event is in ``details`` (already limited to the window).

    A reset saves the new container's ref on the row before it starts that container, so a
    container that exists but was never started, on a row with a recent reset, is that new
    container between create and start, whatever ref the row holds. ``True`` for any event,
    whatever it names; ``False`` for an empty sequence.
    """
    return len(details) > 0


def replaced(details: Sequence[Mapping[str, Any]], driver_ref: str | None) -> bool:
    """Whether some reset event names ``driver_ref`` as the container it replaced.

    ``True`` only for a non-null ``driver_ref`` equal to some event's ``previous_driver_ref``;
    an event without the key proves nothing.
    """
    if driver_ref is None:
        return False
    return any(event.get(PREVIOUS_DRIVER_REF) == driver_ref for event in details)
