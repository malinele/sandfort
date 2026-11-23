"""The pure readers of ``sandbox.reset`` audit details: which container a reset replaced."""

from typing import Any

from sandfort.domain.reset_events import (
    PREVIOUS_DRIVER_REF,
    has_reset_in_window,
    may_point_at_replaced,
    replaced,
)

OLD = "container-old"
NEWER = "container-newer"
CURRENT = "container-current"
LEGACY: dict[str, Any] = {"state": "started"}  # written before the key existed


def event(previous: str | None) -> dict[str, Any]:
    return {"state": "started", PREVIOUS_DRIVER_REF: previous}


def test_the_details_key_is_previous_driver_ref() -> None:
    assert PREVIOUS_DRIVER_REF == "previous_driver_ref"


# -- may_point_at_replaced ---------------------------------------------------------------------


def test_may_point_is_false_without_any_event() -> None:
    assert may_point_at_replaced([], CURRENT) is False
    assert may_point_at_replaced([], None) is False


def test_may_point_is_true_for_a_row_without_a_ref() -> None:
    assert may_point_at_replaced([event(OLD)], None) is True


def test_may_point_is_true_when_an_event_predates_the_key() -> None:
    assert may_point_at_replaced([LEGACY], CURRENT) is True
    assert may_point_at_replaced([event(OLD), LEGACY], CURRENT) is True


def test_may_point_is_true_when_any_event_names_the_ref_not_only_the_last() -> None:
    assert may_point_at_replaced([event(CURRENT), event(OLD), event(NEWER)], CURRENT) is True
    assert may_point_at_replaced([event(OLD), event(CURRENT)], CURRENT) is True


def test_may_point_is_false_when_no_event_names_the_ref() -> None:
    assert may_point_at_replaced([event(OLD), event(NEWER)], CURRENT) is False


def test_a_null_previous_ref_does_not_match_a_row_that_has_a_ref() -> None:
    assert may_point_at_replaced([event(None)], CURRENT) is False


# -- replaced ----------------------------------------------------------------------------------


def test_replaced_is_false_without_any_event() -> None:
    assert replaced([], CURRENT) is False


def test_replaced_is_false_for_a_missing_ref() -> None:
    assert replaced([event(OLD), event(None)], None) is False


def test_replaced_has_no_legacy_fallback() -> None:
    assert replaced([LEGACY], CURRENT) is False
    assert replaced([LEGACY, event(OLD)], CURRENT) is False


def test_replaced_is_true_when_any_event_names_the_ref() -> None:
    assert replaced([event(OLD), event(CURRENT), event(NEWER)], CURRENT) is True
    assert replaced([LEGACY, event(CURRENT)], CURRENT) is True


def test_replaced_is_false_when_no_event_names_the_ref() -> None:
    assert replaced([event(OLD), event(NEWER)], CURRENT) is False


# -- has_reset_in_window -----------------------------------------------------------------------


def test_window_is_empty_without_any_event() -> None:
    assert has_reset_in_window([]) is False


def test_window_has_a_reset_for_any_event_whatever_it_names() -> None:
    assert has_reset_in_window([event(OLD)]) is True
    assert has_reset_in_window([event(None)]) is True
    assert has_reset_in_window([LEGACY]) is True
    assert has_reset_in_window([event(OLD), event(NEWER)]) is True
