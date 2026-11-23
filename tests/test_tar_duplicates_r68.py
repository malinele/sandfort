"""Round 68 (SF74-001): a second member at a path an earlier member already used is refused.

Before this round only a member at the path of an earlier SYMLINK was ``duplicate_entry``; two
regular members of the same name were accepted and the second silently overwrote the first.
The policy now remembers every approved path (file, directory or symlink), normalised, and
refuses any later member with an equal normalised path.
"""

import tarfile

import pytest

from sandfort.drivers.docker import tar_policy
from sandfort.drivers.docker.tar_policy import DUPLICATE_ENTRY, TOO_MANY_ENTRIES, checked_tar
from sandfort.drivers.errors import DriverForbiddenEntry
from test_tar_policy_r67 import (
    directory,
    members_of,
    refused,
    regular,
    run,
    symlink,
    tar_of,
)


def test_two_regular_files_of_the_same_name_are_refused() -> None:
    error = refused(regular("same.txt", b"FIRST"), regular("same.txt", b"SECOND"))

    assert error.violation == DUPLICATE_ENTRY
    assert error.entry == "same.txt"


def test_the_first_member_is_emitted_before_the_duplicate_is_refused() -> None:
    data = tar_of(regular("same.txt", b"FIRST"), regular("same.txt", b"SECOND"))
    seen: list[bytes] = []

    with pytest.raises(DriverForbiddenEntry):
        for chunk in checked_tar([data]):
            seen.append(chunk)

    emitted = b"".join(seen)
    assert b"FIRST" in emitted
    assert b"SECOND" not in emitted


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (regular("x"), directory("x")),
        (directory("x"), regular("x")),
        (regular("x"), symlink("x", "y")),
        (symlink("x", "y"), regular("x")),
        (directory("x"), symlink("x", "y")),
        (symlink("x", "y"), directory("x")),
    ],
    ids=["file-dir", "dir-file", "file-link", "link-file", "dir-link", "link-dir"],
)
def test_the_same_name_with_a_different_type_is_refused(
    first: tuple[tarfile.TarInfo, bytes | None], second: tuple[tarfile.TarInfo, bytes | None]
) -> None:
    assert refused(first, second).violation == DUPLICATE_ENTRY


def test_a_duplicate_directory_entry_is_refused() -> None:
    error = refused(directory("d"), regular("d/a"), directory("d"))

    assert error.violation == DUPLICATE_ENTRY
    assert error.entry == "d"


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("./a", "a"),
        ("a", "./a"),
        ("a", "a/"),
        ("a//b", "a/b"),
        ("./a/./b", "a/b"),
        (".", "./"),
    ],
)
def test_names_that_normalise_to_the_same_path_are_duplicates(first: str, second: str) -> None:
    error = refused(regular(first), regular(second))

    assert error.violation == DUPLICATE_ENTRY


def test_the_duplicate_rule_is_independent_of_chunking() -> None:
    data = tar_of(regular("same.txt", b"FIRST" * 3000), regular("same.txt", b"SECOND"))

    for step in (1, 511, 512, 4096, len(data)):
        with pytest.raises(DriverForbiddenEntry) as caught:
            run(data, step=step)
        assert caught.value.violation == DUPLICATE_ENTRY


def test_distinct_names_and_a_directory_with_its_children_still_pass() -> None:
    data = tar_of(
        directory("d"),
        regular("d/a", b"1"),
        regular("d/b", b"2"),
        regular("a", b"3"),
        symlink("l", "a"),
        directory("e"),
    )

    assert set(members_of(run(data))) == {"d", "d/a", "d/b", "a", "l", "e"}


def test_a_same_basename_in_another_directory_is_not_a_duplicate() -> None:
    data = tar_of(regular("x/f"), regular("y/f"), regular("f"))

    assert set(members_of(run(data))) == {"x/f", "y/f", "f"}


def test_the_seen_paths_are_bounded_by_the_member_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tar_policy, "MAX_MEMBERS", 20)
    members = [regular(f"f{n}") for n in range(21)]

    assert refused(*members).violation == TOO_MANY_ENTRIES


def test_a_legitimate_single_occurrence_archive_round_trips_byte_for_content() -> None:
    data = tar_of(directory("."), regular("a", b"alpha"), directory("s"), regular("s/b", b"beta"))
    found = members_of(run(data))

    assert set(found) == {".", "a", "s", "s/b"}
