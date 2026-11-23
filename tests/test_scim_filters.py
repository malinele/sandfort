"""SCIM slice six: ``parse_user_filter`` accepts ``userName eq "<value>"`` and nothing else.

Pure unit tests: no database, no http, no settings.
"""

import dataclasses

import pytest

from sandfort.api.scim.filters import FilterError, UserNameFilter, parse_user_filter
from sandfort.errors import ValidationFailed


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('userName eq "ada@example.com"', "ada@example.com"),
        ('username eq "ada@example.com"', "ada@example.com"),
        ('USERNAME EQ "ada@example.com"', "ada@example.com"),
        ('uSeRnAmE Eq "ada@example.com"', "ada@example.com"),
        ('userName eq "Ada.Lovelace@Example.COM"', "ada.lovelace@example.com"),
        ('  userName   eq   "ada@example.com"  ', "ada@example.com"),
        ('userName\teq\t"ada@example.com"', "ada@example.com"),
        ('userName eq "a\\"b@example.com"', 'a"b@example.com'),
        ('userName eq "\\u0041da@example.com"', "ada@example.com"),
        ('userName eq "back\\\\slash"', "back\\slash"),
        ('userName eq "x and y or z"', "x and y or z"),
        ('userName eq "(a)"', "(a)"),
        ('userName eq "ünï@example.com"', "ünï@example.com"),
    ],
)
def test_accepts_username_eq_and_returns_lowercased_value(text: str, expected: str) -> None:
    assert parse_user_filter(text) == UserNameFilter(user_name=expected)


REFUSED_FILTERS = [
    pytest.param("", id="empty"),
    pytest.param("   ", id="blank"),
    pytest.param("userName", id="attribute-only"),
    pytest.param("userName eq", id="missing-value"),
    pytest.param("userName pr", id="presence"),
    pytest.param('userName ne "ada@example.com"', id="ne"),
    pytest.param('userName co "ada"', id="co"),
    pytest.param('userName sw "ada"', id="sw"),
    pytest.param('userName ew "example.com"', id="ew"),
    pytest.param('userName gt "a"', id="gt"),
    pytest.param('userName ge "a"', id="ge"),
    pytest.param('userName lt "a"', id="lt"),
    pytest.param('userName le "a"', id="le"),
    pytest.param('userName eq "a" and userName eq "b"', id="and"),
    pytest.param('userName eq "a" AND userName eq "b"', id="and-upper"),
    pytest.param('userName eq "a" or userName eq "b"', id="or"),
    pytest.param('userName eq "a" or externalId eq "b"', id="or-external-id"),
    pytest.param('(userName eq "a")', id="grouped"),
    pytest.param('not (userName eq "a")', id="not"),
    pytest.param('userName eq "a" "b"', id="trailing-garbage"),
    pytest.param('userName eq "a" x', id="trailing-token"),
    pytest.param('x userName eq "a"', id="leading-token"),
    pytest.param('externalId eq "abc"', id="external-id"),
    pytest.param('id eq "usr_1"', id="id"),
    pytest.param('displayName eq "Ada"', id="display-name"),
    pytest.param('emails.value eq "a@example.com"', id="emails-value"),
    pytest.param('emails[type eq "work"].value eq "a@example.com"', id="emails-filter"),
    pytest.param('userName[type eq "work"] eq "a"', id="username-with-sub-filter"),
    pytest.param('userName.value eq "a"', id="username-sub-attribute"),
    pytest.param(
        'urn:ietf:params:scim:schemas:core:2.0:User:userName eq "a"',
        id="fully-qualified-attribute",
    ),
    pytest.param("userName eq a", id="unquoted-word"),
    pytest.param("userName eq 5", id="number"),
    pytest.param("userName eq true", id="boolean"),
    pytest.param("userName eq null", id="null"),
    pytest.param("userName eq 'a@example.com'", id="single-quoted"),
    pytest.param('userName eq "unterminated', id="unterminated"),
    pytest.param('userName eq "a\\x"', id="bad-escape"),
    pytest.param('userName eq "tab\there"', id="raw-control-character"),
    pytest.param('userName eq"a"', id="no-space-before-value"),
    pytest.param('userNameeq "a"', id="no-space-after-attribute"),
    pytest.param('uſerName eq "a"', id="non-ascii-lookalike-attribute"),
    pytest.param('userName eſ "a"', id="non-ascii-lookalike-operator"),
]


@pytest.mark.parametrize("text", REFUSED_FILTERS)
def test_refuses_every_other_filter_as_invalid_filter(text: str) -> None:
    with pytest.raises(FilterError) as info:
        parse_user_filter(text)

    assert info.value.scim_type == "invalidFilter"


def test_filter_error_is_a_400_validation_failure() -> None:
    with pytest.raises(ValidationFailed) as info:
        parse_user_filter('userName co "a"')

    assert info.value.status == 400
    assert isinstance(info.value, FilterError)


def test_refusal_does_not_repeat_the_filter_text() -> None:
    with pytest.raises(FilterError) as info:
        parse_user_filter('externalId eq "s3cret-value"')

    assert "s3cret-value" not in info.value.message
    assert "userName eq" in info.value.message


def test_result_is_immutable() -> None:
    parsed = parse_user_filter('userName eq "a@example.com"')

    with pytest.raises(dataclasses.FrozenInstanceError):
        parsed.user_name = "b@example.com"  # type: ignore[misc]
