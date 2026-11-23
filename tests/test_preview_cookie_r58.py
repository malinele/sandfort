"""Preview cookie hardening: ``__Host-`` prefix, always Secure, unprefixed cookie ignored."""

import pytest

from sandfort.proxy.tokens import (
    COOKIE_NAME,
    TOKEN_PARAM,
    split_cookie_token,
    token_cookie,
)

TOKEN = "abcDEF123_-"


def test_cookie_name_has_host_prefix() -> None:
    assert COOKIE_NAME == f"__Host-{TOKEN_PARAM}"


@pytest.mark.parametrize("secure", [True, False])
def test_cookie_is_host_prefixed_secure_and_domainless(secure: bool) -> None:
    value = token_cookie(TOKEN, secure=secure)

    assert value is not None
    attributes = [part.strip() for part in value.split(";")]
    assert attributes[0] == f"{COOKIE_NAME}={TOKEN}"
    assert "Path=/" in attributes
    assert "Secure" in attributes
    assert "HttpOnly" in attributes
    assert not any(part.lower().startswith("domain") for part in attributes)


def test_cookie_is_secure_by_default() -> None:
    value = token_cookie(TOKEN)

    assert value is not None
    assert "Secure" in value


@pytest.mark.parametrize("token", ["x; Domain=preview.test", "a" * 129, ""])
def test_malformed_token_gets_no_cookie(token: str) -> None:
    assert token_cookie(token, secure=True) is None


def test_prefixed_cookie_is_read_and_removed_from_forwarded_cookies() -> None:
    token, rest = split_cookie_token([f"theme=dark; {COOKIE_NAME}={TOKEN}; a=1"])

    assert token == TOKEN
    assert rest == "theme=dark; a=1"


def test_unprefixed_cookie_is_ignored_and_not_forwarded() -> None:
    token, rest = split_cookie_token([f"{TOKEN_PARAM}={TOKEN}; theme=dark"])

    assert token is None
    assert rest == "theme=dark"


def test_unprefixed_cookie_cannot_shadow_the_prefixed_one() -> None:
    token, rest = split_cookie_token(
        [f"{TOKEN_PARAM}=evil", f"{COOKIE_NAME}={TOKEN}", f"{TOKEN_PARAM}=evil2"]
    )

    assert token == TOKEN
    assert rest is None


def test_no_cookies_yield_no_token() -> None:
    assert split_cookie_token([]) == (None, None)
