"""What ``sandfort preview`` prints: the ``url`` in text mode, ``browser_url`` on request.

Text mode prints the reply's ``url``, which carries the token in its query, so
``curl "$(sandfort preview <sandbox> <port>)"`` reaches the app. With ``--browser`` it prints
the reply's ``browser_url`` instead, but only when that url's fragment carries the token
(``...#sandfort_preview_token=<token>``). In every other case ``--browser`` prints what plain
text mode prints, so it never shows a masked ``#***`` link. The sanitiser would mask the whole
fragment, so :func:`browser_view` puts the pair back, by its parameter name and only when the
token is ordinary text. ``--json`` has ``browser_url`` whenever the server sent one.
"""

import typer

from sandfort_cli.output import shown

# The name of the token pair in the fragment (``TOKEN_PARAM`` in ``cmd_cmd`` and in the server's
# proxy module, repeated here because this module must not import ``cmd_cmd``).
HANDOFF_PARAM = "sandfort_preview_token"


def browser_view(url: str, token: str, api_key: str) -> tuple[str, bool]:
    """``url`` sanitised like any server text, except that the token stays usable, and whether
    the returned url carries the token verbatim.

    The part before ``#`` is sanitised and the fragment is put back as returned when it is exactly
    ``<HANDOFF_PARAM>=<token>`` and the token is ordinary text (the sanitiser would leave it
    unchanged). In every other case the fully sanitised url is returned, with the flag False.
    """
    if not token or shown(token, api_key) != token:
        return shown(url, api_key), False
    head, mark, fragment = url.partition("#")
    if not mark or fragment != f"{HANDOFF_PARAM}={token}":
        return shown(url, api_key), False
    return f"{shown(head, api_key)}#{HANDOFF_PARAM}={token}", True


def browser_field(browser_url: str | None, token: str, api_key: str) -> dict[str, str]:
    """The ``browser_url`` entry of ``sandfort --json preview``, empty when the server sent none."""
    if not browser_url:
        return {}
    return {"browser_url": browser_view(browser_url, token, api_key)[0]}


def echo_preview_text(
    url_view: tuple[str, bool], browser_url: str | None, token: str, api_key: str
) -> None:
    """Print the text mode lines of ``sandfort preview``.

    ``url_view`` is the reply's ``url`` as ``cmd_cmd.preview_view`` returns it, and
    ``browser_url`` is the reply's one when ``--browser`` was given, else None. A browser url
    that carries the token is printed alone. Otherwise the url is printed, followed by a
    ``token:`` line when it cannot carry the token.
    """
    printed, carried = url_view
    if browser_url:
        view = browser_view(browser_url, token, api_key)
        printed, carried = view if view[1] else url_view
    typer.echo(printed)
    if not carried:
        echo_token_line(token)


def has_control_chars(text: str) -> bool:
    return any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in text)


def echo_token_line(token: str) -> None:
    """Text mode only: the exact token on its own line, for a url that could not carry it.

    A token holding control characters is never printed raw, since it could drive the terminal.
    It is not an ordinary token, and ``--json`` has it exactly.
    """
    if not token:
        return
    if has_control_chars(token):
        typer.echo("sandfort: the token holds control characters, use --json to read it", err=True)
        return
    typer.echo(f"token: {token}")
