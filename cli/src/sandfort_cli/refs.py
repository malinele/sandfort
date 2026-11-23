"""Resolve a user-supplied sandbox reference (an id or a name) to a sandbox id."""

from sandfort_sdk import AmbiguousSandboxName, Client, NotFound

from sandfort_cli.output import CliError, _json_errors
from sandfort_cli.sanitise import MAX_ECHOED_VALUE_CHARS, caller_key, sanitise_text

ID_PREFIX = "sbx_"
# The server's code for a missing sandbox; a name miss reports the same one.
NOT_FOUND_CODE = "NOT_FOUND"
DESTROYED_STATE = "destroyed"


class SandboxNameNotFound(CliError):
    """No live sandbox carries the name; distinct from an ambiguous name, which stays a CliError.

    ``request_id`` is the one of the reply that showed the miss (the SDK's not-found carries the
    id of the last list reply), so the json error and the text line's tail name it.
    """

    def __init__(self, *args: object, request_id: str | None = None) -> None:
        super().__init__(*args)
        self.request_id = request_id


def name_miss_message(ref: str) -> str:
    """The error text of a name that matches no live sandbox.

    In text mode it starts with ``NOT_FOUND:``, as the line of an id miss does (the server's
    code before its message). Under ``--json`` the code is the document's ``code`` field, so the
    message carries no prefix.
    """
    # The user's text is sanitised before it is placed in the template: a lone ESC would
    # otherwise swallow the closing quote and part of the template in the later sanitising pass.
    name = sanitise_text(ref, api_key=caller_key(), limit=MAX_ECHOED_VALUE_CHARS)
    message = f"no sandbox named '{name}'; pass an id (sbx_...) or the name of an existing sandbox"
    return message if _json_errors.get() else f"{NOT_FOUND_CODE}: {message}"


def resolve_sandbox_id(client: Client, ref: str) -> str:
    """The id for ``ref``: ids pass through untouched, names are looked up among live sandboxes.

    The lookup rules live in the SDK (``Client.get``): destroyed sandboxes are ignored, those
    in the ``error`` state lose against any other, and a tie that remains is reported with the
    candidate ids. The SDK errors are mapped to the CLI's own messages here.
    """
    if ref.startswith(ID_PREFIX):
        return ref
    try:
        return client.get(ref).id
    except NotFound as exc:
        raise SandboxNameNotFound(name_miss_message(ref), request_id=exc.request_id) from None
    except AmbiguousSandboxName as exc:
        listing = ", ".join(f"{sandbox_id} ({state})" for sandbox_id, state in exc.candidates)
        raise CliError(
            f"several sandboxes are named '{ref}': {listing}; pass an id (sbx_...)"
        ) from None


def resolve_live_sandbox_id(client: Client, ref: str) -> str | None:
    """The id for ``ref``, or ``None`` when the sandbox is already gone.

    Gone means: no live sandbox carries the name, the fetch of the id answers ``NOT_FOUND``, or
    the fetched sandbox is ``destroyed``. Every other error (an ambiguous name, a server
    failure) is raised. A name needs no extra fetch: its lookup only sees live sandboxes.
    """
    try:
        sandbox_id = resolve_sandbox_id(client, ref)
        if ref.startswith(ID_PREFIX) and client.get(sandbox_id).info.state == DESTROYED_STATE:
            return None
    except (SandboxNameNotFound, NotFound):
        return None
    return sandbox_id
