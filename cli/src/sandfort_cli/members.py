"""The ``members`` command group (add, list, set-role, remove)."""

from collections.abc import Sequence
from dataclasses import asdict
from enum import StrEnum
from typing import Annotated, Any

import typer
from sandfort_sdk import Member

from sandfort_cli.config import open_client
from sandfort_cli.output import (
    AppState,
    app_state,
    clean_strings,
    cli_errors,
    print_fields,
    print_json,
    print_table,
    reject_empty_name,
    render_message,
    shown,
)
from sandfort_cli.sandboxes import JSON_ERROR_EPILOG
from sandfort_cli.sanitise import caller_key

members_app = typer.Typer(
    name="members",
    help="Manage organization members.",
    epilog=JSON_ERROR_EPILOG,
    no_args_is_help=True,
)


MEMBER_COLUMNS = ("USER ID", "EMAIL", "NAME", "ROLE")
# Free text, highest priority first; USER ID and ROLE are never squeezed or dropped.
MEMBER_FREE = ("EMAIL", "NAME")


class Role(StrEnum):
    ADMIN = "admin"
    DEVELOPER = "developer"
    VIEWER = "viewer"


USER_ID_METAVAR = "<user-id>"
EMAIL_METAVAR = "<email>"
DISPLAY_NAME_METAVAR = "<display-name>"
UserId = Annotated[str, typer.Argument(metavar=USER_ID_METAVAR, help="User id.")]
RoleOption = Annotated[Role, typer.Option("--role", help="Organization role.")]


def member_payload(member: Member) -> dict[str, Any]:
    """The member object for ``--json``: server strings sanitised like the sandbox views."""
    payload = {**asdict(member), "created_at": member.created_at.isoformat()}
    cleaned: dict[str, Any] = clean_strings(payload, caller_key())
    return cleaned


def render_member(state: AppState, member: Member) -> None:
    if state.json_output:
        print_json(member_payload(member))
        return
    key = caller_key()
    fields = {
        "user_id": shown(member.user_id, key),
        "email": shown(member.email, key),
        "display_name": shown(member.display_name, key),
        "role": shown(member.role, key),
        "created_at": member.created_at.isoformat(),
    }
    print_fields("member", fields)


def render_members(state: AppState, members: Sequence[Member]) -> None:
    if state.json_output:
        print_json([member_payload(member) for member in members])
        return
    key = caller_key()
    rows = [
        (
            shown(m.user_id, key),
            shown(m.email, key),
            shown(m.display_name, key),
            shown(m.role, key),
        )
        for m in members
    ]
    print_table("members", MEMBER_COLUMNS, rows, free=MEMBER_FREE)


@members_app.command("add")
def add(
    ctx: typer.Context,
    email: Annotated[str, typer.Argument(metavar=EMAIL_METAVAR, help="Member email address.")],
    display_name: Annotated[
        str, typer.Argument(metavar=DISPLAY_NAME_METAVAR, help="Member display name.")
    ],
    role: RoleOption,
) -> None:
    """Add a member to the organization."""
    reject_empty_name(email, EMAIL_METAVAR)
    reject_empty_name(display_name, DISPLAY_NAME_METAVAR)
    with cli_errors(), open_client() as client:
        render_member(app_state(ctx), client.members.create(email, display_name, role.value))


@members_app.command("list")
def list_members(ctx: typer.Context) -> None:
    """List members."""
    with cli_errors(), open_client() as client:
        render_members(app_state(ctx), client.members.list())


@members_app.command("set-role")
def set_role(ctx: typer.Context, user_id: UserId, role: RoleOption) -> None:
    """Change a member's role (refused if the org would be left without an admin)."""
    reject_empty_name(user_id, USER_ID_METAVAR)
    with cli_errors(), open_client() as client:
        render_member(app_state(ctx), client.members.set_role(user_id, role.value))


@members_app.command("remove")
def remove(ctx: typer.Context, user_id: UserId) -> None:
    """Remove a member (refused if the org would be left without an admin)."""
    reject_empty_name(user_id, USER_ID_METAVAR)
    with cli_errors(), open_client() as client:
        client.members.remove(user_id)
        clean_id = shown(user_id, caller_key())
        render_message(app_state(ctx), f"removed {clean_id}", {"removed": clean_id})
