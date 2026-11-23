"""The ``sandfort`` Typer application: global ``--json`` plus the subcommands."""

from typing import Annotated, Any, NoReturn

import sandfort_sdk
import typer
from typer.core import TyperGroup

try:  # typer 0.27+ vendors click; its UsageError is not the installed click's class
    from typer._click import core as click_core
    from typer._click import exceptions as click_exceptions
except ImportError:  # pragma: no cover - older typer builds on the installed click
    from click import core as click_core  # type: ignore[no-redef]
    from click import exceptions as click_exceptions  # type: ignore[no-redef]

from sandfort_cli import build_info, shell_cmd
from sandfort_cli.audit import audit_app
from sandfort_cli.cmd_cmd import cmd_app, preview_command
from sandfort_cli.cp_cmd import cp_command
from sandfort_cli.exec_cmd import EXEC_CONTEXT_SETTINGS, exec_command
from sandfort_cli.keys import key_app
from sandfort_cli.members import members_app
from sandfort_cli.output import AppState, app_state, print_json, set_json_errors
from sandfort_cli.quota_cmd import QUOTA_EPILOG, quota_command
from sandfort_cli.sandboxes import (
    EXIT_USAGE,
    JSON_ERROR_EPILOG,
    login,
    sandbox_app,
    usage_error_payload,
)
from sandfort_cli.sanitise import USAGE_MESSAGE_CHARS, caller_key, sanitise_text
from sandfort_cli.snapshot import snapshot_app
from sandfort_cli.usage_cmd import USAGE_EPILOG, usage_command
from sandfort_cli.volume import volume_app
from sandfort_cli.webhooks import webhook_app

SERVER_VERSION_HINT = "server: use GET /v1/status build_sha"
JSON_FLAG = "--json"
JSON_PLACEMENT_HINT = (
    f"{JSON_FLAG} is a global option and belongs before the command, "
    f"for example: sandfort {JSON_FLAG} sandbox list"
)


def add_json_placement_hint(exc: click_exceptions.UsageError) -> None:
    """Append the placement hint to the "No such option: --json" error of a trailing flag.

    Only that exact option name, and only when json mode is not already active (with a leading
    ``--json`` too, "belongs before the command" would be misleading); it changes the message of
    the text usage frame.
    """
    if isinstance(exc, click_exceptions.NoSuchOption) and exc.option_name == JSON_FLAG:
        exc.message = f"{exc.message}; {JSON_PLACEMENT_HINT}"


def sanitise_usage_error(exc: click_exceptions.UsageError) -> None:
    """Clean the message of a text-mode usage error before the frame prints it.

    Typer echoes what was typed ("unexpected extra argument (X)", "No such command 'X'", "No such
    option: X"), so a key given by mistake would reach the terminal; the message goes through the
    same sanitiser as the json usage error (the caller's key and key-shaped tokens are masked,
    control characters removed, the length capped).
    """
    exc.message = sanitise_text(exc.message, api_key=caller_key(), limit=USAGE_MESSAGE_CHARS)


def emit_json_usage_message(message: str) -> NoReturn:
    """Print one json usage-error object with ``message`` on stdout and exit 2."""
    print_json(usage_error_payload(message))
    raise typer.Exit(EXIT_USAGE)


def emit_json_usage_error(exc: click_exceptions.UsageError) -> NoReturn:
    """Print one json usage-error object on stdout (exit 2) instead of the framed usage box."""
    emit_json_usage_message(exc.format_message())


def reject_bare_group(
    ctx: click_core.Context, name: str | None, command: Any, rest: list[str]
) -> None:
    """Under ``--json``, a command group called without arguments is one json usage object.

    Typer prints a group's help while it builds the error for that case (to stdout), which would
    put text in front of the json object. So the check runs here, before the group is entered.
    Text mode is not affected and still prints the help.
    """
    path = [ctx.command_path, name or ""]
    while isinstance(command, TyperGroup) and command.no_args_is_help:
        if not rest:
            emit_json_usage_message(
                f"missing command for '{' '.join(path)}'; the help is available in text mode "
                f"(run it without {JSON_FLAG}, or add --help)"
            )
        nested = None if rest[0].startswith("-") else command.get_command(ctx, rest[0])
        if nested is None:
            return
        path.append(rest[0])
        command, rest = nested, rest[1:]


def leading_json_flag(args: list[str]) -> bool:
    """True when ``--json`` is among the leading options of ``args`` (before any command)."""
    for arg in args:
        if not arg.startswith("-"):
            return False
        if arg == JSON_FLAG:
            return True
    return False


class JsonUsageGroup(TyperGroup):
    """The root group: under ``--json`` a usage error anywhere in the CLI is one json object.

    A usage error of a subcommand (a bad option value, a missing argument, a check raised in
    the command body) passes through the root's ``invoke``; one of the root's own options is
    raised while its context is built. Text mode keeps the framed usage box.
    """

    def make_context(
        self,
        info_name: str | None,
        args: list[str],
        parent: click_core.Context | None = None,
        **extra: Any,
    ) -> click_core.Context:
        typed = list(args)  # the parser consumes ``args`` in place
        try:
            return super().make_context(info_name, args, parent, **extra)
        except click_exceptions.UsageError as exc:
            if leading_json_flag(typed):
                emit_json_usage_error(exc)
            sanitise_usage_error(exc)
            raise

    def resolve_command(
        self, ctx: click_core.Context, args: list[str]
    ) -> tuple[str | None, click_core.Command | None, list[str]]:
        name, command, rest = super().resolve_command(ctx, args)
        if ctx.params.get("json_output"):
            reject_bare_group(ctx, name, command, rest)
        return name, command, rest

    def invoke(self, ctx: click_core.Context) -> Any:
        try:
            return super().invoke(ctx)
        except click_exceptions.UsageError as exc:
            if not ctx.params.get("json_output"):
                sanitise_usage_error(exc)
                add_json_placement_hint(exc)
                raise
            emit_json_usage_error(exc)


def _sdk_build_info() -> build_info.BuildFields:
    """The installed SDK's build info, or an all-None one when the SDK predates ``build_info``.

    The CLI's sdk dependency is unpinned, so an older wheel may be installed next to this CLI.
    """
    sdk_build_info = getattr(sandfort_sdk, "build_info", None)
    if sdk_build_info is None:
        return build_info.BuildInfo(commit=None, tag=None, built_at=None)
    info: build_info.BuildFields = sdk_build_info()
    return info


def version_command(ctx: typer.Context) -> None:
    """Show the cli and sdk versions and builds (no network call)."""
    cli_info = build_info.cli_build_info()
    sdk_info = _sdk_build_info()
    cli_version = build_info.distribution_version(build_info.CLI_DISTRIBUTION)
    sdk_version = build_info.distribution_version(build_info.SDK_DISTRIBUTION)
    if app_state(ctx).json_output:
        print_json(
            {
                "cli": build_info.component_payload(cli_info, cli_version),
                "sdk": build_info.component_payload(sdk_info, sdk_version),
            }
        )
        return
    typer.echo(build_info.component_line("cli", cli_info, cli_version))
    typer.echo(build_info.component_line("sdk", sdk_info, sdk_version))
    typer.echo(SERVER_VERSION_HINT)


def create_app(terminal: shell_cmd.TerminalSeam | None = None) -> typer.Typer:
    """Build the application; ``terminal`` replaces the real terminal for ``shell`` (tests)."""
    app = typer.Typer(
        cls=JsonUsageGroup,
        name="sandfort",
        help="Sandfort sandbox platform CLI.",
        epilog=JSON_ERROR_EPILOG,
        no_args_is_help=True,
    )

    @app.callback()
    def configure(
        ctx: typer.Context,
        json_output: Annotated[
            bool, typer.Option("--json", help="Print raw json instead of tables.")
        ] = False,
    ) -> None:
        ctx.obj = AppState(json_output=json_output)
        set_json_errors(json_output)

    app.command("login", epilog=JSON_ERROR_EPILOG)(login)
    app.add_typer(sandbox_app)
    app.add_typer(snapshot_app)
    app.add_typer(volume_app)
    app.add_typer(members_app)
    app.add_typer(key_app)
    app.add_typer(audit_app)
    app.add_typer(webhook_app)
    app.add_typer(cmd_app)
    app.command("preview", epilog=JSON_ERROR_EPILOG)(preview_command)
    app.command("exec", context_settings=EXEC_CONTEXT_SETTINGS, epilog=JSON_ERROR_EPILOG)(
        exec_command
    )
    app.command("cp", epilog=JSON_ERROR_EPILOG)(cp_command)
    app.command("usage", epilog=USAGE_EPILOG)(usage_command)
    app.command("quota", epilog=QUOTA_EPILOG)(quota_command)
    shell_cmd.register(app, shell_cmd.PosixTerminal() if terminal is None else terminal)
    app.command("version")(version_command)
    return app


app = create_app()


def main() -> None:
    app()
