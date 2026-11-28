"""``sandfort-server`` entrypoint (``--role all|api|worker``) and uvicorn launcher.

For ``uvicorn --factory`` use ``sandfort.main:create_app``; the preview proxy alone is
``sandfort.main:create_proxy_app``. Both paths install the JSON log handler
(``sandfort.logging``) before the application is built; ``sandfort-server`` also hands
uvicorn's own loggers to it and leaves access lines to the telemetry middleware. With
``SANDFORT_PROXY_ENABLED`` the server also serves the preview proxy on ``SANDFORT_PROXY_PORT``
in the same process, sharing the API's preview-token store, so minted tokens open previews.
"""

import argparse
import asyncio
import contextlib
import dataclasses
import logging
import sys
from collections.abc import Sequence
from types import FrameType
from typing import NoReturn

import uvicorn
from fastapi import FastAPI
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sandfort.api.app import EGRESS_OVERRIDE_HINT, IsolationUnavailableError
from sandfort.api.app import create_app as build_app
from sandfort.api.app import create_worker_app as build_worker_app
from sandfort.api.deps import DRIVER_ATTR
from sandfort.api.wiring import (
    PREVIEW_TOKENS_ATTR,
    SESSION_FACTORY_ATTR,
    build_driver,
    sandbox_lookup,
)
from sandfort.clock import SystemClock
from sandfort.config import VALID_ROLES, Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.drivers.base import EndpointDriver
from sandfort.fd_limit import preview_descriptor_need, raise_open_file_limit
from sandfort.logging import configure_logging
from sandfort.preflight import ConfigurationError, check_preflight
from sandfort.proxy.app import MAX_KEEPALIVE
from sandfort.proxy.app import create_proxy_app as build_proxy_app
from sandfort.proxy.hygiene import install_log_redaction

__all__ = ["create_app", "create_proxy_app", "main"]

API_ROLES = ("all", "api")
CONFIGURATION_EXIT_CODE = 2
# The start-up failure code uvicorn exits with once the isolation gate has refused the start.
ISOLATION_EXIT_CODE = 3
# The reasons the gate puts before its findings (``api.app._refuse``).
REFUSAL_REASONS = (
    "host lacks required isolation capabilities",
    "prod configuration is not ready",
)
# The only separator ``refusal_lines`` splits on: the one ``api.app._refuse`` joins findings
# with. A test builds a real refusal and splits it with this constant, so drift shows up there.
FINDING_SEPARATOR = "; "

logger = logging.getLogger(__name__)
ACCESS_LOGGER = "uvicorn.access"


def _configure_logging(level: str) -> None:
    """JSON logging plus token redaction on uvicorn's loggers, for every server role.

    The API serves the pty connect websocket with ``?token=`` and uvicorn logs each handshake,
    so the redaction cannot wait for the preview proxy to be built.
    """
    configure_logging(level)
    install_log_redaction()


def create_app(settings: Settings | None = None) -> FastAPI:
    """The application with structured logging configured (the ``uvicorn --factory`` target)."""
    resolved = settings or Settings.from_env()
    check_preflight(resolved)  # before wiring: the secret box needs the webhook key
    _configure_logging(resolved.log_level)
    return build_app(resolved)


def _endpoint_driver(driver: object) -> EndpointDriver:
    if not isinstance(driver, EndpointDriver):
        raise TypeError(f"the {type(driver).__name__} driver cannot expose sandbox ports")
    return driver


def create_proxy_app(
    settings: Settings | None = None, *, api_app: FastAPI | None = None
) -> ASGIApp:
    """The preview proxy (the ``uvicorn --factory sandfort.main:create_proxy_app`` target).

    Given ``api_app`` it shares that application's database, driver and preview-token store.
    Standalone it opens its own engine and driver, and its token store is its own: tokens
    minted by a separate API process are not honoured there (public sandboxes still work).
    """
    resolved = settings or Settings.from_env()
    if api_app is not None:
        state = api_app.state
        return build_proxy_app(
            resolved,
            tokens=getattr(state, PREVIEW_TOKENS_ATTR),
            lookup=sandbox_lookup(getattr(state, SESSION_FACTORY_ATTR)),
            driver=_endpoint_driver(getattr(state, DRIVER_ATTR)),
        )
    _configure_logging(resolved.log_level)
    engine = create_engine(resolved)
    return build_proxy_app(
        resolved,
        lookup=sandbox_lookup(create_session_factory(engine)),
        driver=_endpoint_driver(build_driver(resolved, SystemClock())),
        on_shutdown=engine.dispose,
    )


class _LinkedServer(uvicorn.Server):
    """A server whose exit signal also stops its peers (the API and the proxy share a process)."""

    def __init__(self, config: uvicorn.Config) -> None:
        super().__init__(config)
        self.peers: list[uvicorn.Server] = []

    def handle_exit(self, sig: int, frame: FrameType | None) -> None:
        super().handle_exit(sig, frame)
        for peer in self.peers:
            peer.should_exit = True


def _config(app: ASGIApp, settings: Settings, port: int, *, access_log: bool) -> uvicorn.Config:
    return uvicorn.Config(
        app,
        host=settings.host,
        port=port,
        log_level=settings.log_level.lower(),
        log_config=None,  # uvicorn's loggers propagate to the JSON root handler
        access_log=access_log,
        proxy_headers=True,
        forwarded_allow_ips=settings.forwarded_allow_ips,
    )


async def _serve_together(*servers: _LinkedServer) -> None:
    for server in servers:
        server.peers = [peer for peer in servers if peer is not server]
    await asyncio.gather(*(server.serve() for server in servers))


def _serve_with_proxy(app: FastAPI, settings: Settings) -> None:
    """The API on ``port`` and the preview proxy on ``proxy_port``, in one event loop."""
    proxy_app = create_proxy_app(settings, api_app=app)
    # The API's telemetry middleware logs its requests, the proxy keeps uvicorn's access log.
    guarded = with_plain_refusal(app)
    api = _LinkedServer(_config(guarded, settings, settings.port, access_log=False))
    proxy = _LinkedServer(_config(proxy_app, settings, settings.proxy_port, access_log=True))
    # access_log=False on the API config turns propagation off on the shared access logger, so
    # the proxy's lines would reach no handler. Each server still checks its own access_log.
    logging.getLogger(ACCESS_LOGGER).propagate = True
    with contextlib.suppress(KeyboardInterrupt):  # uvicorn re-raises the signal it handled
        asyncio.run(_serve_together(api, proxy))


def _exit_with(findings: Sequence[str]) -> NoReturn:
    """One ``error:`` line per finding on stderr, then exit code 2 (no traceback)."""
    for finding in findings:
        print(f"error: {finding}", file=sys.stderr)
    raise SystemExit(CONFIGURATION_EXIT_CODE)


def refusal_lines(message: str) -> list[str]:
    """Plain stderr lines for an isolation gate refusal: the reason, each finding, the override.

    The gate joins its findings into one message after a fixed reason; a message with no such
    reason (the host capacity finding, the driver without a self-check) is one finding. The
    egress override hint that each prod probe finding carries is printed once, as its own line.
    """
    reason: str | None = None
    findings = [message]
    for known in REFUSAL_REASONS:
        if message.startswith(f"{known}: "):
            reason = known
            findings = message[len(known) + 2 :].split(FINDING_SEPARATOR)
            break
    lines = [] if reason is None else [f"error: {reason}"]
    hinted = False
    for finding in findings:
        if finding.endswith(EGRESS_OVERRIDE_HINT):
            finding = finding[: -len(EGRESS_OVERRIDE_HINT)]
            hinted = True
        lines.append(f"error: {finding}")
    if hinted:
        lines.append(f"override: {EGRESS_OVERRIDE_HINT.strip(' ()')}")
    return lines


def with_plain_refusal(app: ASGIApp) -> ASGIApp:
    """``app`` whose start-up isolation refusal reads like the preflight, without a traceback.

    The gate runs in the lifespan, where the framework would send the whole traceback to the
    server as one log line. This holds that failure message back; on an
    ``IsolationUnavailableError`` it prints the findings as plain lines on stderr, logs the
    exception at DEBUG only, and reports a failure with no message, so uvicorn logs just
    "Application startup failed" and exits with code 3. Any other failure is passed on as is.
    """

    async def guarded(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "lifespan":
            await app(scope, receive, send)
            return
        held: list[Message] = []

        async def hold_failure(message: Message) -> None:
            if message["type"] == "lifespan.startup.failed":
                held.append(message)
            else:
                await send(message)

        try:
            await app(scope, receive, hold_failure)
        except IsolationUnavailableError as error:
            if not held:
                raise
            logger.debug("the host isolation gate refused the start", exc_info=error)
            for line in refusal_lines(str(error)):
                print(line, file=sys.stderr)
            await send({"type": "lifespan.startup.failed", "message": ""})
            return
        except BaseException:
            for message in held:
                await send(message)
            raise
        for message in held:
            await send(message)

    return guarded


def _load_settings(args: argparse.Namespace) -> Settings:
    """The settings from the environment plus flags, past the preflight; else exit code 2."""
    try:
        base = Settings.from_env()
        overrides = {
            name: value
            for name, value in (("role", args.role), ("host", args.host), ("port", args.port))
            if value is not None
        }
        settings = dataclasses.replace(base, **overrides)
        check_preflight(settings)
    except ConfigurationError as error:
        _exit_with(error.findings)
    except ValueError as error:
        _exit_with(str(error).splitlines() or [type(error).__name__])
    return settings


def _preview_need(settings: Settings) -> int | None:
    """Descriptors the in-process preview proxy can hold (``fd_limit``), its keep-alive pool too.

    The pool is sized as ``PreviewProxy`` sizes it: the per-sandbox cap, else ``MAX_KEEPALIVE``.
    """
    keepalive = settings.preview_max_concurrent_per_sandbox or MAX_KEEPALIVE
    return preview_descriptor_need(settings.preview_max_concurrent, keepalive)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="sandfort-server", description="Sandfort API server.")
    parser.add_argument("--role", choices=VALID_ROLES, help="process role (env: SANDFORT_ROLE)")
    parser.add_argument("--host", help="bind address (default: SANDFORT_HOST)")
    parser.add_argument("--port", type=int, help="bind port (default: SANDFORT_PORT)")
    args = parser.parse_args(argv)
    settings = _load_settings(args)
    serves_previews = settings.role in API_ROLES and settings.proxy_enabled

    if settings.role in API_ROLES:
        app = create_app(settings)
    else:
        _configure_logging(settings.log_level)
        app = build_worker_app(settings)
    raise_open_file_limit(_preview_need(settings) if serves_previews else None)
    if serves_previews:
        _serve_with_proxy(app, settings)
        return
    uvicorn.run(
        with_plain_refusal(app),
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        log_config=None,  # uvicorn's loggers propagate to the JSON root handler
        access_log=False,  # the telemetry middleware logs one line per request
        proxy_headers=True,
        forwarded_allow_ips=settings.forwarded_allow_ips,
    )


if __name__ == "__main__":
    main()
