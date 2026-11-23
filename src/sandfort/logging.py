"""Structured JSON logging with request correlation (WP 4.5).

``configure_logging`` installs one handler on the root logger that writes one JSON object per
line: ``timestamp`` (UTC, ISO 8601), ``level``, ``logger``, ``message``, ``request_id`` while a
request is being served, ``exception`` when one is attached, and the ``extra=`` fields the call
site passed. The request id lives in a context variable that the request-id middleware binds,
so every line logged while serving a request carries it without any plumbing.
"""

import json
import logging
import sys
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from typing import IO, Any

HANDLER_NAME = "sandfort-json"

_REQUEST_ID: ContextVar[str | None] = ContextVar("sandfort_request_id", default=None)
_CLIENT_IP: ContextVar[str | None] = ContextVar("sandfort_client_ip", default=None)
_USER_AGENT: ContextVar[str | None] = ContextVar("sandfort_user_agent", default=None)
# Attributes every LogRecord carries; anything else on a record came in through ``extra=``.
_RECORD_ATTRS = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
    "message",
    "asctime",
}


def current_request_id() -> str | None:
    """The id of the request being served in this context, if any."""
    return _REQUEST_ID.get()


def bind_request_id(request_id: str) -> Token[str | None]:
    return _REQUEST_ID.set(request_id)


def reset_request_id(token: Token[str | None]) -> None:
    _REQUEST_ID.reset(token)


def current_client_ip() -> str | None:
    """The client ip of the request being served in this context, if any."""
    return _CLIENT_IP.get()


def bind_client_ip(client_ip: str | None) -> Token[str | None]:
    return _CLIENT_IP.set(client_ip)


def reset_client_ip(token: Token[str | None]) -> None:
    _CLIENT_IP.reset(token)


def current_user_agent() -> str | None:
    """The user agent of the request being served in this context, if any."""
    return _USER_AGENT.get()


def bind_user_agent(user_agent: str | None) -> Token[str | None]:
    return _USER_AGENT.set(user_agent)


def reset_user_agent(token: Token[str | None]) -> None:
    _USER_AGENT.reset(token)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        document: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = _REQUEST_ID.get()
        if request_id is not None:
            document["request_id"] = request_id
        for key, value in vars(record).items():
            if key not in _RECORD_ATTRS and key not in document:
                document[key] = value
        if record.exc_info:
            document["exception"] = self.formatException(record.exc_info)
        return json.dumps(document, default=str)


def configure_logging(level: str = "INFO", *, stream: IO[str] | None = None) -> logging.Handler:
    """Route the root logger through one JSON handler; calling it again replaces that handler."""
    root = logging.getLogger()
    for existing in list(root.handlers):
        if existing.get_name() == HANDLER_NAME:
            root.removeHandler(existing)
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.set_name(HANDLER_NAME)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())
    return handler
