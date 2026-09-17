"""Structured, redacted, Loki-friendly logging.

One JSON object per line, with a fixed envelope (``ts``, ``level``, ``logger``, ``event``,
``service``) plus the active ``trace_id``/``span_id`` so a log line joins its trace. Rules
from ``docs/architecture/observability.md`` section 6, enforced at emission:

* **Redaction before the record leaves the process.** Every field passes through
  :func:`asic.observability.redaction.redact_mapping` - secret-named keys are replaced and
  secret-shaped values are replaced whatever their key - and the message itself is checked.
* **No multi-line records.** JSON encoding escapes newlines, so a hostile log excerpt cannot
  forge a second record.
* **Identifiers are fields, never Loki labels.** The shipped collector configuration labels
  streams only by service, environment and level; tenant and incident ids stay in the body
  where they are queryable but add no stream cardinality.
* **No prompt or completion bodies, no exception text from untrusted sources.** Callers pass
  typed, bounded fields; :func:`log_event` records an exception's type, not its message.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from datetime import UTC, datetime
from typing import Any, Final, TextIO

from opentelemetry import trace as otel_trace

from asic.observability.redaction import REDACTED, looks_like_secret, redact_mapping

_RESERVED: Final[frozenset[str]] = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__)
_ENVELOPE: Final[tuple[str, ...]] = ("ts", "level", "logger", "event", "service")
#: Longest message retained.
MAX_MESSAGE_CHARS: Final[int] = 512


class JsonFormatter(logging.Formatter):
    def __init__(self, *, service: str) -> None:
        super().__init__()
        self._service = service

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        if looks_like_secret(message):
            message = REDACTED
        fields = {
            key: value
            for key, value in record.__dict__.items()
            if key not in _RESERVED and not key.startswith("_")
        }
        body: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": str(fields.pop("event", message))[:128],
            "service": self._service,
        }
        if message and message != body["event"]:
            body["message"] = message[:MAX_MESSAGE_CHARS]
        context = otel_trace.get_current_span().get_span_context()
        if context.is_valid:
            body["trace_id"] = format(context.trace_id, "032x")
            body["span_id"] = format(context.span_id, "016x")
        if record.exc_info and record.exc_info[0] is not None:
            body["error_type"] = record.exc_info[0].__name__
        for key, value in redact_mapping(fields).items():
            if key not in body:
                body[key] = value
        return json.dumps(body, default=str, separators=(",", ":"), ensure_ascii=True)


_lock = threading.Lock()
_configured = False


def configure_logging(
    *, service: str, level: str = "INFO", stream: TextIO | None = None
) -> logging.Handler:
    """Route the ``asic`` logger hierarchy to one JSON handler. Idempotent per process."""
    global _configured
    root = logging.getLogger("asic")
    with _lock:
        if _configured:
            return root.handlers[0]
        handler = logging.StreamHandler(stream or sys.stdout)
        handler.setFormatter(JsonFormatter(service=service))
        root.handlers = [handler]
        root.setLevel(level.upper())
        root.propagate = False
        _configured = True
        return handler


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.INFO,
    error: BaseException | None = None,
    **fields: Any,
) -> None:
    """Emit one structured event. ``error`` contributes its type only, never its message."""
    if not logger.isEnabledFor(level):
        return
    extra: dict[str, Any] = {"event": event, **fields}
    if error is not None:
        extra["error_type"] = type(error).__name__
    logger.log(level, event, extra={k: v for k, v in extra.items() if k not in _RESERVED})


__all__ = ["MAX_MESSAGE_CHARS", "JsonFormatter", "configure_logging", "log_event"]
