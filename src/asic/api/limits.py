"""Request-shape bounds enforced before any route code runs (Phase 13, ADR-0030).

Two properties, both applied at the ASGI edge so that no handler (including one that reads
the raw body itself, like ingestion) can be handed an unbounded or wrongly-typed request:

* **Bounded body.** Declared ``Content-Length`` above the ceiling is refused with 413
  without reading anything. A body with no declared length (chunked) is counted as it
  streams and refused the moment it crosses the ceiling. The ceiling is 128 KiB: twice the
  64 KiB ingestion contract ceiling (``asic.ingestion.contracts``) to leave room for JSON
  escaping, and far above every other request (the largest human-authored field is a
  4,000-character justification).
* **JSON only.** A mutating request that carries a body must be ``application/json``;
  anything else is 415. (A bodyless request is left to authentication and authorization.)
  The API has no form, multipart or XML surface, so accepting one would only add parsers.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any, Final

# Minimal ASGI type aliases, structurally identical to Starlette's. Defined here so the module
# needs no direct dependency on Starlette (it is only a transitive dependency of FastAPI).
Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

MAX_REQUEST_BODY_BYTES: Final[int] = 128 * 1024
_BODY_METHODS: Final[frozenset[str]] = frozenset({"POST", "PUT", "PATCH"})


def _media_type(headers: list[tuple[bytes, bytes]]) -> str:
    for name, value in headers:
        if name == b"content-type":
            return value.decode("latin-1").split(";", 1)[0].strip().lower()
    return ""


def _content_length(headers: list[tuple[bytes, bytes]]) -> int | None:
    for name, value in headers:
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return -1
    return None


class _TooLarge(Exception):
    pass


class RequestBoundsMiddleware:
    def __init__(self, app: ASGIApp, *, max_body_bytes: int = MAX_REQUEST_BODY_BYTES) -> None:
        self._app = app
        self._max = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        headers: list[tuple[bytes, bytes]] = list(scope.get("headers", []))
        method = scope.get("method", "GET")
        declared = _content_length(headers)
        if declared is not None and (declared < 0 or declared > self._max):
            await self._reject(send, 413, "payload_too_large", "request body is too large")
            return
        has_body = (declared or 0) > 0 or any(name == b"transfer-encoding" for name, _ in headers)
        if method in _BODY_METHODS and has_body and _media_type(headers) != "application/json":
            await self._reject(
                send, 415, "unsupported_media_type", "Content-Type must be application/json"
            )
            return

        received = 0
        exceeded = False
        started = False

        async def bounded_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self._max:
                    exceeded = True
                    raise _TooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if exceeded:
                # The framework may have swallowed the abort and produced its own error
                # (FastAPI turns a body-read failure into a 400). The truth is "too large":
                # answer that, exactly once, and drop whatever the app tries to send.
                if not started:
                    started = True
                    await self._reject(send, 413, "payload_too_large", "request body is too large")
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        with contextlib.suppress(_TooLarge):
            await self._app(scope, bounded_receive, tracking_send)
        if exceeded and not started:
            await self._reject(send, 413, "payload_too_large", "request body is too large")

    @staticmethod
    async def _reject(send: Send, status: int, code: str, message: str) -> None:
        body: dict[str, Any] = {"detail": {"code": code, "message": message}}
        payload = json.dumps(body).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload})


__all__ = ["MAX_REQUEST_BODY_BYTES", "RequestBoundsMiddleware"]
