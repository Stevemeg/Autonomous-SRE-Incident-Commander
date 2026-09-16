"""A deterministic local HTTP server: explicit test infrastructure, never a vendor.

It stands in for Prometheus, Loki, the Kubernetes API, Slack, Teams, PagerDuty, Jira and
Grafana by answering scripted responses on a loopback port and recording every request it
received. Passing tests against it prove request construction, parsing, failure
classification and broker behaviour. They do **not** prove compatibility with any live
vendor deployment, and nothing in this repository claims they do.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit


@dataclass(frozen=True)
class Recorded:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


@dataclass
class Scripted:
    status: int = 200
    body: Any = None
    raw: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)
    #: Seconds to stall *after* reading the request, before answering.
    delay: float = 0.0
    #: Close the socket after reading the request, without answering.
    drop: bool = False


Route = tuple[str, str]  # (method, path)


class LocalHttpServer:
    def __init__(self) -> None:
        self.requests: list[Recorded] = []
        self._routes: dict[Route, deque[Scripted] | Callable[[Recorded], Scripted]] = {}
        self._lock = threading.Lock()
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                parts = urlsplit(self.path)
                recorded = Recorded(
                    method=self.command,
                    path=parts.path,
                    query=parse_qs(parts.query),
                    headers={k.lower(): v for k, v in self.headers.items()},
                    body=body,
                )
                scripted = server._next(recorded)
                if scripted.delay:
                    time.sleep(scripted.delay)
                if scripted.drop:
                    self.close_connection = True
                    self.connection.close()
                    return
                payload = (
                    scripted.raw
                    if scripted.raw is not None
                    else (b"" if scripted.body is None else json.dumps(scripted.body).encode())
                )
                self.send_response(scripted.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                for name, value in scripted.headers.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(payload)

            do_GET = _handle  # noqa: N815
            do_POST = _handle  # noqa: N815
            do_PATCH = _handle  # noqa: N815
            do_PUT = _handle  # noqa: N815

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def route(self, method: str, path: str, *responses: Scripted) -> None:
        with self._lock:
            self._routes[(method, path)] = deque(responses)

    def handler(self, method: str, path: str, fn: Callable[[Recorded], Scripted]) -> None:
        with self._lock:
            self._routes[(method, path)] = fn

    def _next(self, recorded: Recorded) -> Scripted:
        with self._lock:
            self.requests.append(recorded)
            entry = self._routes.get((recorded.method, recorded.path))
            if entry is None:
                return Scripted(status=404, body={"error": "no route"})
            if callable(entry):
                return entry(recorded)
            if len(entry) > 1:
                return entry.popleft()
            return entry[0] if entry else Scripted(status=500)

    def calls(self, method: str, path: str) -> list[Recorded]:
        return [r for r in self.requests if r.method == method and r.path == path]

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@contextmanager
def local_server() -> Iterator[LocalHttpServer]:
    server = LocalHttpServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()
