"""An in-process HTTP transport that answers from fixtures. Evaluation infrastructure only.

Used where an evaluation scenario must exercise the *native* adapter path - connector scope,
credential resolution, broker authority - without any network. It never pretends to be a
vendor: it answers only the fixture it was built with, counts every request it received,
and refuses to exist in a production deployment.
"""

from __future__ import annotations

import json
import ssl
import threading
from typing import Any

from asic.integrations.credentials import is_production_deployment
from asic.integrations.transport import DEFAULT_MAX_RESPONSE_BYTES, HttpRequest, HttpResponse


class FixtureTransport:
    def __init__(self, status: int, body: Any) -> None:
        if is_production_deployment():
            raise RuntimeError("fixture transport cannot run in a production deployment")
        self._status = status
        self._body = json.dumps(body).encode("utf-8")
        self._lock = threading.Lock()
        self._calls = 0

    @classmethod
    def prometheus_ok(cls) -> FixtureTransport:
        return cls(200, {"status": "success", "data": {"resultType": "matrix", "result": []}})

    @property
    def calls(self) -> int:
        return self._calls

    def send(
        self,
        request: HttpRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        ssl_context: ssl.SSLContext | None = None,
    ) -> HttpResponse:
        with self._lock:
            self._calls += 1
        return HttpResponse(status=self._status, headers={}, body=self._body)


__all__ = ["FixtureTransport"]
