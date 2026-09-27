"""A controllable TCP fault proxy for resilience tests (test infrastructure only).

Sits between a client (the application's database engine, an adapter) and a real server and
injects the network faults Phase 15 needs to observe, without touching the host network or
the server itself:

* ``PASS``    - forward bytes both ways;
* ``REFUSE``  - accept and immediately close new connections (a dead endpoint, fast failure);
* ``LATENCY`` - forward, delaying every chunk by ``latency`` seconds (a slow dependency);
* ``sever()`` - kill every established connection now (a restart / connection loss).

Every thread is a daemon and ``close()`` releases the listener, so a failing test cannot leave
a fault behind (Phase 15.30 cleanup).
"""

from __future__ import annotations

import contextlib
import enum
import socket
import threading
import time
from types import TracebackType


class Mode(enum.Enum):
    PASS = "pass"
    REFUSE = "refuse"
    LATENCY = "latency"


class FaultProxy:
    def __init__(self, target_host: str, target_port: int) -> None:
        self.target = (target_host, target_port)
        self.mode = Mode.PASS
        self.latency = 0.0
        self.accepted = 0
        self.refused = 0
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(128)
        self.port = self._listener.getsockname()[1]
        self._pairs: set[tuple[socket.socket, socket.socket]] = set()
        self._lock = threading.Lock()
        self._closed = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    # ------------------------------------------------------------------ control
    def set(self, mode: Mode, *, latency: float = 0.0) -> None:
        self.mode, self.latency = mode, latency

    def sever(self) -> int:
        """Close every established connection; returns how many were cut."""
        with self._lock:
            pairs, self._pairs = self._pairs, set()
        for client, upstream in pairs:
            for sock in (client, upstream):
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)
                sock.close()
        return len(pairs)

    def active(self) -> int:
        with self._lock:
            return len(self._pairs)

    def close(self) -> None:
        self._closed.set()
        self.sever()
        self._listener.close()

    def __enter__(self) -> FaultProxy:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # ------------------------------------------------------------------ internals
    def _accept(self) -> None:
        while not self._closed.is_set():
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            if self.mode is Mode.REFUSE:
                self.refused += 1
                client.close()
                continue
            try:
                upstream = socket.create_connection(self.target, timeout=5)
            except OSError:
                client.close()
                continue
            upstream.settimeout(None)
            self.accepted += 1
            pair = (client, upstream)
            with self._lock:
                self._pairs.add(pair)
            threading.Thread(target=self._pump, args=(client, upstream, pair), daemon=True).start()
            threading.Thread(target=self._pump, args=(upstream, client, pair), daemon=True).start()

    def _pump(
        self,
        source: socket.socket,
        sink: socket.socket,
        pair: tuple[socket.socket, socket.socket],
    ) -> None:
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                if self.mode is Mode.LATENCY and self.latency:
                    time.sleep(self.latency)
                sink.sendall(data)
        except OSError:
            pass
        finally:
            with self._lock:
                self._pairs.discard(pair)
            for sock in pair:
                with contextlib.suppress(OSError):
                    sock.close()


__all__ = ["FaultProxy", "Mode"]
