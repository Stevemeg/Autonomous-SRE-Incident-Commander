"""Phase 15.4/15.10: an unavailable OTLP collector never degrades the product.

Telemetry is best-effort by design (ADR-0029): spans are exported by a background
``BatchSpanProcessor`` whose queue is bounded (2048 spans; the rest are dropped). The
invariants checked here with the exporter class production composes, pointed at a closed
port:

* creating spans never waits on the network (the request path is not coupled to export);
* memory stays bounded however many spans are produced while the collector is down;
* the exporter gives up within its own deadline, so shutdown is bounded by it.

Observed (recorded in docs/testing/RESILIENCE_AND_CHAOS.md): with the default 10 s exporter
timeout a full queue drains in tens of seconds at shutdown, i.e. a pod stopping during a
collector outage may use its whole termination grace period and lose those spans. The
``OTEL_EXPORTER_OTLP_TIMEOUT`` setting bounds that; losing spans is acceptable, blocking is not.
"""

from __future__ import annotations

import gc
import socket
import time
import tracemalloc

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def _closed_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def test_collector_outage_never_blocks_span_creation_and_memory_is_bounded() -> None:
    exporter = OTLPSpanExporter(endpoint=f"http://127.0.0.1:{_closed_port()}/v1/traces", timeout=1)
    provider = TracerProvider(shutdown_on_exit=False)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    tracer = provider.get_tracer("asic.resilience")

    def emit(count: int) -> float:
        slowest = 0.0
        for index in range(count):
            begun = time.perf_counter()
            with tracer.start_as_current_span("api.request") as span:
                span.set_attribute("n", index)
            slowest = max(slowest, time.perf_counter() - begun)
        return slowest

    started = time.perf_counter()
    slowest = emit(30_000)
    # 30k spans in far less time than a single blocked export would take.
    assert time.perf_counter() - started < 10.0
    assert slowest < 0.5
    # Bounded queue: once it is full, further spans while the collector is down are dropped,
    # so memory does not grow with the outage's length.
    tracemalloc.start()
    try:
        emit(4_000)
        gc.collect()
        filled, _ = tracemalloc.get_traced_memory()
        emit(8_000)
        gc.collect()
        middle, _ = tracemalloc.get_traced_memory()
        emit(8_000)
        gc.collect()
        after, _ = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # An unbounded queue would retain ~16k more spans (tens of MiB) across the two rounds.
    assert after - filled < 6 * 1024 * 1024, f"grew {after - filled} bytes"
    assert after - middle < 3 * 1024 * 1024, f"grew {after - middle} bytes in the last round"
    started = time.perf_counter()
    provider.shutdown()
    assert time.perf_counter() - started < 20.0  # bounded by the exporter deadline x batches
