#!/usr/bin/env python3
"""Redaction timing at 1, 5, 20 and 100 KB (Phase 15.14). LOCAL BENCHMARK.

Times the two public redaction entry points - ``asic.observability.redaction.scrub_text``
(telemetry, audit, persisted spans and checkpoints) and ``deploy_release.redact`` (deployment
diagnostics) - over inputs shaped to defeat each pattern (long unbroken runs of the characters a
pattern backtracks over) and one realistic log line repeated. Prints the worst time per size and
the growth factor from 20 KB to 100 KB (about 5 for linear behaviour; a quadratic pattern shows
about 25). Pass ``--json PATH`` to also write the rows.

``scrub_text`` is timed with ``limit=None``-equivalent input sizes: its production default
truncates values first (``MAX_VALUE_CHARS``), so the figures here are the unbounded worst case.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from collections.abc import Callable
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

import deploy_release  # noqa: E402

from asic.observability import redaction  # noqa: E402

SIZES = (1_000, 5_000, 20_000, 100_000)
REALISTIC = (
    'level=error msg="db connect failed" dsn=postgresql://app:***@db:5432/asic '  # hygiene: synthetic-secret-fixture
    "authorization=Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig request_id=7f3a "  # hygiene: synthetic-secret-fixture
)
SHAPES: dict[str, Callable[[int], str]] = {
    "letters": lambda n: "a" * n,
    "dotted": lambda n: "a." * (n // 2),
    "dashed": lambda n: "a-" * (n // 2),
    "jwt-prefix": lambda n: "eyJ-" * (n // 4),
    "scheme-colon": lambda n: "a:" * (n // 2),
    "scheme-no-at": lambda n: "a://" + "b" * (n - 4),
    "password-run": lambda n: "passwor" * (n // 7),
    "bearer-run": lambda n: "bearer " * (n // 7),
    "query-run": lambda n: "?token=" * (n // 7),
    "realistic-log": lambda n: (REALISTIC * (n // len(REALISTIC) + 1))[:n],
}


def _time(fn: Callable[[str], object], text: str, repeat: int = 3) -> float:
    best = float("inf")
    for _ in range(repeat):
        started = time.perf_counter()
        fn(text)
        best = min(best, time.perf_counter() - started)
    return best


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    targets: dict[str, Callable[[str], object]] = {
        "scrub_text": lambda text: redaction.scrub_text(text, limit=len(text) + 1),
        "deploy_redact": deploy_release.redact,
    }
    rows = []
    for target, fn in targets.items():
        for size in SIZES:
            worst_shape, worst = max(
                ((shape, _time(fn, make(size))) for shape, make in SHAPES.items()),
                key=lambda item: item[1],
            )
            rows.append(
                {
                    "target": target,
                    "bytes": size,
                    "worst_ms": round(worst * 1000, 2),
                    "shape": worst_shape,
                }
            )
    print(f"LOCAL BENCHMARK - Python {platform.python_version()} on {platform.platform()}")
    print(f"{'target':14} {'size':>8} {'worst ms':>10}  worst shape")
    for row in rows:
        print(f"{row['target']:14} {row['bytes']:>8} {row['worst_ms']:>10.2f}  {row['shape']}")
    for target in targets:
        by_size = {r["bytes"]: r["worst_ms"] for r in rows if r["target"] == target}
        growth = by_size[100_000] / max(by_size[20_000], 0.01)
        print(f"{target}: 20 KB -> 100 KB growth x{growth:.1f} (linear ~5, quadratic ~25)")
    if args.json:
        args.json.write_text(json.dumps(rows, indent=2), "utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
