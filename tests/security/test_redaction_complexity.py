"""Redaction runs in linear time and detects exactly what it detected before (Phase 15).

Two redaction layers see untrusted or tool-produced text: telemetry/audit redaction
(``asic.observability.redaction``) and deployment diagnostics (``scripts/deploy_release``).
Four of their patterns were quadratic on long unbroken runs - measured before the fix at
7 s (DSN rule) and 51 s (key=value rule) for 20 KB of ``a.a.a...`` - so a hostile log line or
a large kubectl error could stall a worker. The rewritten patterns are checked two ways:

* **scaling**: 100 KB adversarial inputs, each shaped to defeat one pattern, finish within a
  generous absolute bound (a quadratic pattern needs minutes at that size);
* **equivalence**: over a seeded corpus of short strings drawn from the characters the
  patterns care about, the new patterns decide exactly like the original ones (kept here
  verbatim as the reference). Speed was not bought with weaker detection.
"""

from __future__ import annotations

import random
import re
import time
from collections.abc import Callable

import pytest
from scripts import deploy_release

from asic.observability import redaction

pytestmark = pytest.mark.security

#: The original (pre-Phase-15) forms, used only as a behavioural reference on short input.
_REFERENCE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_REFERENCE_URL_CREDENTIALS = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]+@")
_REFERENCE_SECRET_KEY = r"[\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)"
_REFERENCE_DEPLOY = (
    (re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+@"), r"\1***@"),
    deploy_release._REDACTIONS[1],
    deploy_release._REDACTIONS[2],
    (
        re.compile(
            rf"(?i)(\b{_REFERENCE_SECRET_KEY}[\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;&}}\]]+)"
        ),
        r"\1***",
    ),
)

ADVERSARIAL: dict[str, Callable[[int], str]] = {
    "letters": lambda n: "a" * n,
    "dotted": lambda n: "a." * (n // 2),
    "dashed": lambda n: "a-" * (n // 2),
    "jwt-starts": lambda n: "eyJ-" * (n // 4),
    "jwt-no-third": lambda n: "eyJ" + "a" * (n // 2) + "." + "b" * (n // 2),
    "scheme-no-at": lambda n: "a://" + "b" * (n - 4),
    "scheme-runs": lambda n: "a+b.c-" * (n // 6) + "://x",
    "key-runs": lambda n: "passwor" * (n // 7),
    "key-dotted": lambda n: "x.password" * (n // 10),
    "bearer": lambda n: "bearer " * (n // 7),
    "colons": lambda n: "a:" * (n // 2),
}
SIZES = (1_000, 5_000, 20_000, 100_000)
#: Linear redaction of 100 KB takes milliseconds; the quadratic forms took minutes.
BOUND_SECONDS = 1.0


def _elapsed(function: Callable[[str], object], text: str) -> float:
    started = time.perf_counter()
    function(text)
    return time.perf_counter() - started


@pytest.mark.parametrize("shape", sorted(ADVERSARIAL))
def test_telemetry_redaction_is_linear(shape: str) -> None:
    for size in SIZES:
        text = ADVERSARIAL[shape](size)
        assert _elapsed(redaction.redact_value, text) < BOUND_SECONDS, (shape, size)


@pytest.mark.parametrize("shape", sorted(ADVERSARIAL))
def test_deployment_redaction_is_linear(shape: str) -> None:
    for size in SIZES:
        text = ADVERSARIAL[shape](size)
        assert _elapsed(deploy_release.redact, text) < BOUND_SECONDS, (shape, size)


def test_bounded_diagnostics_of_a_huge_error_are_fast() -> None:
    # kubectl can print megabytes on a bad apply; bounding happens after redaction.
    text = "x.token" * 150_000
    assert _elapsed(deploy_release.bounded, text) < BOUND_SECONDS * 2


def _corpus(pieces: tuple[str, ...], count: int, seed: int) -> list[str]:
    """Strings assembled from the pieces a pattern distinguishes, so positives, near misses
    and every boundary between them occur densely (single random characters almost never
    form a secret shape)."""
    rng = random.Random(seed)
    return ["".join(rng.choice(pieces) for _ in range(rng.randint(1, 12))) for _ in range(count)]


_JWT_PIECES = ("eyJ", "eyJ", "aaaaa", "bbbbbbbbbb", "0", "_", "-", ".", ".", " ", '"', "=", "J")
_URL_PIECES = ("a", "https", "9", "+", ".", "-", "://", ":", "/", "@", "u", "p", " ", "X", "s")
_DEPLOY_PIECES = (
    "password",
    "PGPASSWORD",
    "token",
    "api_key",
    "access-key",
    "db.",
    "x",
    "-",
    "_",
    "=",
    ": ",
    " ",
    '"',
    "'",
    ",",
    ";",
    "}",
    "postgres",
    "://",
    "u:p",
    "@",
    "host",
    "9",
    "--",
    "Authorization: Bearer ",
    "abc",
)


def _structured(template: tuple[tuple[str, ...], ...], count: int, seed: int) -> list[str]:
    """Near-miss and positive candidates: one random choice per slot of ``template``."""
    rng = random.Random(seed)
    return ["".join(rng.choice(slot) for slot in template) for _ in range(count)]


_SEGMENTS = ("", "a" * 5, "b" * 9, "c" * 10, "d" * 14, "e-f_g" * 3, "eyJ")
_JWT_TEMPLATE = (
    ("", " ", "-", "_", "x", "eyJ-", "a.", '"', "="),
    ("eyJ", "eyJ", "ey", "EyJ"),
    _SEGMENTS,
    (".", ".", "-", ""),
    _SEGMENTS,
    (".", ".", " "),
    _SEGMENTS,
)
_URL_TEMPLATE = (
    ("", " ", "x", ".", "9", "-", "_"),
    ("https", "9pg", "a-b", "+x", "", "X", "ab.c", "s3+x"),
    ("://", "://", ":/", "//"),
    ("u", "", "u/v", "u@", "user"),
    (":", ":", ""),
    ("p", "", "p:q", "p w", "pw"),
    ("@", "@", ""),
)


def test_jwt_detection_is_unchanged() -> None:
    new = redaction._SECRET_SHAPED[1]
    samples = _corpus(_JWT_PIECES, 20_000, 1501)
    samples += _structured(_JWT_TEMPLATE, 20_000, 1504)
    samples += ["x eyJhbGciOiJ.eyJzdWIiOiJ.c2lnbmF0dXJl", "_eyJaaaaaaaaaa.bbbbbbbbbb.cccccccccc"]
    samples += [
        "-eyJaaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc",
        "eyJ-eyJaaaaaaaaaa.bbbbbbbbbb.cccccccccc",
    ]
    for sample in samples:
        assert bool(new.search(sample)) == bool(_REFERENCE_JWT.search(sample)), sample
    # The corpus must actually contain positives, or equivalence would be vacuous.
    assert sum(bool(_REFERENCE_JWT.search(s)) for s in samples) >= 200


def test_url_credential_detection_is_unchanged() -> None:
    new = redaction._SECRET_SHAPED[4]
    samples = _corpus(_URL_PIECES, 20_000, 1502)
    samples += _structured(_URL_TEMPLATE, 20_000, 1505)
    samples += ["9postgres://u:p@h", "x.https://u:p@h", "HTTPS://u:p@h", "a-b+c.d://u:p@h"]
    for sample in samples:
        assert bool(new.search(sample)) == bool(_REFERENCE_URL_CREDENTIALS.search(sample)), sample
    assert sum(bool(_REFERENCE_URL_CREDENTIALS.search(s)) for s in samples) >= 200


def _apply(rules: object, text: str) -> str:
    for pattern, replacement in rules:  # type: ignore[attr-defined]
        text = pattern.sub(replacement, text)
    return text


def test_deployment_redaction_output_is_unchanged() -> None:
    samples = _corpus(_DEPLOY_PIECES, 40_000, 1503)
    samples += [
        "PGPASSWORD=s3cret psql",
        "postgresql+psycopg2://owner:pw@db/asic",
        "9postgres://u:p@h",
        '{"api_key": "abc", "x.password": \'q\'}',
        "--password hunter2 --token=abc",
        "Authorization: Bearer abc.def",
        "db.password: x, other.token=y;",
    ]
    changed = 0
    for sample in samples:
        expected = _apply(_REFERENCE_DEPLOY, sample)
        assert deploy_release.redact(sample) == expected, sample
        changed += expected != sample
    assert changed >= 5_000  # the corpus exercises real redactions
