"""Untrusted operational content: labelling, delimiting, and injection detection.

Master specification section 15 requires that logs, runbooks and tickets be treated as
potentially untrusted, and that retrieved text never override system policy or tool
authorization. This module carries the *handling*; it is deliberately not the defence.

The defence is structural and lives elsewhere:

* the capability menu is resolved before a model is invoked, so a model cannot ask for a
  capability it was not granted (``asic.tools.capability``);
* tool scope is resolved from incident context, never read from an argument
  (``asic.tools.broker``);
* the broker's request type has no field that can carry free text into an authorization
  decision.

Detection here is a *signal* - recorded on the evidence row, emitted as
``content.injection_flagged``, counted as a metric - and never a gate. A detector that
were the gate would fail the moment an attacker phrased the instruction differently,
which is precisely why SEC-I5 requires the resistance to be structural.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

from asic.domain.enums import ProvenanceLabel
from asic.domain.errors import ProvenanceViolation

#: Named patterns, so a flag says *which* shape was seen rather than merely "suspicious".
#: The list is illustrative of known families and is expected to be incomplete - see the
#: module docstring for why that is acceptable here and would not be acceptable as a gate.
_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "instruction_override",
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}?"
            r"\b(?:previous|prior|earlier|above|all)\b[^.\n]{0,20}?"
            r"\b(?:instruction|instructions|prompt|prompts|rule|rules|policy|policies)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "role_reassignment",
        re.compile(
            r"\byou\s+are\s+now\b|\bact\s+as\s+(?:a|an|the)\b|\bnew\s+system\s+prompt\b",
            re.IGNORECASE,
        ),
    ),
    (
        "authorization_claim",
        re.compile(
            r"\b(?:this\s+is\s+)?(?:pre-?)?(?:approved|authori[sz]ed|permitted|sanctioned)\b"
            r"[^.\n]{0,40}?\b(?:by|from)\b[^.\n]{0,30}?"
            r"\b(?:admin|administrator|sre|security|oncall|on-call|management)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "capability_grant_attempt",
        re.compile(
            r"\b(?:grant|enable|allow|escalate|elevate|unlock)\b[^.\n]{0,40}?"
            r"\b(?:capability|capabilities|permission|permissions|privilege|privileges|"
            r"access|tool|tools)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "approval_bypass",
        re.compile(
            r"\b(?:skip|bypass|no\s+need\s+for|without)\b[^.\n]{0,30}?"
            r"\b(?:approval|approvals|human\s+review|confirmation|policy\s+gate)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "command_injection",
        re.compile(
            r"(?:^|[\s`;|])(?:kubectl|helm|curl|wget|bash|sh|psql|aws|gcloud|az)\s+\S",
            re.IGNORECASE,
        ),
    ),
    (
        "delimiter_escape",
        re.compile(
            r"(?:```|</?(?:system|assistant|user|untrusted)[^>]*>|\[/?INST\]|<\|[a-z_]+\|>)",
            re.IGNORECASE,
        ),
    ),
    (
        "tenant_context_claim",
        re.compile(r"\btenant[_\s-]?id\b\s*[:=]", re.IGNORECASE),
    ),
)

#: Opening and closing markers for an untrusted region inside a prompt. They are stripped
#: from the content itself (see :func:`_neutralise`) so a payload cannot forge a close.
_BLOCK_OPEN: Final[str] = "<<<UNTRUSTED_DATA"
_BLOCK_CLOSE: Final[str] = "UNTRUSTED_DATA>>>"

_MARKER_LIKE: Final[re.Pattern[str]] = re.compile(
    r"<<<\s*UNTRUSTED_DATA|UNTRUSTED_DATA\s*>>>", re.IGNORECASE
)


def scan(text: str) -> tuple[str, ...]:
    """Names of the injection patterns present in ``text``, in declaration order."""
    return tuple(name for name, pattern in _PATTERNS if pattern.search(text))


def scan_structure(value: object) -> tuple[str, ...]:
    """Scan every string reachable inside a nested structure.

    Tool results are JSON-shaped, and an injection payload is as likely to arrive in a log
    line nested three levels down as at the top level.
    """
    found: list[str] = []
    _walk(value, found)
    seen: set[str] = set()
    ordered: list[str] = []
    for name, _ in _PATTERNS:
        if name in found and name not in seen:
            seen.add(name)
            ordered.append(name)
    return tuple(ordered)


def _walk(value: object, found: list[str]) -> None:
    if isinstance(value, str):
        found.extend(scan(value))
    elif isinstance(value, dict):
        for key, item in value.items():
            found.extend(scan(str(key)))
            _walk(item, found)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _walk(item, found)


def _neutralise(text: str) -> str:
    """Remove anything that could impersonate our own block markers."""
    return _MARKER_LIKE.sub("[redacted-marker]", text)


@dataclass(frozen=True, slots=True)
class UntrustedBlock:
    """One region of content that arrived from outside our trust boundary."""

    #: Where it came from: ``logs:checkout-api``, ``knowledge:runbook-42``.
    source: str
    provenance: ProvenanceLabel
    content: str

    def __post_init__(self) -> None:
        if self.provenance.confers_authority:
            raise ProvenanceViolation(
                f"an untrusted block cannot carry provenance {self.provenance.value!r}: "
                "authority flows only from SYSTEM and HUMAN (SEC-I4)"
            )

    @property
    def injection_flags(self) -> tuple[str, ...]:
        return scan(self.content)


def render_untrusted(blocks: Sequence[UntrustedBlock]) -> str:
    """Render untrusted content into a prompt as *data*, never as instruction.

    Three properties make this safe to call with hostile input:

    1. Every block is fenced by markers, and any marker-like text inside the content is
       replaced first, so a payload cannot close the fence early and escape into the
       instruction position.
    2. Each fence names the source and the provenance label, so the surrounding template
       can state - once, in the system position - that the enclosed text is operational
       data to be analysed and never obeyed.
    3. The function returns a string that callers place in a dedicated data slot. There is
       no code path that concatenates untrusted content into the instruction slot, which
       is what makes this structural rather than a request politely made of the model.
    """
    if not blocks:
        return f"{_BLOCK_OPEN} count=0 {_BLOCK_CLOSE}"
    rendered: list[str] = []
    for index, block in enumerate(blocks, start=1):
        flags = ",".join(block.injection_flags) or "none"
        rendered.append(
            f"{_BLOCK_OPEN} index={index} source={block.source!r} "
            f"provenance={block.provenance.value} injection_flags={flags}\n"
            f"{_neutralise(block.content)}\n"
            f"{_BLOCK_CLOSE}"
        )
    return "\n".join(rendered)


def assert_confers_authority(provenance: ProvenanceLabel, *, what: str) -> None:
    """Guard an authorization path against untrusted provenance.

    Raises:
        ProvenanceViolation: if ``provenance`` is not ``SYSTEM`` or ``HUMAN``.
    """
    if not provenance.confers_authority:
        raise ProvenanceViolation(
            f"{what} was offered with provenance {provenance.value!r}; authority flows "
            "only from SYSTEM and HUMAN provenance (SEC-I4, SI-3)"
        )


def flagged_sources(blocks: Iterable[UntrustedBlock]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """``(source, flags)`` for every block in which something was detected."""
    return tuple((b.source, b.injection_flags) for b in blocks if b.injection_flags)


__all__ = [
    "UntrustedBlock",
    "assert_confers_authority",
    "flagged_sources",
    "render_untrusted",
    "scan",
    "scan_structure",
]
