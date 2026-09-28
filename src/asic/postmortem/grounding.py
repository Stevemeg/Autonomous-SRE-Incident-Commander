"""Deterministic grounding validation for postmortem claims (FR-PMT-02).

A model may draft prose. It may not add an operational fact that no record supports. Every
model-authored claim passes these checks, in order, and the first that fails removes the claim
from the draft's factual sections and records it - with its reason - in the uncertainty list:

``no_citation``
    The claim cites nothing.
``unknown_citation``
    It cites a handle that is not a record of this incident (a hallucinated or foreign id).
``flagged_source_only``
    Every record it cites is evidence flagged as a possible prompt injection.
``unsupported_causal_claim``
    It asserts causation without citing the root-cause hypothesis, or names a cause class
    other than the one that hypothesis records.
``unsupported_figure``
    It states a number that appears in none of the records it cites.

Nothing is silently kept and nothing is silently dropped. The checks are mechanical on purpose:
a second model judging the first would be another unsupported claim.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from asic.observability.redaction import scrub_text
from asic.postmortem.sources import PostmortemSources

#: Sections a model may contribute to. Everything else in its output is ignored and reported.
MODEL_SECTIONS: Final[tuple[str, ...]] = (
    "summary",
    "what_went_well",
    "what_went_poorly",
    "follow_up_actions",
)

MAX_CLAIMS_PER_SECTION: Final[int] = 8
MAX_CLAIM_CHARS: Final[int] = 500
MAX_CITATIONS_PER_CLAIM: Final[int] = 10

#: Root-cause classes the hypothesis engine may record (``HYPOTHESIS_PROMPT``).
ROOT_CAUSE_CLASSES: Final[tuple[str, ...]] = (
    "bad_deployment",
    "dependency_regression",
    "resource_exhaustion",
    "configuration_change",
    "capacity",
    "external_dependency",
)

_CAUSAL: Final[re.Pattern[str]] = re.compile(
    r"\b(caus\w*|because|due to|root[- ]cause|result(?:ed|s)? (?:in|from)|triggered|led to"
    r"|attributable)\b",
    re.IGNORECASE,
)
_FIGURE: Final[re.Pattern[str]] = re.compile(r"\d+(?:\.\d+)?")
_CONTROL: Final[re.Pattern[str]] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True, slots=True)
class Claim:
    """One statement in a draft, with the records that support it.

    ``origin`` is ``record`` (assembled by the author from typed columns), ``model`` (drafted
    by the model and validated here) or ``system`` (fixed structural text owned by the author,
    such as "a human must review this draft", which states no operational fact).
    """

    text: str
    citations: tuple[str, ...]
    origin: str

    def to_json(self) -> dict[str, Any]:
        return {"text": self.text, "citations": list(self.citations), "origin": self.origin}


@dataclass(frozen=True, slots=True)
class Uncertainty:
    section: str
    text: str
    reason: str
    citations: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "section": self.section,
            "text": self.text,
            "reason": self.reason,
            "citations": list(self.citations),
        }


@dataclass(slots=True)
class GroundingReport:
    """What validation did to one generator response."""

    kept: dict[str, list[Claim]] = field(default_factory=dict)
    removed: list[Uncertainty] = field(default_factory=list)
    ignored_fields: list[str] = field(default_factory=list)
    output_error: str | None = None

    def to_json(self) -> dict[str, Any]:
        reasons: dict[str, int] = {}
        for item in self.removed:
            reasons[item.reason] = reasons.get(item.reason, 0) + 1
        return {
            "model_claims_kept": sum(len(claims) for claims in self.kept.values()),
            "model_claims_removed": len(self.removed),
            "removed_by_reason": dict(sorted(reasons.items())),
            "ignored_fields": sorted(self.ignored_fields),
            "output_error": self.output_error,
        }


def clean_text(text: str) -> str:
    """Bound, de-control and de-secret a piece of text before it is stored."""
    return scrub_text(_CONTROL.sub(" ", text).strip(), limit=MAX_CLAIM_CHARS)


def validate_model_output(raw: str, sources: PostmortemSources) -> GroundingReport:
    """Parse a generator response and keep only the claims its cited records support."""
    report = GroundingReport()
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        report.output_error = "unparseable"
        return report
    if not isinstance(parsed, Mapping):
        report.output_error = "not_an_object"
        return report
    # Anything the model returns beyond its sections - a status, a publish flag, a reviewer -
    # has no path into the draft. It is reported so a reviewer can see the attempt.
    report.ignored_fields.extend(str(key)[:64] for key in parsed if key not in MODEL_SECTIONS)
    for section in MODEL_SECTIONS:
        items = parsed.get(section, [])
        if not isinstance(items, list):
            report.removed.append(Uncertainty(section, "(section was not a list)", "malformed"))
            continue
        for item in items[:MAX_CLAIMS_PER_SECTION]:
            claim, problem = _claim(item)
            if claim is None:
                report.removed.append(Uncertainty(section, "(unreadable claim)", problem))
                continue
            reason = check_claim(claim, sources)
            if reason is None:
                report.kept.setdefault(section, []).append(claim)
            else:
                report.removed.append(Uncertainty(section, claim.text, reason, claim.citations))
    return report


def _claim(item: object) -> tuple[Claim | None, str]:
    if not isinstance(item, Mapping):
        return None, "malformed"
    text = item.get("text")
    citations = item.get("citations", [])
    if not isinstance(text, str) or not text.strip():
        return None, "malformed"
    if not isinstance(citations, list) or not all(isinstance(c, str) for c in citations):
        return None, "malformed"
    handles = tuple(dict.fromkeys(c.strip() for c in citations[:MAX_CITATIONS_PER_CLAIM]))
    return Claim(text=clean_text(text), citations=handles, origin="model"), ""


def check_claim(claim: Claim, sources: PostmortemSources) -> str | None:
    """The first grounding rule the claim breaks, or ``None`` if it is supported."""
    if not claim.citations:
        return "no_citation"
    records = [sources.records.get(handle) for handle in claim.citations]
    if any(record is None for record in records):
        return "unknown_citation"
    cited = [record for record in records if record is not None]
    if all(record.injection_flagged for record in cited):
        return "flagged_source_only"
    if _CAUSAL.search(claim.text) and not _causal_claim_supported(claim, sources):
        return "unsupported_causal_claim"
    support = " ".join(f"{record.description} {record.untrusted_text or ''}" for record in cited)
    for figure in _FIGURE.findall(claim.text):
        if figure not in support:
            return "unsupported_figure"
    return None


def _causal_claim_supported(claim: Claim, sources: PostmortemSources) -> bool:
    if sources.root_cause is None or sources.root_cause.handle not in claim.citations:
        return False
    text = claim.text.lower()
    for cause in ROOT_CAUSE_CLASSES:
        if cause == sources.root_cause_class:
            continue
        if cause in text or cause.replace("_", " ") in text:
            return False
    return True


def check_record_claims(claims: Sequence[Claim], sources: PostmortemSources) -> None:
    """Assert the author's own record claims are grounded. A failure is a defect, not data."""
    for claim in claims:
        if claim.origin == "system":
            continue
        missing = [handle for handle in claim.citations if handle not in sources.records]
        if not claim.citations or missing:
            raise AssertionError(f"record claim is not grounded: {claim.text[:80]!r} {missing}")


__all__ = [
    "MODEL_SECTIONS",
    "ROOT_CAUSE_CLASSES",
    "Claim",
    "GroundingReport",
    "Uncertainty",
    "check_claim",
    "check_record_claims",
    "clean_text",
    "validate_model_output",
]
