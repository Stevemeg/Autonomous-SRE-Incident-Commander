"""Typed knowledge failures. Every one carries a safe reason code and never source text."""

from __future__ import annotations

from asic.domain.errors import DomainError


class KnowledgeRejected(DomainError):
    """A deterministic refusal: malformed, oversized, unsupported or out of policy.

    Retrying the same input fails the same way, so the outcome is recorded durably.
    """

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class EmbeddingFailure(DomainError):
    """The embedding dependency failed. ``transient`` failures may succeed on retry."""

    def __init__(self, code: str, *, transient: bool = False) -> None:
        self.code = code
        self.transient = transient
        super().__init__(code)


class EmbeddingTimeout(EmbeddingFailure):
    """The provider did not answer within its deadline. The call was abandoned."""

    def __init__(self) -> None:
        super().__init__("embedding_timeout", transient=True)


class EmbeddingDimensionMismatch(EmbeddingFailure):
    """The provider's vectors do not fit the stored vector column.

    Raised at construction: a mismatched provider is a configuration error, and letting it
    run would either fail every write or - worse - compare vectors from different spaces.
    """

    def __init__(self, expected: int, actual: int) -> None:
        super().__init__(f"dimension_mismatch:{expected}!={actual}")


class RetrievalRefused(DomainError):
    """Retrieval could not run safely - a scope or principal problem, never "no results"."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CitationInvalid(DomainError):
    """A citation does not resolve to a chunk actually returned by the retrieval it names."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


__all__ = [
    "CitationInvalid",
    "EmbeddingDimensionMismatch",
    "EmbeddingFailure",
    "EmbeddingTimeout",
    "KnowledgeRejected",
    "RetrievalRefused",
]
