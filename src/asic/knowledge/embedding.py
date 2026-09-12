"""The embedding port, and a deterministic provider for tests and evaluation.

Persistence and retrieval depend on :class:`EmbeddingProvider`, never on a vendor. A
provider declares its :class:`EmbeddingModel` - provider, model, version, dimensions and
normalisation - and that identity is stored on every chunk and every retrieval, so vectors
from different models are never compared and a model change is visible as the re-index it
is.

:class:`EmbeddingService` is the only caller of a provider. It bounds batch size, enforces a
deadline by running the provider on a worker thread and abandoning it at the timeout (the
same pattern the Tool Broker uses for adapters), and validates every vector: right
dimensions, finite, unit length. A provider is not trusted to have produced a usable vector.

**About the deterministic provider.** It is not a semantic model and makes no claim to be
one. It hashes stemmed tokens and a small, versioned table of operational concepts into a
fixed-width vector, so "OOMKilled" and "out of memory" land near each other and unrelated
text lands near zero. That is enough to exercise the hybrid retrieval path, its filters and
its evaluation reproducibly without a network call. Retrieval quality measured with it says
nothing about retrieval quality with a real embedding model; a real provider must be
evaluated on its own.
"""

from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from collections import Counter
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

from asic.db.models.knowledge import EMBEDDING_DIMENSIONS
from asic.knowledge.errors import EmbeddingDimensionMismatch, EmbeddingFailure, EmbeddingTimeout


@dataclass(frozen=True, slots=True)
class EmbeddingModel:
    """The identity of a vector space."""

    provider: str
    model_id: str
    model_version: str
    dimensions: int
    #: Only L2-normalised vectors are accepted: cosine distance in the index assumes it.
    normalization: str = "l2"
    schema_version: int = 1

    @property
    def identifier(self) -> str:
        """Stored on every chunk and retrieval. Bounded to the 128-character column."""
        value = f"{self.provider}/{self.model_id}@{self.model_version}"
        if len(value) > 128:
            raise ValueError("embedding model identifier exceeds 128 characters")
        return value


@runtime_checkable
class EmbeddingProvider(Protocol):
    """A source of vectors. Implementations must be pure with respect to their input."""

    @property
    def model(self) -> EmbeddingModel: ...

    def embed(self, texts: Sequence[str]) -> Sequence[Sequence[float]]:
        """Return one vector per input text, in order."""


#: Worker pool shared by all embedding services. A provider call that outlives its
#: deadline is abandoned here, never waited for.
_EXECUTOR: Final = ThreadPoolExecutor(max_workers=4, thread_name_prefix="asic-embed")


class EmbeddingService:
    """Deadline-bounded, validated access to one embedding provider."""

    __slots__ = ("_max_batch", "_provider", "_timeout")

    def __init__(
        self,
        provider: EmbeddingProvider,
        *,
        timeout_seconds: float = 20.0,
        max_batch: int = 64,
        expected_dimensions: int = EMBEDDING_DIMENSIONS,
    ) -> None:
        if provider.model.dimensions != expected_dimensions:
            raise EmbeddingDimensionMismatch(expected_dimensions, provider.model.dimensions)
        if provider.model.normalization != "l2":
            raise EmbeddingFailure("unsupported_normalization")
        if timeout_seconds <= 0 or max_batch <= 0:
            raise ValueError("timeout and batch size must be positive")
        self._provider = provider
        self._timeout = timeout_seconds
        self._max_batch = max_batch

    @property
    def model(self) -> EmbeddingModel:
        return self._provider.model

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """Embed ``texts`` in bounded batches.

        Raises:
            EmbeddingTimeout: a batch exceeded the deadline.
            EmbeddingFailure: the provider raised, or returned an unusable vector.
        """
        vectors: list[list[float]] = []
        for offset in range(0, len(texts), self._max_batch):
            batch = list(texts[offset : offset + self._max_batch])
            future = _EXECUTOR.submit(self._provider.embed, batch)
            try:
                produced = future.result(timeout=self._timeout)
            except FutureTimeout as exc:
                future.cancel()
                raise EmbeddingTimeout() from exc
            except EmbeddingFailure:
                raise
            except Exception as exc:
                raise EmbeddingFailure("provider_error", transient=True) from exc
            if len(produced) != len(batch):
                raise EmbeddingFailure("vector_count_mismatch")
            vectors.extend(self._validated(vector) for vector in produced)
        return vectors

    def embed_one(self, text: str) -> list[float]:
        return self.embed([text])[0]

    def _validated(self, vector: Sequence[float]) -> list[float]:
        values = [float(v) for v in vector]
        if len(values) != self.model.dimensions:
            raise EmbeddingFailure("vector_dimension_mismatch")
        if not all(math.isfinite(v) for v in values):
            raise EmbeddingFailure("non_finite_vector")
        norm = math.sqrt(sum(v * v for v in values))
        if abs(norm - 1.0) > 1e-3:
            raise EmbeddingFailure("vector_not_normalised")
        return values


# ------------------------------------------------------------ deterministic provider

DETERMINISTIC_MODEL: Final = EmbeddingModel(
    provider="asic-deterministic",
    model_id="hash-concept",
    model_version="1",
    dimensions=EMBEDDING_DIMENSIONS,
)

_TOKEN = re.compile(r"[a-z0-9]+")

_STOPWORDS: Final[frozenset[str]] = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "been",
        "by",
        "for",
        "from",
        "has",
        "have",
        "how",
        "if",
        "in",
        "into",
        "is",
        "it",
        "its",
        "of",
        "on",
        "or",
        "that",
        "the",
        "their",
        "then",
        "there",
        "these",
        "this",
        "to",
        "was",
        "were",
        "what",
        "when",
        "where",
        "which",
        "while",
        "who",
        "why",
        "will",
        "with",
        "you",
        "your",
        "we",
        "our",
        "not",
        "no",
        "do",
        "does",
        "did",
        "can",
        "could",
        "should",
        "would",
        "may",
        "might",
    ]
)

#: Operational concepts and the surface forms that express them. Versioned with the model:
#: editing this table changes every vector, so it is part of ``DETERMINISTIC_MODEL``.
_CONCEPT_FORMS: Final[dict[str, tuple[str, ...]]] = {
    "memory_exhaustion": (
        "oom",
        "oomkilled",
        "out of memory",
        "memory exhaustion",
        "memory pressure",
        "heap exhausted",
        "memory limit",
    ),
    "latency": ("latency", "slow", "slowness", "response time", "p95", "p99", "sluggish"),
    "request_timeout": ("timeout", "timed out", "deadline exceeded"),
    "connection_pool": (
        "connection pool",
        "pool exhausted",
        "too many connections",
        "connection limit",
        "pool saturation",
    ),
    "crash_loop": ("crashloopbackoff", "crash loop", "crashing", "restart loop"),
    "rollback": ("rollback", "roll back", "revert", "undo the deployment"),
    "deployment": ("deploy", "deployment", "release", "rollout"),
    "database": ("database", "db", "postgres", "postgresql"),
    "certificate": ("certificate", "cert", "tls", "ssl"),
    "disk_pressure": ("disk full", "no space left", "disk pressure", "volume full"),
    "dns": ("dns", "name resolution", "nxdomain"),
    "error_rate": ("5xx", "error rate", "internal server error", "http 500"),
    "restart": ("restart", "reboot", "bounce"),
}


def _stem(token: str) -> str:
    for suffix in ("ing", "ed", "es", "s"):
        if token.endswith(suffix) and len(token) - len(suffix) >= 3:
            return token[: -len(suffix)]
    return token


def _tokens(text: str) -> list[str]:
    normalised = unicodedata.normalize("NFKC", text).lower()
    return [_stem(token) for token in _TOKEN.findall(normalised)]


_CONCEPTS: Final[dict[tuple[str, ...], str]] = {
    tuple(_tokens(form)): concept for concept, forms in _CONCEPT_FORMS.items() for form in forms
}
_MAX_PHRASE: Final[int] = max(len(key) for key in _CONCEPTS)


class DeterministicEmbeddingProvider:
    """Hashed token and concept features. For tests and evaluation only - see module docs."""

    __slots__ = ()

    @property
    def model(self) -> EmbeddingModel:
        return DETERMINISTIC_MODEL

    def embed(self, texts: Sequence[str]) -> Sequence[Sequence[float]]:
        return [self._embed(text) for text in texts]

    def _embed(self, text: str) -> list[float]:
        tokens = _tokens(text)
        features: Counter[str] = Counter(
            f"t:{token}" for token in tokens if token not in _STOPWORDS
        )
        for index in range(len(tokens)):
            for width in range(1, _MAX_PHRASE + 1):
                concept = _CONCEPTS.get(tuple(tokens[index : index + width]))
                if concept is not None:
                    features[f"c:{concept}"] += 1
        vector = [0.0] * DETERMINISTIC_MODEL.dimensions
        for feature, count in sorted(features.items()):
            weight = (2.0 if feature.startswith("c:") else 1.0) * (1.0 + math.log(count))
            digest = hashlib.sha256(feature.encode("utf-8")).digest()
            slot = int.from_bytes(digest[:4], "big") % DETERMINISTIC_MODEL.dimensions
            vector[slot] += weight if digest[4] & 1 else -weight
        norm = math.sqrt(sum(v * v for v in vector))
        if norm == 0.0:
            raise EmbeddingFailure("empty_embedding_input")
        return [v / norm for v in vector]


__all__ = [
    "DETERMINISTIC_MODEL",
    "DeterministicEmbeddingProvider",
    "EmbeddingModel",
    "EmbeddingProvider",
    "EmbeddingService",
]
