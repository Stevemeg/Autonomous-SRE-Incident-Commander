"""The embedding port: deadlines, validation and the deterministic provider. No database."""

from __future__ import annotations

import math
import time
from collections.abc import Sequence

import pytest

from asic.knowledge.embedding import (
    DETERMINISTIC_MODEL,
    DeterministicEmbeddingProvider,
    EmbeddingModel,
    EmbeddingService,
)
from asic.knowledge.errors import EmbeddingDimensionMismatch, EmbeddingFailure, EmbeddingTimeout


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    return sum(x * y for x, y in zip(a, b, strict=True))


class _Provider:
    """A provider whose output the test controls."""

    def __init__(
        self,
        vectors: Sequence[Sequence[float]] | None = None,
        *,
        sleep: float = 0.0,
        raise_error: bool = False,
        dimensions: int = DETERMINISTIC_MODEL.dimensions,
    ) -> None:
        self._vectors = vectors
        self._sleep = sleep
        self._raise = raise_error
        self._model = EmbeddingModel("test", "controlled", "1", dimensions)

    @property
    def model(self) -> EmbeddingModel:
        return self._model

    def embed(self, texts: Sequence[str]) -> Sequence[Sequence[float]]:
        if self._sleep:
            time.sleep(self._sleep)
        if self._raise:
            raise RuntimeError("upstream exploded with secret=abc123")
        assert self._vectors is not None
        return self._vectors[: len(texts)]


def _unit(dimensions: int = DETERMINISTIC_MODEL.dimensions) -> list[float]:
    vector = [0.0] * dimensions
    vector[0] = 1.0
    return vector


class TestDeterministicProvider:
    def test_vectors_are_deterministic_normalised_and_full_width(self) -> None:
        service = EmbeddingService(DeterministicEmbeddingProvider())
        first, second = service.embed(["checkout latency after deploy"] * 2)
        assert first == second
        assert len(first) == 1536
        assert math.isclose(math.sqrt(_cosine(first, first)), 1.0, rel_tol=1e-9)

    def test_operational_paraphrases_land_closer_than_unrelated_text(self) -> None:
        service = EmbeddingService(DeterministicEmbeddingProvider())
        oom, paraphrase, unrelated = service.embed(
            ["pods are OOMKilled", "the container ran out of memory", "certificate expired"]
        )
        assert _cosine(oom, paraphrase) > _cosine(oom, unrelated) + 0.2

    def test_text_with_no_features_is_refused(self) -> None:
        with pytest.raises(EmbeddingFailure, match="empty_embedding_input"):
            EmbeddingService(DeterministicEmbeddingProvider()).embed(["the of and !!!"])

    def test_the_model_identity_is_recorded_and_bounded(self) -> None:
        assert DETERMINISTIC_MODEL.identifier == "asic-deterministic/hash-concept@1"
        with pytest.raises(ValueError, match="128"):
            _ = EmbeddingModel("p" * 100, "m" * 40, "1", 1536).identifier


class TestServiceValidation:
    def test_a_provider_with_the_wrong_width_is_refused_at_construction(self) -> None:
        with pytest.raises(EmbeddingDimensionMismatch):
            EmbeddingService(_Provider(dimensions=8))

    def test_a_hanging_provider_is_abandoned_at_the_deadline(self) -> None:
        service = EmbeddingService(_Provider([_unit()], sleep=5.0), timeout_seconds=0.2)
        started = time.monotonic()
        with pytest.raises(EmbeddingTimeout):
            service.embed(["anything"])
        assert time.monotonic() - started < 2.0, "the deadline was not enforced"

    @pytest.mark.parametrize(
        ("vector", "code"),
        [
            ([float("nan")] + [0.0] * 1535, "non_finite_vector"),
            ([0.5] + [0.0] * 1535, "vector_not_normalised"),
            ([1.0] * 10, "vector_dimension_mismatch"),
        ],
        ids=["nan", "unnormalised", "short"],
    )
    def test_an_unusable_vector_is_refused(self, vector: list[float], code: str) -> None:
        with pytest.raises(EmbeddingFailure, match=code):
            EmbeddingService(_Provider([vector])).embed(["x"])

    def test_a_short_answer_is_refused_not_padded(self) -> None:
        with pytest.raises(EmbeddingFailure, match="vector_count_mismatch"):
            EmbeddingService(_Provider([_unit()])).embed(["a", "b"])

    def test_a_provider_error_is_typed_and_leaks_nothing(self) -> None:
        with pytest.raises(EmbeddingFailure) as caught:
            EmbeddingService(_Provider(raise_error=True)).embed(["x"])
        assert caught.value.code == "provider_error" and caught.value.transient
        assert "secret" not in str(caught.value)
