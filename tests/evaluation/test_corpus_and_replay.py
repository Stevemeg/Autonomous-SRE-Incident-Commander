"""UNIT: the versioned golden corpus and the strict replay providers."""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from typing import Any, ClassVar, cast

import pytest

from asic.domain.enums import NodeId
from asic.domain.errors import ModelProviderError, ToolAdapterError, ToolTimeout
from asic.evaluation.corpus import (
    COVERAGE_CATEGORIES,
    GOLDEN_CORPUS,
    SMOKE_KEYS,
    WorkflowKind,
    corpus_digest,
    coverage,
    scenario_digest,
    select,
)
from asic.evaluation.replay import (
    ReplayDivergence,
    ReplayFixture,
    ReplayModelProvider,
    ReplayRefused,
    ReplayToolProvider,
    model_identity,
    request_identity,
)
from asic.evaluation.versioning import REPLAY_FORMAT_VERSION, digest
from asic.integrations.credentials import DEPLOYMENT_ENV_VAR
from asic.llm.port import ModelRequest
from asic.tools.provider import InvocationContext
from asic.tools.registry import ToolRegistry

METRICS = ToolRegistry.read_only().by_name("metrics.query")
CONTEXT = cast(InvocationContext, None)  # replay never reads the invocation context


class TestCorpus:
    def test_every_required_category_is_covered_by_at_least_one_scenario(self) -> None:
        covered = coverage()
        assert len(COVERAGE_CATEGORIES) == 23
        assert [c for c, keys in covered.items() if not keys] == []

    def test_scenarios_declare_only_known_categories(self) -> None:
        for golden in GOLDEN_CORPUS:
            assert set(golden.covers) <= set(COVERAGE_CATEGORIES), golden.key

    def test_keys_are_unique_and_each_scenario_has_exactly_its_kind_of_expectation(self) -> None:
        keys = [g.key for g in GOLDEN_CORPUS]
        assert len(keys) == len(set(keys))
        slot = {
            WorkflowKind.INVESTIGATION: "investigation",
            WorkflowKind.REMEDIATION: "remediation",
            WorkflowKind.CORRELATION: "correlation",
            WorkflowKind.BROKER_SECURITY: "security",
        }
        for golden in GOLDEN_CORPUS:
            present = [
                name
                for name in ("investigation", "remediation", "correlation", "security")
                if getattr(golden, name) is not None
            ]
            assert present == [slot[golden.kind]], golden.key

    def test_digests_are_stable(self) -> None:
        assert [scenario_digest(g) for g in GOLDEN_CORPUS] == [
            scenario_digest(g) for g in GOLDEN_CORPUS
        ]
        assert corpus_digest(GOLDEN_CORPUS) == corpus_digest(GOLDEN_CORPUS)

    def test_editing_an_expectation_changes_the_digest(self) -> None:
        golden = select(("EV-INV-001",))[0]
        assert golden.investigation is not None
        edited = dataclasses.replace(
            golden,
            investigation=dataclasses.replace(golden.investigation, incident_status="resolved"),
        )
        assert scenario_digest(edited) != scenario_digest(golden)
        assert corpus_digest((edited,)) != corpus_digest((golden,))

    def test_smoke_selection_and_unknown_keys(self) -> None:
        assert tuple(g.key for g in select(suite="smoke")) == SMOKE_KEYS
        assert select() == GOLDEN_CORPUS
        with pytest.raises(KeyError, match="EV-NOPE"):
            select(("EV-NOPE",))


def _fixture(
    tool_calls: Sequence[dict[str, Any]], model_calls: Sequence[dict[str, Any]] = ()
) -> ReplayFixture:
    return ReplayFixture(
        scenario_key="EV-TEST",
        scenario_digest="0" * 64,
        tool_calls=tuple(tool_calls),
        model_calls=tuple(model_calls),
    )


ARGS = {"metric": "http_request_duration_p95_seconds", "service": "checkout-api"}


class TestReplayFixture:
    def test_round_trips_and_verifies_its_digest(self) -> None:
        fixture = _fixture(
            [{"identity": "x", "tool": "metrics.query", "outcome": "result", "payload": {}}]
        )
        loaded = ReplayFixture.load(fixture.content(), expected_digest=fixture.digest)
        assert loaded == fixture

    def test_tampered_content_is_refused(self) -> None:
        fixture = _fixture(
            [{"identity": "x", "tool": "metrics.query", "outcome": "result", "payload": {"p95": 1}}]
        )
        content = fixture.content()
        content["tool_calls"][0]["payload"]["p95"] = 0.1
        with pytest.raises(ReplayRefused, match="digest"):
            ReplayFixture.load(content, expected_digest=fixture.digest)

    def test_unknown_format_version_is_refused(self) -> None:
        content = _fixture([]).content()
        content["format_version"] = REPLAY_FORMAT_VERSION + 1
        with pytest.raises(ReplayRefused, match="format"):
            ReplayFixture.load(content, expected_digest=digest(content))


class TestReplayToolProvider:
    def test_serves_recorded_answers_in_order_ignoring_scope_arguments(self) -> None:
        identity = request_identity(METRICS, ARGS)
        provider = ReplayToolProvider(
            _fixture(
                [
                    {
                        "identity": identity,
                        "tool": "metrics.query",
                        "outcome": "result",
                        "payload": {"v": 1},
                    }
                ]
            )
        )
        # A replay world has different scope identifiers; what was asked is unchanged.
        moved = {**ARGS, "service": "other-world-service", "environment": "ev-other"}
        assert request_identity(METRICS, moved) == identity
        assert provider.invoke(METRICS, moved, CONTEXT) == {"v": 1}
        assert provider.remaining == 0

    def test_a_different_question_diverges_instead_of_being_answered(self) -> None:
        provider = ReplayToolProvider(
            _fixture(
                [
                    {
                        "identity": request_identity(METRICS, ARGS),
                        "tool": "metrics.query",
                        "outcome": "result",
                        "payload": {},
                    }
                ]
            )
        )
        with pytest.raises(ReplayDivergence):
            provider.invoke(METRICS, {**ARGS, "metric": "error_rate"}, CONTEXT)
        assert provider.remaining == 1

    def test_an_unrecorded_extra_call_diverges(self) -> None:
        provider = ReplayToolProvider(_fixture([]))
        assert provider.supports(METRICS)  # routed here so it cannot reach another provider
        with pytest.raises(ReplayDivergence):
            provider.invoke(METRICS, ARGS, CONTEXT)

    def test_recorded_failures_replay_as_failures_not_results(self) -> None:
        identity = request_identity(METRICS, ARGS)
        provider = ReplayToolProvider(
            _fixture(
                [
                    {
                        "identity": identity,
                        "tool": "metrics.query",
                        "outcome": "timeout",
                        "message": "t",
                    },
                    {
                        "identity": identity,
                        "tool": "metrics.query",
                        "outcome": "error",
                        "transient": False,
                        "message": "boom",
                    },
                ]
            )
        )
        with pytest.raises(ToolTimeout):
            provider.invoke(METRICS, ARGS, CONTEXT)
        with pytest.raises(ToolAdapterError) as raised:
            provider.invoke(METRICS, ARGS, CONTEXT)
        assert raised.value.transient is False

    def test_refuses_a_production_deployment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(DEPLOYMENT_ENV_VAR, "production")
        with pytest.raises(ReplayRefused):
            ReplayToolProvider(_fixture([]))
        with pytest.raises(ReplayRefused):
            ReplayModelProvider(_fixture([]), provider_name="p", model_id="m")


def _request(prompt_version: str = "1") -> ModelRequest:
    return ModelRequest(
        node_id=NodeId.G5_HYPOTHESIS_ENGINE,
        prompt_id="hypothesis",
        prompt_version=prompt_version,
        prompt_hash="h" * 64,
        prompt_text="rendered",
    )


class TestReplayModelProvider:
    RESPONSE: ClassVar[dict[str, Any]] = {
        "text": "{}",
        "provider": "deterministic",
        "model_id": "scripted",
        "input_tokens": 10,
        "output_tokens": 5,
        "cost_usd": 0.001,
        "finish_reason": "stop",
    }

    def test_serves_the_recorded_response(self) -> None:
        provider = ReplayModelProvider(
            _fixture(
                [],
                [
                    {
                        "identity": model_identity(_request()),
                        "outcome": "response",
                        "response": self.RESPONSE,
                    }
                ],
            ),
            provider_name="deterministic",
            model_id="scripted",
        )
        assert provider.estimate(_request()).max_input_tokens == 10
        assert provider.complete(_request()).text == "{}"
        assert provider.remaining == 0

    def test_a_changed_prompt_version_diverges(self) -> None:
        provider = ReplayModelProvider(
            _fixture(
                [],
                [
                    {
                        "identity": model_identity(_request()),
                        "outcome": "response",
                        "response": self.RESPONSE,
                    }
                ],
            ),
            provider_name="deterministic",
            model_id="scripted",
        )
        with pytest.raises(ModelProviderError, match="diverged"):
            provider.complete(_request(prompt_version="2"))
