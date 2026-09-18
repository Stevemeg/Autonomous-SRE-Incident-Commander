"""Strict replay, checked where it is claimed: at the harness and the gate.

INTEGRATION / REPLAY. The provider-level tests in ``test_corpus_and_replay.py`` prove that
a divergent request raises. They cannot prove what a *suite run* does with that raise, and
that gap is what let a fixture with its first recording removed still report ``passed``:
the broker turns the divergence into a degraded tool result, and the scenario's remaining
expectations survived it.

So every mutation below is applied to a real recorded fixture and replayed through the real
harness, and the assertion is about the verdict and the gate, not about the exception.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from asic.db.models import EvaluationReplayFixture
from asic.db.session import bind_tenant
from asic.domain.enums import EvaluationGateStatus, EvaluationRunVerdict, ExecutionMode
from asic.evaluation.comparison import gate_status
from asic.evaluation.corpus import GoldenScenario, select
from asic.evaluation.harness import EvaluationHarness, HarnessConfig, ScenarioOutcome
from asic.evaluation.replay import ReplayFixture
from asic.evaluation.world import ensure_tenant
from tests.conftest import requires_postgres

pytestmark = requires_postgres

#: One investigation scenario and one remediation scenario, as the audit asked for.
SCENARIOS: tuple[str, ...] = ("EV-INV-001", "EV-REM-001")


def _mutations(
    fixture: ReplayFixture,
) -> dict[str, ReplayFixture]:
    """Every way a recording can stop describing the run it claims to reproduce."""
    tools = [dict(call) for call in fixture.tool_calls]
    models = [dict(call) for call in fixture.model_calls]

    def rebuilt(
        tool_calls: Sequence[Mapping[str, Any]] | None = None,
        model_calls: Sequence[Mapping[str, Any]] | None = None,
    ) -> ReplayFixture:
        return ReplayFixture(
            scenario_key=fixture.scenario_key,
            scenario_digest=fixture.scenario_digest,
            tool_calls=tuple(tool_calls if tool_calls is not None else tools),
            model_calls=tuple(model_calls if model_calls is not None else models),
        )

    reordered_tools = list(tools)
    reordered_tools[0], reordered_tools[-1] = reordered_tools[-1], reordered_tools[0]
    reordered_models = list(models)
    reordered_models[0], reordered_models[-1] = reordered_models[-1], reordered_models[0]

    wrong_capability = copy.deepcopy(tools)
    wrong_capability[0]["tool"] = "logs.query"
    wrong_capability[0]["identity"] = "c" * 64

    wrong_arguments = copy.deepcopy(tools)
    wrong_arguments[0]["identity"] = "a" * 64

    wrong_model_identity = copy.deepcopy(models)
    wrong_model_identity[0]["identity"] = "m" * 64

    swapped_text = copy.deepcopy(models)
    first, last = swapped_text[0].get("response"), swapped_text[-1].get("response")
    if isinstance(first, dict) and isinstance(last, dict):
        first["text"], last["text"] = last["text"], first["text"]

    return {
        "A_delete_first_tool": rebuilt(tool_calls=tools[1:]),
        "B_delete_last_tool": rebuilt(tool_calls=tools[:-1]),
        "C_insert_unused_tool": rebuilt(tool_calls=[*tools, dict(tools[-1])]),
        "D_reorder_tools": rebuilt(tool_calls=reordered_tools),
        "E_change_capability": rebuilt(tool_calls=wrong_capability),
        "F_change_tool_arguments": rebuilt(tool_calls=wrong_arguments),
        "G_delete_first_model": rebuilt(model_calls=models[1:]),
        "H_delete_last_model": rebuilt(model_calls=models[:-1]),
        "I_insert_unused_model": rebuilt(model_calls=[*models, dict(models[-1])]),
        "J_reorder_models": rebuilt(model_calls=reordered_models),
        "K_change_model_identity": rebuilt(model_calls=wrong_model_identity),
        "L_swap_model_response_text": rebuilt(model_calls=swapped_text),
    }


@pytest.fixture(scope="module")
def recorded(
    owner_engine: Engine, app_engine: Engine
) -> Iterator[tuple[EvaluationHarness, uuid.UUID, dict[str, ReplayFixture], dict[str, Any]]]:
    """One simulator suite run, so every mutation replays against real recordings."""
    admin_factory: Callable[[], Session] = sessionmaker(
        bind=owner_engine, expire_on_commit=False, autoflush=False
    )
    app_factory: Callable[[], Session] = sessionmaker(
        bind=app_engine, expire_on_commit=False, autoflush=False
    )
    harness = EvaluationHarness(admin_factory=admin_factory, app_factory=app_factory)
    slug = f"replay-div-{uuid.uuid4().hex[:8]}"
    outcome = harness.run(
        HarnessConfig(
            tenant_slug=slug, keys=SCENARIOS, mode=ExecutionMode.SIMULATOR, baseline="none"
        )
    )
    assert outcome.status == "passed", outcome.report
    tenant_id = ensure_tenant(admin_factory, slug)
    with app_factory() as session:
        bind_tenant(session, tenant_id)
        fixtures = {
            row.scenario_key: ReplayFixture.load(row.content, expected_digest=row.digest)
            for row in session.scalars(
                sa.select(EvaluationReplayFixture).where(
                    EvaluationReplayFixture.tenant_id == tenant_id
                )
            )
        }
    assert set(fixtures) == set(SCENARIOS)
    yield harness, tenant_id, fixtures, outcome.report


def _replay(
    harness: EvaluationHarness,
    tenant_id: uuid.UUID,
    report: dict[str, Any],
    key: str,
    fixture: ReplayFixture,
) -> ScenarioOutcome:
    # The ordinal must be the one the recording was made with: it fixes the scenario's
    # logical clock, and therefore the observation windows inside every recorded request.
    selected = select(SCENARIOS)
    golden: GoldenScenario = next(g for g in selected if g.key == key)
    ordinal = next(i for i, g in enumerate(selected) if g.key == key)
    return harness._run_scenario(
        golden,
        tenant_id=tenant_id,
        behaviour_id=uuid.UUID(report["behaviour_version_id"]),
        token=uuid.uuid4().hex[:8],
        ordinal=ordinal,
        mode=ExecutionMode.REPLAY,
        fixture=fixture,
    )


@pytest.mark.parametrize("key", SCENARIOS)
def test_m_an_unmutated_recording_replays_to_a_pass(
    recorded: tuple[EvaluationHarness, uuid.UUID, dict[str, ReplayFixture], dict[str, Any]],
    key: str,
) -> None:
    """The positive control. Without it the matrix below could pass by always failing."""
    harness, tenant_id, fixtures, report = recorded
    outcome = _replay(harness, tenant_id, report, key, fixtures[key])
    assert outcome.verdict is EvaluationRunVerdict.PASSED, outcome.report()
    checks = outcome.report()["checks_failed"]
    assert checks == [], checks
    assert outcome.extra["replay_divergences"] == 0


@pytest.mark.parametrize("key", SCENARIOS)
@pytest.mark.parametrize(
    "mutation",
    [
        "A_delete_first_tool",
        "B_delete_last_tool",
        "C_insert_unused_tool",
        "D_reorder_tools",
        "E_change_capability",
        "F_change_tool_arguments",
        "G_delete_first_model",
        "H_delete_last_model",
        "I_insert_unused_model",
        "J_reorder_models",
        "K_change_model_identity",
        "L_swap_model_response_text",
    ],
)
def test_a_mutated_recording_never_replays_to_a_pass(
    recorded: tuple[EvaluationHarness, uuid.UUID, dict[str, ReplayFixture], dict[str, Any]],
    key: str,
    mutation: str,
) -> None:
    harness, tenant_id, fixtures, report = recorded
    mutated = _mutations(fixtures[key])[mutation]
    outcome = _replay(harness, tenant_id, report, key, mutated)

    assert outcome.verdict in (
        EvaluationRunVerdict.FAILED,
        EvaluationRunVerdict.ERRORED,
    ), f"{key}/{mutation} replayed to {outcome.verdict.value}: {outcome.report()}"

    if outcome.verdict is EvaluationRunVerdict.FAILED:
        # The divergence itself is the finding, not a downstream expectation that happened
        # to notice: one of the replay invariants must be among the zero-tolerance failures.
        zero = set(outcome.report()["zero_tolerance_failures"])
        assert zero & {
            "replay.no_divergence",
            "replay.fully_consumed",
            "replay.interaction_signature",
        }, f"{key}/{mutation} failed only on downstream expectations: {zero}"

    report_for_gate = {
        "scenarios": [outcome.report()],
        "comparison": {},
    }
    assert gate_status(report_for_gate) is not EvaluationGateStatus.PASSED
