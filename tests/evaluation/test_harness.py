"""INTEGRATION / SIMULATOR / REPLAY: the evaluation harness against PostgreSQL.

Runs a representative slice of the golden corpus in simulator mode, then replays it with a
fresh harness instance (a restart: nothing shared but the database), and checks what the
records say - never the harness's in-memory view. Every result here is simulated or
replayed evaluation evidence, not a production measurement.
"""

from __future__ import annotations

import dataclasses
import json
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import jwt
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from asic.api import ApiSettings, create_app
from asic.db.models import (
    EvaluationJudgeResult,
    EvaluationReplayFixture,
    EvaluationRun,
    EvaluationScenario,
    EvaluationSuiteRun,
    ExecutionTrace,
    KnowledgeRetrieval,
    Role,
    User,
    UserRoleAssignment,
    WorkflowRun,
)
from asic.db.session import bind_tenant
from asic.domain.enums import ExecutionMode, JudgeOutcome, UserStatus
from asic.evaluation import gate
from asic.evaluation import harness as harness_module
from asic.evaluation.corpus import select
from asic.evaluation.harness import EvaluationHarness, HarnessConfig, HarnessRefused, SuiteOutcome
from asic.evaluation.judges import JudgePanel, LlmJudge
from asic.evaluation.versioning import digest
from asic.evaluation.world import ensure_tenant
from asic.integrations.credentials import DEPLOYMENT_ENV_VAR
from tests.evaluation.test_judges_comparison_evaluators import ScriptedJudgeModel

pytestmark = pytest.mark.postgres

#: One of each workflow kind, including RAG, fabricated citations, approval and revocation.
KEYS = (
    "EV-INV-001",
    "EV-INV-009",
    "EV-INV-010",
    "EV-REM-002",
    "EV-COR-001",
    "EV-SEC-002",
)


@dataclass(frozen=True)
class Suites:
    tenant_slug: str
    tenant_id: uuid.UUID
    simulator: SuiteOutcome
    replay: SuiteOutcome


def _factory(engine: Engine) -> Callable[[], Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def _harness(owner_engine: Engine, app_engine: Engine, **kwargs: Any) -> EvaluationHarness:
    return EvaluationHarness(
        admin_factory=_factory(owner_engine), app_factory=_factory(app_engine), **kwargs
    )


@pytest.fixture(scope="module")
def suites(owner_engine: Engine, app_engine: Engine) -> Suites:
    slug = f"ev-{uuid.uuid4().hex[:10]}"
    simulator = _harness(owner_engine, app_engine).run(
        HarnessConfig(tenant_slug=slug, keys=KEYS, baseline="none")
    )
    # A new harness instance: replay depends only on what the database holds.
    replay = _harness(owner_engine, app_engine).run(
        HarnessConfig(
            tenant_slug=slug,
            keys=KEYS,
            mode=ExecutionMode.REPLAY,
            baseline=str(simulator.suite_run_id),
        )
    )
    return Suites(slug, ensure_tenant(_factory(owner_engine), slug), simulator, replay)


def _scenarios(outcome: SuiteOutcome) -> dict[str, dict[str, Any]]:
    return {s["key"]: s for s in outcome.report["scenarios"]}


@pytest.fixture
def owner(owner_engine: Engine) -> Iterator[Session]:
    with Session(bind=owner_engine) as session:
        yield session


class TestSimulatorAndReplay:
    def test_the_simulator_suite_passes_with_honest_labels(self, suites: Suites) -> None:
        report = suites.simulator.report
        assert suites.simulator.status == "passed", render(report)
        assert {s["verdict"] for s in report["scenarios"]} == {"passed"}
        assert report["evidence_label"] == "SIMULATED / REPLAY EVALUATION - not production results"
        assert report["execution_mode"] == "simulator"
        # No judge provider is configured: not measured, never a number.
        assert report["judges"] == report["aggregate"]["llm_judge"] == "not_measured"
        assert {s["judges"]["status"] for s in report["scenarios"]} == {"not_measured"}

    def test_replay_after_restart_reproduces_every_observation(self, suites: Suites) -> None:
        assert suites.replay.status == "passed", render(suites.replay.report)
        simulated, replayed = _scenarios(suites.simulator), _scenarios(suites.replay)
        assert set(simulated) == set(replayed) == set(KEYS)
        for key in KEYS:
            assert replayed[key]["signature"] == simulated[key]["signature"], key
            assert replayed[key]["signature"] is not None
        comparison = suites.replay.report["comparison"]
        assert comparison["status"] == "compared"
        assert comparison["comparable_scenarios"] == len(KEYS)
        assert (comparison["new_failures"], comparison["regression_rate"]) == ([], 0.0)

    def test_replay_consumed_every_recorded_answer(self, suites: Suites, owner: Session) -> None:
        bind_tenant(owner, suites.tenant_id)
        checks = owner.scalars(
            sa.select(EvaluationRun.checks).where(
                EvaluationRun.suite_run_id == suites.replay.suite_run_id
            )
        ).all()
        consumed = [c["replay.fully_consumed"] for c in checks if "replay.fully_consumed" in c]
        # Investigation and remediation scenarios replay recorded answers.
        assert len(consumed) == 4
        assert all(c["passed"] for c in consumed)

    def test_cost_and_tokens_aggregate_from_the_runs(self, suites: Suites) -> None:
        report = suites.simulator.report
        tokens = sum(int(s["metrics"].get("tokens") or 0) for s in report["scenarios"])
        cost = sum(float(s["metrics"].get("cost_usd") or 0) for s in report["scenarios"])
        assert tokens > 0
        assert report["aggregate"]["tokens"] == tokens
        assert report["aggregate"]["cost_usd"] == pytest.approx(cost)

    def test_rag_scenario_used_governed_retrieval(self, suites: Suites, owner: Session) -> None:
        metrics = _scenarios(suites.simulator)["EV-INV-009"]["metrics"]
        assert metrics["evidence_recall"] == 1.0
        assert metrics["rca_top1"] is True
        assert metrics["knowledge_results"] >= 1
        bind_tenant(owner, suites.tenant_id)
        run = owner.scalars(
            sa.select(EvaluationRun)
            .join(EvaluationScenario, EvaluationScenario.id == EvaluationRun.evaluation_scenario_id)
            .where(
                EvaluationRun.suite_run_id == suites.simulator.suite_run_id,
                EvaluationScenario.key == "EV-INV-009",
            )
        ).one()
        incident = owner.scalar(
            sa.select(WorkflowRun.incident_id).where(WorkflowRun.id == run.workflow_run_id)
        )
        retrievals = owner.scalars(
            sa.select(KnowledgeRetrieval).where(KnowledgeRetrieval.incident_id == incident)
        ).all()
        assert retrievals and all(r.result_count >= 1 for r in retrievals)

    def test_safety_scenarios_evidence_what_they_claim(self, suites: Suites) -> None:
        scenarios = _scenarios(suites.simulator)
        assert scenarios["EV-INV-010"]["metrics"]["rejected_citations"] > 0
        assert scenarios["EV-SEC-002"]["metrics"]["adapter_calls"] == 1
        assert scenarios["EV-REM-002"]["metrics"]["unsafe_actions"] == 0
        assert suites.simulator.report["aggregate"]["unsafe_actions"] == 0


class TestPersistence:
    def test_results_are_bound_to_workflow_runs_and_traces(
        self, suites: Suites, owner: Session
    ) -> None:
        bind_tenant(owner, suites.tenant_id)
        rows = owner.execute(
            sa.select(EvaluationRun, EvaluationScenario.key)
            .join(EvaluationScenario, EvaluationScenario.id == EvaluationRun.evaluation_scenario_id)
            .where(EvaluationRun.suite_run_id == suites.simulator.suite_run_id)
        ).all()
        assert {key for _, key in rows} == set(KEYS)
        bound = [(run, key) for run, key in rows if key.startswith(("EV-INV", "EV-REM"))]
        assert len(bound) == 4
        for run, key in bound:
            assert run.workflow_run_id is not None, key
            assert run.execution_mode is ExecutionMode.SIMULATOR
            workflow = owner.get(WorkflowRun, run.workflow_run_id)
            assert workflow is not None
            trace = owner.scalars(
                sa.select(ExecutionTrace).where(ExecutionTrace.workflow_run_id == workflow.id)
            ).first()
            assert trace is not None, key
            assert trace.incident_id == workflow.incident_id
            assert trace.fixture_refs["evaluation_scenario"] == key
            assert trace.fixture_refs["mode"] == "simulator"

    def test_suite_report_is_sealed_and_links_its_baseline(
        self, suites: Suites, owner: Session
    ) -> None:
        bind_tenant(owner, suites.tenant_id)
        replay = owner.get(EvaluationSuiteRun, suites.replay.suite_run_id)
        assert replay is not None
        assert digest(dict(replay.report)) == replay.report_digest
        assert replay.baseline_suite_run_id == suites.simulator.suite_run_id
        fixtures = owner.scalars(
            sa.select(EvaluationReplayFixture).where(
                EvaluationReplayFixture.tenant_id == suites.tenant_id
            )
        ).all()
        assert {f.scenario_key for f in fixtures} == {
            "EV-INV-001",
            "EV-INV-009",
            "EV-INV-010",
            "EV-REM-002",
        }
        assert all(digest(dict(f.content)) == f.digest for f in fixtures)

    @pytest.mark.parametrize(
        "statement",
        [
            "UPDATE evaluation_run SET verdict = 'passed'",
            "DELETE FROM evaluation_run",
            "UPDATE evaluation_suite_run SET gate_status = 'passed'",
            "DELETE FROM evaluation_replay_fixture",
            "UPDATE evaluation_scenario SET title = 'edited'",
        ],
    )
    def test_the_application_role_cannot_rewrite_results(
        self, suites: Suites, app_engine: Engine, statement: str
    ) -> None:
        with Session(bind=app_engine) as session:
            bind_tenant(session, suites.tenant_id)
            with pytest.raises(DBAPIError, match="permission denied"):
                session.execute(sa.text(statement))

    def test_another_tenant_sees_none_of_the_results(
        self, suites: Suites, owner_engine: Engine, app_engine: Engine
    ) -> None:
        other = ensure_tenant(_factory(owner_engine), f"ev-other-{uuid.uuid4().hex[:8]}")
        with Session(bind=app_engine) as session:
            bind_tenant(session, other)
            for model in (
                EvaluationSuiteRun,
                EvaluationRun,
                EvaluationReplayFixture,
                EvaluationScenario,
            ):
                assert session.scalar(sa.select(sa.func.count()).select_from(model)) == 0
            # Explicitly asking for the first tenant's rows does not bypass the policy.
            assert session.get(EvaluationSuiteRun, suites.simulator.suite_run_id) is None


def render(report: Any) -> str:
    return json.dumps(
        [
            (s["key"], s["verdict"], s["checks_failed"], s["error"])
            for s in report.get("scenarios", [])
        ]
    )


class TestRefusals:
    def test_a_tampered_replay_fixture_errors_instead_of_replaying(
        self, owner_engine: Engine, app_engine: Engine
    ) -> None:
        slug = f"ev-tamper-{uuid.uuid4().hex[:8]}"
        keys = ("EV-INV-001",)
        _harness(owner_engine, app_engine).run(
            HarnessConfig(tenant_slug=slug, keys=keys, baseline="none")
        )
        tenant = ensure_tenant(_factory(owner_engine), slug)
        with Session(bind=owner_engine) as session, session.begin():
            row = session.scalars(
                sa.select(EvaluationReplayFixture).where(
                    EvaluationReplayFixture.tenant_id == tenant
                )
            ).one()
            content = dict(row.content)
            content["model_calls"] = content["model_calls"][:-1]
            session.execute(
                sa.update(EvaluationReplayFixture)
                .where(EvaluationReplayFixture.id == row.id)
                .values(content=content)
            )
        replay = _harness(owner_engine, app_engine).run(
            HarnessConfig(tenant_slug=slug, keys=keys, mode=ExecutionMode.REPLAY, baseline="none")
        )
        assert replay.status == "errored"
        (scenario,) = replay.report["scenarios"]
        assert scenario["verdict"] == "errored"
        assert "refused" in scenario["error"] and "digest" in scenario["error"]

    def test_a_scenario_changed_without_a_version_bump_is_refused(
        self, owner_engine: Engine, app_engine: Engine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        slug = f"ev-bump-{uuid.uuid4().hex[:8]}"
        keys = ("EV-SEC-001",)
        first = _harness(owner_engine, app_engine).run(
            HarnessConfig(tenant_slug=slug, keys=keys, baseline="none")
        )
        assert first.status == "passed", render(first.report)
        original = select(keys)[0]
        edited = dataclasses.replace(original, title="silently edited expectation")
        monkeypatch.setattr(harness_module, "select", lambda keys, suite: (edited,))
        second = _harness(owner_engine, app_engine).run(
            HarnessConfig(tenant_slug=slug, keys=keys, baseline="none")
        )
        assert second.status == "errored"
        assert "without a version bump" in second.report["scenarios"][0]["error"]

    def test_a_tampered_baseline_is_refused(
        self, suites: Suites, owner_engine: Engine, app_engine: Engine
    ) -> None:
        slug = f"ev-base-{uuid.uuid4().hex[:8]}"
        keys = ("EV-SEC-001",)
        baseline = _harness(owner_engine, app_engine).run(
            HarnessConfig(tenant_slug=slug, keys=keys, baseline="none")
        )
        with Session(bind=owner_engine) as session, session.begin():
            row = session.get(EvaluationSuiteRun, baseline.suite_run_id)
            assert row is not None
            report = dict(row.report)
            report["gate_status"] = "passed-and-then-some"
            session.execute(
                sa.update(EvaluationSuiteRun)
                .where(EvaluationSuiteRun.id == row.id)
                .values(report=report)
            )
        with pytest.raises(HarnessRefused, match="baseline"):
            _harness(owner_engine, app_engine).run(
                HarnessConfig(tenant_slug=slug, keys=keys, baseline=str(baseline.suite_run_id))
            )

    def test_the_harness_refuses_a_production_deployment(
        self, owner_engine: Engine, app_engine: Engine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DEPLOYMENT_ENV_VAR, "production")
        with pytest.raises(HarnessRefused):
            _harness(owner_engine, app_engine)


class TestJudgesInTheHarness:
    def test_disagreeing_judges_contest_without_failing_and_are_recorded(
        self, owner_engine: Engine, app_engine: Engine
    ) -> None:
        def judge(key: str, score: float) -> LlmJudge:
            reply = json.dumps({"score": score, "cited_evidence_ids": [], "rationale": "scripted"})
            return LlmJudge(key, ScriptedJudgeModel(reply))

        slug = f"ev-judge-{uuid.uuid4().hex[:8]}"
        outcome = _harness(
            owner_engine, app_engine, judge_panel=JudgePanel([judge("a", 0.9), judge("b", 0.1)])
        ).run(HarnessConfig(tenant_slug=slug, keys=("EV-INV-001",), baseline="none"))
        (scenario,) = outcome.report["scenarios"]
        assert scenario["verdict"] == "contested"
        assert outcome.status == "passed"  # a judge never decides the gate
        assert outcome.report["aggregate"]["llm_judge"] == {"contested": 1}
        tenant = ensure_tenant(_factory(owner_engine), slug)
        with Session(bind=owner_engine) as session:
            results = session.scalars(
                sa.select(EvaluationJudgeResult).where(EvaluationJudgeResult.tenant_id == tenant)
            ).all()
            assert sorted(float(r.score) for r in results if r.score is not None) == [0.1, 0.9]
            assert {r.outcome for r in results} == {JudgeOutcome.SCORED}
            assert {r.calibration_status for r in results} == {"uncalibrated"}


class TestGateCli:
    def test_exit_codes(self, database_url: str, _ensure_test_app_role: str, tmp_path: Any) -> None:
        output = tmp_path / "report.json"
        common = [
            "--database-url",
            _ensure_test_app_role,
            "--admin-database-url",
            database_url,
            "--tenant-slug",
            f"ev-cli-{uuid.uuid4().hex[:8]}",
        ]
        assert gate.main([*common, "--scenario", "EV-SEC-001", "--output", str(output)]) == 0
        assert json.loads(output.read_text(encoding="utf-8"))["gate_status"] == "passed"
        # A replay with nothing recorded cannot produce a trustworthy result.
        assert gate.main([*common, "--scenario", "EV-INV-001", "--mode", "replay"]) == 2


SECRET = "phase11-test-signing-secret-is-not-production"
SETTINGS = ApiSettings(jwt_secret=SECRET, rate_limit_per_minute=100)


class TestEvaluationApi:
    def _client(self, app_engine: Engine) -> TestClient:
        return TestClient(create_app(settings=SETTINGS, factory=_factory(app_engine)))

    def _headers(
        self, owner_engine: Engine, tenant: uuid.UUID, role_key: str, *, env: Any
    ) -> dict[str, str]:
        subject = f"{role_key}-{uuid.uuid4().hex[:8]}"
        with Session(bind=owner_engine) as session, session.begin():
            bind_tenant(session, tenant)
            user = User(
                id=uuid.uuid4(),
                tenant_id=tenant,
                external_idp_subject=subject,
                email=f"{subject}@example.invalid",
                display_name=subject,
                status=UserStatus.ACTIVE,
            )
            session.add(user)
            session.flush()
            role = session.scalar(sa.select(Role).where(Role.key == role_key))
            assert role is not None
            session.add(
                UserRoleAssignment(
                    id=uuid.uuid4(),
                    tenant_id=tenant,
                    user_id=user.id,
                    role_id=role.id,
                    environment_id=env,
                )
            )
        token = jwt.encode(
            {
                "sub": subject,
                "tenant_id": str(tenant),
                "iss": SETTINGS.jwt_issuer,
                "aud": SETTINGS.jwt_audience,
                "exp": int(time.time()) + 300,
            },
            SECRET,
            algorithm="HS256",
        )
        return {"Authorization": f"Bearer {token}"}

    def test_reads_sealed_results_with_tenant_wide_authority(
        self, suites: Suites, owner_engine: Engine, app_engine: Engine
    ) -> None:
        client = self._client(app_engine)
        headers = self._headers(owner_engine, suites.tenant_id, "system_operator", env=None)
        listed = client.get("/api/v1/evaluation/suite-runs", headers=headers)
        assert listed.status_code == 200
        ids = {item["id"] for item in listed.json()["items"]}
        assert {str(suites.simulator.suite_run_id), str(suites.replay.suite_run_id)} <= ids
        detail = client.get(
            f"/api/v1/evaluation/suite-runs/{suites.replay.suite_run_id}", headers=headers
        ).json()
        assert detail["report_verified"] is True
        assert detail["gate_status"] == "passed"
        assert detail["baseline_suite_run_id"] == str(suites.simulator.suite_run_id)
        runs = client.get(
            "/api/v1/evaluation/runs",
            params={"suite_run_id": str(suites.replay.suite_run_id)},
            headers=headers,
        ).json()["items"]
        assert {r["scenario_key"] for r in runs} == set(KEYS)
        assert {r["execution_mode"] for r in runs} == {"replay"}
        # Execution is the gate's job, not an API caller's.
        assert client.post("/api/v1/evaluation/suite-runs", headers=headers).status_code == 405

    def test_environment_scoped_and_foreign_principals_cannot_read(
        self, suites: Suites, owner_engine: Engine, app_engine: Engine
    ) -> None:
        client = self._client(app_engine)
        with Session(bind=owner_engine) as session:
            bind_tenant(session, suites.tenant_id)
            environment = session.scalar(
                sa.text("SELECT id FROM environment WHERE tenant_id = :t LIMIT 1"),
                {"t": suites.tenant_id},
            )
        scoped = self._headers(owner_engine, suites.tenant_id, "system_operator", env=environment)
        assert client.get("/api/v1/evaluation/suite-runs", headers=scoped).status_code == 403
        other = ensure_tenant(_factory(owner_engine), f"ev-api-{uuid.uuid4().hex[:8]}")
        foreign = self._headers(owner_engine, other, "system_operator", env=None)
        assert client.get("/api/v1/evaluation/suite-runs", headers=foreign).json()["items"] == []
        missing = client.get(
            f"/api/v1/evaluation/suite-runs/{suites.simulator.suite_run_id}", headers=foreign
        )
        assert missing.status_code == 404
