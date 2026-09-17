"""Evaluation harness: suite runs, judge results, replay fixtures and immutable results.

Self-contained (ADR-0018). Builds on the Phase 3 ``evaluation_scenario`` and
``evaluation_run`` tables rather than duplicating them:

* ``evaluation_run`` gains the link to the suite and to the real workflow run the harness
  observed, the scenario digest, execution mode, evaluator version, deterministic check
  results and failure classes; its uniqueness is re-keyed per suite run;
* ``evaluation_suite_run`` records one sealed gate decision per suite execution;
* ``evaluation_judge_result`` records each LLM judge result separately, never averaged;
* ``evaluation_replay_fixture`` holds digest-sealed recorded tool and model responses.

Results are evidence, so the application role loses ``UPDATE`` and ``DELETE`` on
``evaluation_run`` and ``evaluation_scenario``: a scenario changes by publishing a new
version, and a result is never edited into a pass. New tables are insert/select only.

Revision ID: 0017_evaluation_harness
Revises: 0016_external_integrations
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0017_evaluation_harness"
down_revision: str | None = "0016_external_integrations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TENANT_TABLES: tuple[str, ...] = (
    "evaluation_suite_run",
    "evaluation_judge_result",
    "evaluation_replay_fixture",
)

EXECUTION_MODES: tuple[str, ...] = ("live", "simulator", "replay")
GATE_STATUSES: tuple[str, ...] = ("passed", "failed", "errored")
JUDGE_OUTCOMES: tuple[str, ...] = ("scored", "failed", "unavailable")


def _identity(table: str) -> tuple[sa.UniqueConstraint, sa.ForeignKeyConstraint]:
    return (
        sa.UniqueConstraint("tenant_id", "id", name=f"uq_{table}_tenant_id_id"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenant.id"], ondelete="RESTRICT", name=f"fk_{table}_tenant_id_tenant"
        ),
    )


def _protect(table: str) -> None:
    op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON {table} "
        "USING (tenant_id = app.current_tenant_id()) "
        "WITH CHECK (tenant_id = app.current_tenant_id())"
    )
    op.execute(f"GRANT SELECT, INSERT ON {table} TO asic_app")
    op.execute(f"GRANT SELECT ON {table} TO asic_auditor")


def upgrade() -> None:
    # The judge is a model caller, so it needs a node identity on a ModelRequest. Adding an
    # enum value cannot be undone by ALTER TYPE; the downgrade leaves this unused value in
    # place (see downgrade()).
    op.execute("ALTER TYPE node_id ADD VALUE IF NOT EXISTS 'e1_evaluation_judge'")
    bind = op.get_bind()
    for name, values in (
        ("execution_mode", EXECUTION_MODES),
        ("evaluation_gate_status", GATE_STATUSES),
        ("judge_outcome", JUDGE_OUTCOMES),
    ):
        pg.ENUM(*values, name=name).create(bind, checkfirst=False)
    mode = pg.ENUM(*EXECUTION_MODES, name="execution_mode", create_type=False)

    op.create_table(
        "evaluation_suite_run",
        sa.Column(
            "id", pg.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("suite_key", sa.String(64), nullable=False),
        sa.Column("suite_version", sa.Integer(), nullable=False),
        sa.Column("corpus_digest", sa.String(64), nullable=False),
        sa.Column("behaviour_version_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_mode", mode, nullable=False),
        sa.Column("evaluator_version", sa.String(64), nullable=False),
        sa.Column("baseline_suite_run_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "gate_status",
            pg.ENUM(*GATE_STATUSES, name="evaluation_gate_status", create_type=False),
            nullable=False,
        ),
        sa.Column("scenario_count", sa.Integer(), nullable=False),
        sa.Column("report", pg.JSONB(), nullable=False),
        sa.Column("report_digest", sa.String(64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_evaluation_suite_run"),
        *_identity("evaluation_suite_run"),
        sa.ForeignKeyConstraint(
            ["behaviour_version_id"],
            ["behaviour_version.id"],
            ondelete="RESTRICT",
            name="fk_evaluation_suite_run_behaviour_version",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "baseline_suite_run_id"],
            ["evaluation_suite_run.tenant_id", "evaluation_suite_run.id"],
            ondelete="RESTRICT",
            name="fk_evaluation_suite_run_baseline",
        ),
        sa.CheckConstraint("suite_version >= 1", name="suite_version_positive"),
        sa.CheckConstraint("scenario_count >= 0", name="scenario_count_non_negative"),
        sa.CheckConstraint("corpus_digest ~ '^[0-9a-f]{64}$'", name="corpus_digest_format"),
        sa.CheckConstraint("report_digest ~ '^[0-9a-f]{64}$'", name="report_digest_format"),
        sa.CheckConstraint("completed_at >= started_at", name="completed_after_start"),
        sa.CheckConstraint(
            "baseline_suite_run_id IS NULL OR baseline_suite_run_id <> id",
            name="baseline_is_not_self",
        ),
    )
    op.create_index(
        "ix_evaluation_suite_run_suite",
        "evaluation_suite_run",
        ["tenant_id", "suite_key", "completed_at"],
    )
    _protect("evaluation_suite_run")

    # ------------------------------------------------------------- evaluation_run
    op.add_column("evaluation_run", sa.Column("suite_run_id", pg.UUID(as_uuid=True), nullable=True))
    op.add_column(
        "evaluation_run", sa.Column("workflow_run_id", pg.UUID(as_uuid=True), nullable=True)
    )
    op.add_column("evaluation_run", sa.Column("scenario_digest", sa.String(64), nullable=True))
    op.add_column("evaluation_run", sa.Column("execution_mode", mode, nullable=True))
    op.add_column("evaluation_run", sa.Column("evaluator_version", sa.String(64), nullable=True))
    op.add_column(
        "evaluation_run",
        sa.Column("checks", pg.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
    )
    op.add_column(
        "evaluation_run",
        sa.Column(
            "failure_classes",
            pg.ARRAY(sa.String(64)),
            server_default=sa.text("'{}'::varchar[]"),
            nullable=False,
        ),
    )
    op.add_column("evaluation_run", sa.Column("wall_clock_ms", sa.Integer(), nullable=True))
    op.drop_constraint("uq_evaluation_run_repetition", "evaluation_run", type_="unique")
    op.create_unique_constraint(
        "uq_evaluation_run_repetition",
        "evaluation_run",
        ["tenant_id", "suite_run_id", "evaluation_scenario_id", "repetition_index"],
    )
    op.create_foreign_key(
        "fk_evaluation_run_suite_run",
        "evaluation_run",
        "evaluation_suite_run",
        ["tenant_id", "suite_run_id"],
        ["tenant_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_evaluation_run_workflow_run",
        "evaluation_run",
        "workflow_run",
        ["tenant_id", "workflow_run_id"],
        ["tenant_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        "scenario_digest_format",
        "evaluation_run",
        "scenario_digest IS NULL OR scenario_digest ~ '^[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        "wall_clock_non_negative", "evaluation_run", "wall_clock_ms IS NULL OR wall_clock_ms >= 0"
    )
    op.execute("REVOKE UPDATE, DELETE ON evaluation_run FROM asic_app")
    op.execute("REVOKE UPDATE, DELETE ON evaluation_scenario FROM asic_app")

    # ---------------------------------------------------------- judge results
    op.create_table(
        "evaluation_judge_result",
        sa.Column(
            "id", pg.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("evaluation_run_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("judge_key", sa.String(64), nullable=False),
        sa.Column("judge_provider", sa.String(128), nullable=False),
        sa.Column("judge_model", sa.String(128), nullable=False),
        sa.Column("rubric_id", sa.String(64), nullable=False),
        sa.Column("rubric_version", sa.String(32), nullable=False),
        sa.Column(
            "outcome",
            pg.ENUM(*JUDGE_OUTCOMES, name="judge_outcome", create_type=False),
            nullable=False,
        ),
        sa.Column("score", sa.Numeric(5, 4), nullable=True),
        sa.Column("calibration_status", sa.String(16), nullable=False),
        sa.Column(
            "cited_evidence_ids",
            pg.ARRAY(sa.String(64)),
            server_default=sa.text("'{}'::varchar[]"),
            nullable=False,
        ),
        sa.Column("failure_reason", sa.String(255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_evaluation_judge_result"),
        *_identity("evaluation_judge_result"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "evaluation_run_id"],
            ["evaluation_run.tenant_id", "evaluation_run.id"],
            ondelete="RESTRICT",
            name="fk_evaluation_judge_result_run",
        ),
        sa.UniqueConstraint(
            "tenant_id", "evaluation_run_id", "judge_key", "rubric_id", name="uq_judge_result"
        ),
        sa.CheckConstraint(
            "(outcome = 'scored') = (score IS NOT NULL)", name="score_only_when_scored"
        ),
        sa.CheckConstraint("score IS NULL OR (score >= 0 AND score <= 1)", name="score_range"),
        sa.CheckConstraint(
            "calibration_status IN ('uncalibrated', 'calibrated')", name="calibration_status_known"
        ),
    )
    _protect("evaluation_judge_result")

    # --------------------------------------------------------- replay fixtures
    op.create_table(
        "evaluation_replay_fixture",
        sa.Column(
            "id", pg.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("source_workflow_run_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column("scenario_key", sa.String(32), nullable=False),
        sa.Column("scenario_digest", sa.String(64), nullable=False),
        sa.Column("format_version", sa.Integer(), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("content", pg.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_evaluation_replay_fixture"),
        *_identity("evaluation_replay_fixture"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "source_workflow_run_id"],
            ["workflow_run.tenant_id", "workflow_run.id"],
            ondelete="RESTRICT",
            name="fk_evaluation_replay_fixture_run",
        ),
        sa.UniqueConstraint("tenant_id", "digest", name="uq_evaluation_replay_fixture_digest"),
        sa.CheckConstraint("digest ~ '^[0-9a-f]{64}$'", name="digest_format"),
        sa.CheckConstraint("scenario_digest ~ '^[0-9a-f]{64}$'", name="scenario_digest_format"),
        sa.CheckConstraint("format_version >= 1", name="format_version_positive"),
        sa.CheckConstraint("octet_length(content::text) <= 8000000", name="content_bounded"),
    )
    _protect("evaluation_replay_fixture")


def downgrade() -> None:
    """Reverse 0017, except the ``e1_evaluation_judge`` node_id value.

    PostgreSQL cannot drop an enum value without rebuilding every column of that type; the
    value is unused by 0016-era code and harmless, so it is intentionally left in place.

    Evaluation results are append-only history. If any suite run has been recorded the
    downgrade is refused rather than discarding it (the Phase 5 precedent): 0016's shape
    cannot hold several suite runs. Fail closed if migration credentials cannot see
    FORCE-RLS rows.
    """
    op.execute("SET LOCAL row_security = off")
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM evaluation_suite_run) THEN
            RAISE EXCEPTION 'evaluation suite history exists; downgrade refused';
        END IF;
        END $$""")
    op.drop_table("evaluation_replay_fixture")
    op.drop_table("evaluation_judge_result")

    op.execute("GRANT UPDATE, DELETE ON evaluation_scenario TO asic_app")
    op.execute("GRANT UPDATE, DELETE ON evaluation_run TO asic_app")
    op.drop_constraint("wall_clock_non_negative", "evaluation_run", type_="check")
    op.drop_constraint("scenario_digest_format", "evaluation_run", type_="check")
    op.drop_constraint("fk_evaluation_run_workflow_run", "evaluation_run", type_="foreignkey")
    op.drop_constraint("fk_evaluation_run_suite_run", "evaluation_run", type_="foreignkey")
    op.drop_constraint("uq_evaluation_run_repetition", "evaluation_run", type_="unique")
    op.create_unique_constraint(
        "uq_evaluation_run_repetition",
        "evaluation_run",
        [
            "tenant_id",
            "evaluation_scenario_id",
            "scenario_version",
            "behaviour_version_id",
            "repetition_index",
        ],
    )
    for column in (
        "wall_clock_ms",
        "failure_classes",
        "checks",
        "evaluator_version",
        "execution_mode",
        "scenario_digest",
        "workflow_run_id",
        "suite_run_id",
    ):
        op.drop_column("evaluation_run", column)

    op.drop_table("evaluation_suite_run")
    bind = op.get_bind()
    for name in ("judge_outcome", "evaluation_gate_status", "execution_mode"):
        pg.ENUM(name=name).drop(bind, checkfirst=False)
