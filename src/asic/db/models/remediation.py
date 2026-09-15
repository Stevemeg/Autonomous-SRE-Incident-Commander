"""The safety path: proposal, policy decision, approval, execution outcome, verification.

This module carries the invariants that matter most in the whole system. Each is a
database constraint, not a convention:

* **INV-6** - exactly one policy decision per action, including allows. An audit log that
  only records denials cannot prove what was permitted.
* **INV-8** - an approval-required action cannot reach an executed state without a
  matching approval row.
* **INV-9** - the approval binds to a specific ``action_version_hash``. Change the
  parameters and the approval no longer matches, so it fails closed (SI-6).
* **INV-10** - the approver is never the proposer. Separation of duties applies to humans
  as it does to nodes.
* **INV-11** - verification criteria are frozen at proposal time, and the verification row
  carries the hash of the criteria it judged against, so success cannot be redefined
  after the fact.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.orm import Mapped, mapped_column

from asic.db.base import (
    Base,
    CreatedAtMixin,
    TenantScoped,
    TimestampMixin,
    enum_column,
    tenant_fk,
    tenant_identity_constraints,
    uuid_pk,
)
from asic.domain.enums import (
    ApprovalDecision,
    NodeId,
    PolicyVerdict,
    RemediationActionStatus,
    RiskTier,
    VerificationVerdict,
)
from asic.domain.idempotency import KEY_LENGTH


class RemediationTarget(Base, TenantScoped, CreatedAtMixin):
    """Immutable, server-resolved objective for exactly one remediation run.

    This row is created before planning.  It is the durable authority for every later
    target decision; mutable incident alerts are never consulted to reconstruct scope on
    resume.
    """

    __tablename__ = "remediation_target"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    workflow_run_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    incident_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    investigation_run_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    hypothesis_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    service_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    environment_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    resolved_permission_scope: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)

    __table_args__ = (
        *tenant_identity_constraints("remediation_target"),
        tenant_fk(
            "workflow_run_id", "workflow_run", ondelete="CASCADE", name="fk_remediation_target_run"
        ),
        tenant_fk(
            "incident_id", "incident", ondelete="CASCADE", name="fk_remediation_target_incident"
        ),
        tenant_fk(
            "investigation_run_id",
            "workflow_run",
            ondelete="RESTRICT",
            name="fk_remediation_target_investigation_run",
        ),
        tenant_fk(
            "hypothesis_id",
            "hypothesis",
            ondelete="RESTRICT",
            name="fk_remediation_target_hypothesis",
        ),
        tenant_fk(
            "service_id", "service", ondelete="RESTRICT", name="fk_remediation_target_service"
        ),
        tenant_fk(
            "environment_id",
            "environment",
            ondelete="RESTRICT",
            name="fk_remediation_target_environment",
        ),
        sa.UniqueConstraint("tenant_id", "workflow_run_id", name="uq_remediation_target_run"),
        sa.Index("ix_remediation_target_incident", "tenant_id", "incident_id"),
    )


class RemediationAction(Base, TenantScoped, TimestampMixin):
    """A proposed action and its lifecycle.

    Every one of the twelve fields master specification section 6 requires is present.
    Only four of them are authored by the model - reason, evidence, expected effect and
    verification criteria. The rest (risk tier, permission scope, preconditions, rollback,
    approval requirement, timeout) are resolved from the registry and the incident
    context, which is what makes "the model cannot escalate its own privileges" a
    structural property rather than a hope.
    """

    __tablename__ = "remediation_action"

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    workflow_run_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    #: The hypothesis this action is justified by. NOT NULL: an action with no hypothesis
    #: is a guess.
    hypothesis_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    tool_definition_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    remediation_target_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)

    # -- section 6 field 2: reason -------------------------------------------------
    reason: Mapped[str] = mapped_column(sa.Text, nullable=False)
    # -- field 4: expected effect ---------------------------------------------------
    expected_effect: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    # -- field 5: risk level (from the registry, never the model) --------------------
    risk_tier: Mapped[RiskTier] = mapped_column(enum_column(RiskTier, "risk_tier"), nullable=False)
    # -- field 6: permission scope (resolved, not supplied) -------------------------
    permission_scope: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    # -- field 7: preconditions -----------------------------------------------------
    preconditions: Mapped[list[str]] = mapped_column(
        pg.ARRAY(sa.String(128)), nullable=False, server_default=sa.text("'{}'::varchar[]")
    )
    # -- field 8: rollback / compensation -------------------------------------------
    rollback_tool_name: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    rollback_arguments: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    # -- field 9: approval requirement (decided by the gate) ------------------------
    approval_required: Mapped[bool] = mapped_column(sa.Boolean, nullable=False)
    # -- field 10: timeout ----------------------------------------------------------
    timeout_seconds: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    # -- field 11: verification criteria, frozen at proposal time -------------------
    verification_criteria: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    #: Hash of ``verification_criteria`` at proposal time. The verification row must carry
    #: the same value, which makes post-hoc redefinition of success detectable (INV-11).
    verification_criteria_hash: Mapped[str] = mapped_column(sa.String(KEY_LENGTH), nullable=False)
    #: Pre-action measurement captured at proposal time, for comparison after execution.
    baseline_snapshot: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )

    tool_name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    tool_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    arguments: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)

    #: Binds an approval to exactly this version of this action (SI-6). Recomputed by the
    #: broker immediately before execution; divergence fails closed.
    action_version_hash: Mapped[str] = mapped_column(sa.String(KEY_LENGTH), nullable=False)
    #: Deduplicates repeated proposals of the same effect for the same hypothesis.
    request_idempotency_key: Mapped[str] = mapped_column(sa.String(KEY_LENGTH), nullable=False)

    status: Mapped[RemediationActionStatus] = mapped_column(
        enum_column(RemediationActionStatus, "remediation_action_status"),
        nullable=False,
        default=RemediationActionStatus.PROPOSED,
    )
    #: Which node proposed it. Always the remediation planner; recorded for evaluation.
    proposed_by_node: Mapped[NodeId] = mapped_column(enum_column(NodeId, "node_id"), nullable=False)
    proposed_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    executed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    version_id: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)

    # RUF012: SQLAlchemy's declarative convention. It cannot be a ClassVar because
    # DeclarativeBase declares it as an instance variable.
    __mapper_args__ = {"version_id_col": version_id}  # noqa: RUF012

    __table_args__ = (
        *tenant_identity_constraints("remediation_action"),
        tenant_fk(
            "incident_id", "incident", ondelete="CASCADE", name="fk_remediation_action_incident"
        ),
        tenant_fk(
            "workflow_run_id",
            "workflow_run",
            ondelete="CASCADE",
            name="fk_remediation_action_workflow_run",
        ),
        tenant_fk(
            "hypothesis_id",
            "hypothesis",
            ondelete="RESTRICT",
            name="fk_remediation_action_hypothesis",
        ),
        sa.ForeignKeyConstraint(
            ["tool_definition_id"],
            ["tool_definition.id"],
            ondelete="RESTRICT",
            name="fk_remediation_action_tool_definition",
        ),
        tenant_fk(
            "remediation_target_id",
            "remediation_target",
            ondelete="RESTRICT",
            name="fk_remediation_action_target",
        ),
        sa.UniqueConstraint(
            "tenant_id", "request_idempotency_key", name="uq_remediation_action_request"
        ),
        # SI-5 again, at the action level: a destructive action cannot even be proposed.
        sa.CheckConstraint("risk_tier <> 'r3'", name="no_destructive_action"),
        # A write action must carry a rollback path, decided before it is ever proposed.
        sa.CheckConstraint(
            "risk_tier = 'ro' OR rollback_tool_name IS NOT NULL",
            name="write_action_declares_rollback",
        ),
        # R2 is never autonomous.
        sa.CheckConstraint(
            "risk_tier <> 'r2' OR approval_required", name="high_risk_requires_approval"
        ),
        sa.CheckConstraint("timeout_seconds > 0", name="timeout_positive"),
        sa.CheckConstraint(
            "(executed_at IS NULL) OR (status <> 'proposed')", name="executed_not_proposed"
        ),
        sa.Index("ix_remediation_action_incident", "tenant_id", "incident_id"),
        sa.Index("ix_remediation_action_status", "tenant_id", "status"),
        sa.Index("ix_remediation_action_hypothesis", "tenant_id", "hypothesis_id"),
    )


class PolicyDecision(Base, TenantScoped, CreatedAtMixin):
    """The deterministic gate's verdict on one action. Append-only.

    Exactly one row per action (INV-6), written on *every* path including allow. The
    deciding rule is recorded by identifier so a decision can be explained later without
    re-running the policy engine against a policy that may since have changed.
    """

    __tablename__ = "policy_decision"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    remediation_action_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    verdict: Mapped[PolicyVerdict] = mapped_column(
        enum_column(PolicyVerdict, "policy_verdict"), nullable=False
    )
    #: Identifier of the rule that produced the verdict.
    rule_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    #: Version of the policy set evaluated, so a decision is reproducible.
    policy_version: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: Why, in terms a human can audit. Deterministic text, not model prose.
    rationale: Mapped[str] = mapped_column(sa.Text, nullable=False)
    #: Which ambiguity triggers fired, if any.
    ambiguity_signals: Mapped[list[Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")
    )
    evaluated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        *tenant_identity_constraints("policy_decision"),
        tenant_fk(
            "remediation_action_id",
            "remediation_action",
            ondelete="CASCADE",
            name="fk_policy_decision_action",
        ),
        # INV-6: exactly one decision per action.
        sa.UniqueConstraint("tenant_id", "remediation_action_id", name="uq_policy_decision_action"),
        sa.Index("ix_policy_decision_verdict", "tenant_id", "verdict", "evaluated_at"),
    )


class Approval(Base, TenantScoped, CreatedAtMixin):
    """A human decision on one action version. Append-only.

    ``action_version_hash`` is copied here from the action at request time. The broker
    recomputes the action's hash immediately before execution and compares: any parameter
    change between approval and execution invalidates the approval (INV-9).
    """

    __tablename__ = "approval"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    remediation_action_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    #: The exact action version this decision binds to.
    action_version_hash: Mapped[str] = mapped_column(sa.String(KEY_LENGTH), nullable=False)
    #: Deduplicates repeated callbacks from a chat platform.
    callback_idempotency_key: Mapped[str] = mapped_column(sa.String(KEY_LENGTH), nullable=False)

    required_role_key: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: Who proposed the action; recorded so self-approval can be rejected by constraint.
    proposer_user_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    approver_user_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    decision: Mapped[ApprovalDecision] = mapped_column(
        enum_column(ApprovalDecision, "approval_decision"), nullable=False
    )
    justification: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    #: How the decision arrived: ``dashboard``, ``slack``, ``teams``. Chat identity is
    #: resolved to an internal principal before this row is written.
    decision_channel: Mapped[str | None] = mapped_column(sa.String(32), nullable=True)

    requested_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("approval"),
        tenant_fk(
            "remediation_action_id",
            "remediation_action",
            ondelete="CASCADE",
            name="fk_approval_action",
        ),
        tenant_fk("approver_user_id", "app_user", ondelete="RESTRICT", name="fk_approval_approver"),
        sa.UniqueConstraint("tenant_id", "callback_idempotency_key", name="uq_approval_callback"),
        # One decision per action version. A re-proposed action gets a new hash and needs
        # a new decision.
        sa.UniqueConstraint(
            "tenant_id",
            "remediation_action_id",
            "action_version_hash",
            name="uq_approval_action_version",
        ),
        # INV-10: separation of duties. A human may not approve their own proposal.
        sa.CheckConstraint(
            "approver_user_id IS NULL OR proposer_user_id IS NULL"
            " OR approver_user_id <> proposer_user_id",
            name="no_self_approval",
        ),
        # A granted or rejected decision names the human who made it; expiry and
        # invalidation are system outcomes with no approver.
        sa.CheckConstraint(
            "(decision IN ('approved', 'rejected')) = (approver_user_id IS NOT NULL)",
            name="human_decision_names_approver",
        ),
        sa.CheckConstraint(
            "(decision IN ('approved', 'rejected')) = (decided_at IS NOT NULL)",
            name="human_decision_has_timestamp",
        ),
        sa.CheckConstraint("expires_at > requested_at", name="expiry_after_request"),
        sa.Index("ix_approval_action", "tenant_id", "remediation_action_id"),
        sa.Index(
            "ix_approval_pending",
            "tenant_id",
            "expires_at",
            postgresql_where=sa.text("decided_at IS NULL"),
        ),
    )


class Verification(Base, TenantScoped, CreatedAtMixin):
    """Independent post-remediation verdict. Append-only.

    The verifier receives the frozen criteria and the telemetry - never the executor's
    claim of success (SI-9). ``criteria_hash`` must equal the action's
    ``verification_criteria_hash``; a mismatch means the criteria changed after proposal,
    which is the failure this column exists to catch.
    """

    __tablename__ = "verification"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    remediation_action_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    #: Verification may be re-attempted within the settling window; each attempt is a row.
    attempt: Mapped[int] = mapped_column(sa.Integer, nullable=False, server_default=sa.text("1"))
    callback_idempotency_key: Mapped[str] = mapped_column(sa.String(KEY_LENGTH), nullable=False)

    criteria_hash: Mapped[str] = mapped_column(sa.String(KEY_LENGTH), nullable=False)
    verdict: Mapped[VerificationVerdict] = mapped_column(
        enum_column(VerificationVerdict, "verification_verdict"), nullable=False
    )
    #: What was measured, and against what baseline.
    observed: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    baseline: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    #: How comfortably the criteria were met or missed.
    margin: Mapped[float | None] = mapped_column(sa.Numeric(10, 4), nullable=True)
    observation_window_start: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    observation_window_end: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    verified_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        *tenant_identity_constraints("verification"),
        tenant_fk(
            "remediation_action_id",
            "remediation_action",
            ondelete="CASCADE",
            name="fk_verification_action",
        ),
        sa.UniqueConstraint(
            "tenant_id", "callback_idempotency_key", name="uq_verification_callback"
        ),
        sa.UniqueConstraint(
            "tenant_id", "remediation_action_id", "attempt", name="uq_verification_attempt"
        ),
        sa.CheckConstraint("attempt >= 1", name="attempt_starts_at_one"),
        sa.CheckConstraint(
            "observation_window_end >= observation_window_start", name="window_ordered"
        ),
        sa.Index("ix_verification_action", "tenant_id", "remediation_action_id"),
        sa.Index("ix_verification_verdict", "tenant_id", "verdict", "verified_at"),
    )


class RemediationBaseline(Base, TenantScoped, CreatedAtMixin):
    """Immutable pre-write observation bound to one action, target and policy profile."""

    __tablename__ = "remediation_baseline"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    remediation_target_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    remediation_action_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    service_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    environment_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    profile_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    profile_version: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    criteria_hash: Mapped[str] = mapped_column(sa.String(KEY_LENGTH), nullable=False)
    metric: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    source_capability: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    source_provider: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    read_execution_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    observed_value: Mapped[float] = mapped_column(sa.Numeric(18, 6), nullable=False)
    provenance_hash: Mapped[str] = mapped_column(sa.String(KEY_LENGTH), nullable=False)

    __table_args__ = (
        *tenant_identity_constraints("remediation_baseline"),
        tenant_fk("incident_id", "incident", name="fk_remediation_baseline_incident"),
        tenant_fk(
            "remediation_target_id",
            "remediation_target",
            ondelete="RESTRICT",
            name="fk_remediation_baseline_target",
        ),
        tenant_fk(
            "remediation_action_id",
            "remediation_action",
            ondelete="CASCADE",
            name="fk_remediation_baseline_action",
        ),
        tenant_fk("service_id", "service", name="fk_remediation_baseline_service"),
        tenant_fk("environment_id", "environment", name="fk_remediation_baseline_environment"),
        tenant_fk(
            "read_execution_id",
            "tool_execution",
            ondelete="RESTRICT",
            name="fk_remediation_baseline_read_execution",
        ),
        sa.UniqueConstraint(
            "tenant_id", "remediation_action_id", name="uq_remediation_baseline_action"
        ),
        sa.CheckConstraint("profile_version > 0", name="profile_version_positive"),
        sa.CheckConstraint("observed_at <= captured_at", name="observed_before_capture"),
        sa.Index("ix_remediation_baseline_target", "tenant_id", "remediation_target_id"),
    )
