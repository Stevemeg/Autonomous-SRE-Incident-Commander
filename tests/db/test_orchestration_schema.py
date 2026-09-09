"""The checkpoint table is protected exactly like every other tenant-scoped table.

Phase 3 established that tenant isolation is a database property. A table added in a later
phase must inherit that property or the guarantee stops being one, so these assertions are
against the live database rather than against the model definitions.
"""

from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from asic.db.models import WorkflowCheckpoint, append_only_tables, tenant_scoped_tables
from asic.db.session import bind_tenant, clear_tenant
from asic.orchestration.checkpoint import CHECKPOINT_REASONS
from tests.conftest import requires_postgres
from tests.kernel_fixtures import build_fixture

pytestmark = requires_postgres

TABLE = "workflow_checkpoint"


class TestCoverage:
    def test_the_checkpoint_table_is_tenant_scoped(self) -> None:
        assert TABLE in tenant_scoped_tables()

    def test_the_checkpoint_table_is_append_only(self) -> None:
        assert TABLE in append_only_tables()

    def test_row_level_security_is_enabled_and_forced(self, owner_session: Session) -> None:
        enabled, forced = owner_session.execute(
            sa.text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = :t AND relkind = 'r'"
            ),
            {"t": TABLE},
        ).one()
        assert enabled is True
        # FORCE is the load-bearing half: ENABLE alone exempts the table owner.
        assert forced is True

    def test_the_policy_checks_reads_and_writes(self, owner_session: Session) -> None:
        using, with_check = owner_session.execute(
            sa.text(
                "SELECT qual, with_check FROM pg_policies "
                "WHERE tablename = :t AND policyname = 'tenant_isolation'"
            ),
            {"t": TABLE},
        ).one()
        assert "current_tenant_id" in using
        # Without WITH CHECK a session could insert rows it could not read back.
        assert with_check is not None
        assert "current_tenant_id" in with_check

    def test_every_tenant_scoped_table_in_the_models_is_protected(
        self, owner_session: Session
    ) -> None:
        # Derived from the mappings, so a new tenant-scoped table cannot be added without
        # a migration that protects it.
        protected = set(
            owner_session.execute(
                sa.text(
                    "SELECT relname FROM pg_class WHERE relkind = 'r' "
                    "AND relrowsecurity AND relforcerowsecurity"
                )
            ).scalars()
        )
        missing = tenant_scoped_tables() - protected
        assert missing == set(), f"unprotected tenant-scoped table(s): {sorted(missing)}"

    def test_the_application_role_cannot_rewrite_a_checkpoint(self, owner_session: Session) -> None:
        privileges = set(
            owner_session.execute(
                sa.text(
                    "SELECT privilege_type FROM information_schema.role_table_grants "
                    "WHERE table_name = :t AND grantee = 'asic_app'"
                ),
                {"t": TABLE},
            ).scalars()
        )
        assert "SELECT" in privileges
        assert "INSERT" in privileges
        assert "UPDATE" not in privileges, "a rewritable checkpoint can misdirect a resume"
        assert "DELETE" not in privileges


class TestIsolation:
    def test_a_checkpoint_is_invisible_to_another_tenant(self, app_session: Session) -> None:
        first = build_fixture(app_session, slug="ckpt-a")
        app_session.add(_checkpoint(first.tenant_id, first))
        app_session.flush()

        second = build_fixture(app_session, slug="ckpt-b")
        # Bound to the second tenant now: the first tenant's checkpoints must be gone.
        visible = list(app_session.execute(sa.select(WorkflowCheckpoint.id)).scalars())
        assert visible == []
        assert second.tenant_id != first.tenant_id

    def test_with_no_tenant_bound_nothing_is_visible(self, app_session: Session) -> None:
        fixture = build_fixture(app_session, slug="ckpt-unbound")
        app_session.add(_checkpoint(fixture.tenant_id, fixture))
        app_session.flush()
        assert list(app_session.execute(sa.select(WorkflowCheckpoint.id)).scalars())

        clear_tenant(app_session)
        # Note the query has no tenant predicate at all. Forgetting one must yield nothing.
        assert list(app_session.execute(sa.select(WorkflowCheckpoint.id)).scalars()) == []

    def test_writing_a_checkpoint_for_another_tenant_is_refused(self, app_session: Session) -> None:
        fixture = build_fixture(app_session, slug="ckpt-crosswrite")
        bind_tenant(app_session, fixture.tenant_id)
        row = _checkpoint(uuid.uuid4(), fixture)
        app_session.add(row)
        with pytest.raises((IntegrityError, DBAPIError)):
            app_session.flush()
        app_session.rollback()


class TestConstraints:
    def test_an_unknown_reason_is_refused(self, app_session: Session) -> None:
        fixture = build_fixture(app_session, slug="ckpt-reason")
        row = _checkpoint(fixture.tenant_id, fixture, reason="whenever")
        app_session.add(row)
        with pytest.raises((IntegrityError, DBAPIError)):
            app_session.flush()
        app_session.rollback()

    def test_the_known_reasons_match_the_constraint(self, app_session: Session) -> None:
        fixture = build_fixture(app_session, slug="ckpt-reasons-ok")
        for index, reason in enumerate(sorted(CHECKPOINT_REASONS), start=1):
            app_session.add(_checkpoint(fixture.tenant_id, fixture, reason=reason, sequence=index))
        app_session.flush()

    def test_a_short_digest_is_refused(self, app_session: Session) -> None:
        fixture = build_fixture(app_session, slug="ckpt-digest")
        row = _checkpoint(fixture.tenant_id, fixture)
        row.state_digest = "tooshort"
        app_session.add(row)
        with pytest.raises((IntegrityError, DBAPIError)):
            app_session.flush()
        app_session.rollback()

    def test_a_duplicate_sequence_within_a_run_is_refused(self, app_session: Session) -> None:
        fixture = build_fixture(app_session, slug="ckpt-dupseq")
        app_session.add(_checkpoint(fixture.tenant_id, fixture, sequence=1))
        app_session.flush()
        app_session.add(_checkpoint(fixture.tenant_id, fixture, sequence=1))
        with pytest.raises((IntegrityError, DBAPIError)):
            app_session.flush()
        app_session.rollback()

    def test_a_zero_sequence_is_refused(self, app_session: Session) -> None:
        fixture = build_fixture(app_session, slug="ckpt-zeroseq")
        app_session.add(_checkpoint(fixture.tenant_id, fixture, sequence=0))
        with pytest.raises((IntegrityError, DBAPIError)):
            app_session.flush()
        app_session.rollback()


def _checkpoint(
    tenant_id: uuid.UUID,
    fixture: object,
    *,
    reason: str = "node_boundary",
    sequence: int = 1,
) -> WorkflowCheckpoint:
    """A checkpoint row attached to a run created for the fixture's incident."""
    from asic.db.models import WorkflowRun
    from asic.domain.enums import WorkflowRunStatus

    incident = fixture.incident  # type: ignore[attr-defined]
    behaviour = fixture.behaviour_version  # type: ignore[attr-defined]
    session = sa.orm.object_session(incident)
    assert session is not None
    run = session.execute(
        sa.select(WorkflowRun).where(WorkflowRun.incident_id == incident.id)
    ).scalar_one_or_none()
    if run is None:
        run = WorkflowRun(
            id=uuid.uuid4(),
            tenant_id=incident.tenant_id,
            incident_id=incident.id,
            behaviour_version_id=behaviour.id,
            status=WorkflowRunStatus.RUNNING,
        )
        session.add(run)
        session.flush()
    return WorkflowCheckpoint(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        workflow_run_id=run.id,
        incident_id=incident.id,
        sequence=sequence,
        after_node="planner",
        reason=reason,
        state={"phase": "planning"},
        state_digest="a" * 64,
        durable_counts={},
        budget_consumed={},
        behaviour_version_id=behaviour.id,
        correlation_id=uuid.uuid4(),
    )
