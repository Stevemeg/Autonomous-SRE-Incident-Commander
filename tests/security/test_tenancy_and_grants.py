"""Phase 13 tenancy, least-privilege and referential-integrity proof against a live schema.

The mechanical audit (``asic.db.tenancy_audit``) is exercised twice: once to show the real
migrated schema is clean, and once *per mutation* to show each guard actually fires - an
audit that could not fail would prove nothing. Behavioural cross-tenant attacks on the
unprivileged application role live in ``tests/db/test_tenant_isolation.py``; this module
adds the checks that only exist since Phase 13.
"""

from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from asic.db.models import (
    ConnectorScopeBinding,
    ExecutionTrace,
    IntegrationConnector,
    WorkflowRun,
    append_only_tables,
)
from asic.db.session import bind_tenant
from asic.db.tenancy_audit import (
    APP_ROLE,
    RUNTIME_READ_ONLY_TABLES,
    audit_schema,
    privilege_inventory,
)
from asic.domain.enums import IntegrationKind, WorkflowRunStatus
from asic.observability.trace_ids import (
    InvalidTraceId,
    is_valid_trace_id,
    require_valid_trace_id,
)
from tests.conftest import (
    make_behaviour_version,
    make_environment,
    make_incident,
    make_service,
    make_tenant,
)

pytestmark = pytest.mark.security


def codes(session: Session) -> set[str]:
    return {finding.code for finding in audit_schema(session.connection())}


@pytest.mark.postgres
class TestMechanicalAudit:
    def test_the_migrated_schema_is_clean(self, owner_session: Session) -> None:
        findings = audit_schema(owner_session.connection())
        assert findings == [], [f.render() for f in findings]

    @pytest.mark.parametrize(
        ("mutation", "expected"),
        [
            ("ALTER TABLE incident NO FORCE ROW LEVEL SECURITY", "rls_not_forced"),
            ("ALTER TABLE incident DISABLE ROW LEVEL SECURITY", "rls_disabled"),
            ("DROP POLICY tenant_isolation ON incident", "no_policy"),
            (
                "ALTER POLICY tenant_isolation ON incident USING (true)",
                "policy_using",
            ),
            (
                "ALTER POLICY tenant_isolation ON incident WITH CHECK (true)",
                "policy_with_check",
            ),
            (
                "ALTER TABLE alert ADD CONSTRAINT probe_fk FOREIGN KEY (incident_id) "
                "REFERENCES incident (id)",
                "fk_not_tenant_composite",
            ),
            (f"ALTER ROLE {APP_ROLE} BYPASSRLS", "role_bypasses_rls"),
            (f"ALTER ROLE {APP_ROLE} SUPERUSER", "role_bypasses_rls"),
            (f"ALTER TABLE incident OWNER TO {APP_ROLE}", "role_owns_table"),
            (f"GRANT CREATE ON SCHEMA public TO {APP_ROLE}", "role_can_create"),
            (f"GRANT DELETE ON incident TO {APP_ROLE}", "grant_forbidden"),
            (f"GRANT TRUNCATE ON incident TO {APP_ROLE}", "grant_forbidden"),
            (f"GRANT UPDATE ON audit_record TO {APP_ROLE}", "grant_append_only"),
            (f"GRANT INSERT ON app_user TO {APP_ROLE}", "grant_read_only"),
            (f"GRANT UPDATE ON alembic_version TO {APP_ROLE}", "grant_read_only"),
            (f"GRANT INSERT ON role TO {APP_ROLE}", "grant_read_only"),
            ("CREATE TABLE probe_untenanted (id int)", "unclassified_table"),
            (
                "CREATE TABLE probe_tenant_table (tenant_id uuid NOT NULL)",
                "unregistered_tenant_table",
            ),
            ("ALTER TABLE incident ALTER COLUMN tenant_id DROP NOT NULL", "tenant_id_nullable"),
        ],
    )
    def test_each_guard_fires_when_its_control_is_removed(
        self, owner_session: Session, mutation: str, expected: str
    ) -> None:
        owner_session.execute(sa.text(mutation))
        assert expected in codes(owner_session)

    def test_the_audit_role_is_not_privileged_and_owns_nothing(
        self, owner_session: Session
    ) -> None:
        row = owner_session.execute(
            sa.text("SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = :r"),
            {"r": APP_ROLE},
        ).one()
        assert (row.rolsuper, row.rolbypassrls) == (False, False)
        owned = owner_session.execute(
            sa.text(
                "SELECT count(*) FROM pg_class WHERE relowner = (SELECT oid FROM pg_roles WHERE rolname = :r)"
            ),
            {"r": APP_ROLE},
        ).scalar_one()
        assert owned == 0

    def test_the_session_role_used_for_isolation_tests_is_unprivileged(
        self, app_session: Session
    ) -> None:
        row = app_session.execute(
            sa.text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        ).one()
        assert (row.rolsuper, row.rolbypassrls) == (False, False)


@pytest.mark.postgres
class TestLeastPrivilege:
    def test_no_runtime_privilege_beyond_select_insert_update(self, owner_session: Session) -> None:
        inventory = privilege_inventory(owner_session.connection())
        assert inventory, "no tables found"
        for table, held in inventory.items():
            assert set(held) <= {"SELECT", "INSERT", "UPDATE"}, (table, held)

    def test_the_application_role_never_deletes_anything(self, owner_session: Session) -> None:
        inventory = privilege_inventory(owner_session.connection())
        assert [t for t, held in inventory.items() if "DELETE" in held] == []

    def test_append_only_tables_are_insert_and_select_only(self, owner_session: Session) -> None:
        inventory = privilege_inventory(owner_session.connection())
        for table in sorted(append_only_tables()):
            # Never UPDATE. (Some append-only tables are global catalogues the runtime only
            # reads; INSERT is then absent as well.)
            assert set(inventory[table]) <= {"SELECT", "INSERT"}, table
            assert "SELECT" in inventory[table], table

    def test_authority_and_configuration_tables_are_read_only_to_the_runtime(
        self, owner_session: Session
    ) -> None:
        inventory = privilege_inventory(owner_session.connection())
        for table in sorted(RUNTIME_READ_ONLY_TABLES):
            assert inventory[table] == ("SELECT",), (table, inventory[table])

    @pytest.mark.parametrize(
        ("table", "expected"),
        [
            ("audit_record", ("SELECT", "INSERT")),
            ("approval", ("SELECT", "INSERT")),
            ("remediation_target", ("SELECT", "INSERT")),
            ("remediation_baseline", ("SELECT", "INSERT")),
            ("verification", ("SELECT", "INSERT")),
            ("model_call_reservation", ("SELECT", "INSERT")),
            ("tool_execution", ("SELECT", "INSERT")),
            ("evaluation_run", ("SELECT", "INSERT")),
            ("connector_scope_binding", ("SELECT",)),
            ("integration_connector", ("SELECT",)),
            ("alembic_version", ("SELECT",)),
            ("role", ("SELECT",)),
            ("permission", ("SELECT",)),
        ],
    )
    def test_security_sensitive_tables_carry_exactly_the_documented_privileges(
        self, owner_session: Session, table: str, expected: tuple[str, ...]
    ) -> None:
        assert privilege_inventory(owner_session.connection())[table] == expected


def _world(session: Session, slug: str) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    tenant = make_tenant(session, slug)
    bind_tenant(session, tenant.id)
    environment = make_environment(session, tenant)
    service = make_service(session, tenant, f"svc-{slug}")
    session.flush()
    return tenant.id, environment.id, service.id


def _connector(
    session: Session, tenant_id: uuid.UUID, environment_id: uuid.UUID, connector_id: str
) -> None:
    session.add(
        IntegrationConnector(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            connector_id=connector_id,
            kind=IntegrationKind.PROMETHEUS,
            environment_id=environment_id,
            is_enabled=False,
        )
    )
    session.flush()


def _binding(
    tenant_id: uuid.UUID, connector_id: str, service_id: uuid.UUID, environment_id: uuid.UUID
) -> ConnectorScopeBinding:
    return ConnectorScopeBinding(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        connector_id=connector_id,
        source="prometheus",
        service_id=service_id,
        environment_id=environment_id,
    )


@pytest.mark.postgres
class TestConnectorReferentialIntegrity:
    """F-13: a scope binding must reference a real connector of the same tenant."""

    def test_a_binding_to_a_registered_connector_is_accepted(self, owner_session: Session) -> None:
        tenant, environment, service = _world(owner_session, "fk-ok")
        _connector(owner_session, tenant, environment, "prom-a")
        owner_session.add(_binding(tenant, "prom-a", service, environment))
        owner_session.flush()

    def test_a_binding_to_a_nonexistent_connector_is_refused(self, owner_session: Session) -> None:
        tenant, environment, service = _world(owner_session, "fk-none")
        owner_session.add(_binding(tenant, "ghost", service, environment))
        with pytest.raises(IntegrityError, match="fk_connector_scope_binding_connector"):
            owner_session.flush()

    def test_a_binding_cannot_reference_another_tenants_connector(
        self, owner_session: Session
    ) -> None:
        tenant_a, env_a, service_a = _world(owner_session, "fk-a")
        tenant_b, env_b, _ = _world(owner_session, "fk-b")
        _connector(owner_session, tenant_b, env_b, "prom-of-b")
        # Same connector_id string, wrong tenant: only the composite key catches it.
        owner_session.add(_binding(tenant_a, "prom-of-b", service_a, env_a))
        with pytest.raises(IntegrityError, match="fk_connector_scope_binding_connector"):
            owner_session.flush()

    def test_a_connector_with_authority_history_cannot_be_deleted(
        self, owner_session: Session
    ) -> None:
        tenant, environment, service = _world(owner_session, "fk-restrict")
        _connector(owner_session, tenant, environment, "prom-r")
        owner_session.add(_binding(tenant, "prom-r", service, environment))
        owner_session.flush()
        with pytest.raises(IntegrityError, match="fk_connector_scope_binding_connector"):
            owner_session.execute(
                sa.delete(IntegrationConnector).where(IntegrationConnector.connector_id == "prom-r")
            )


def _trace(session: Session, trace_id: str) -> ExecutionTrace:
    tenant = make_tenant(session, f"tr-{uuid.uuid4().hex[:10]}")
    bind_tenant(session, tenant.id)
    environment = make_environment(session, tenant)
    incident = make_incident(session, tenant, environment)
    behaviour = make_behaviour_version(session, f"tr-{uuid.uuid4().hex[:8]}")
    run = WorkflowRun(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        incident_id=incident.id,
        behaviour_version_id=behaviour.id,
        status=WorkflowRunStatus.RUNNING,
    )
    session.add(run)
    session.flush()
    return ExecutionTrace(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        workflow_run_id=run.id,
        incident_id=incident.id,
        behaviour_version_id=behaviour.id,
        trace_id=trace_id,
        correlation_id=uuid.uuid4(),
    )


class TestTraceIdRule:
    """F-11: one authoritative validity rule, in code and in the database."""

    @pytest.mark.parametrize("value", [uuid.uuid4().hex, "0" * 31 + "1", "f" * 32, "a1" * 16])
    def test_valid_ids(self, value: str) -> None:
        assert is_valid_trace_id(value)
        assert require_valid_trace_id(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "0" * 32,  # the W3C invalid id: OpenTelemetry would drop its spans
            "a" * 31,
            "a" * 33,
            "g" * 32,
            "A" * 32,  # uppercase is refused: one canonical spelling
            "0x" + "a" * 30,
            " " + "a" * 31,
            "a" * 31 + "\n",
            None,
            123,
            b"a" * 32,
        ],
    )
    def test_invalid_ids(self, value: object) -> None:
        assert not is_valid_trace_id(value)
        with pytest.raises(InvalidTraceId) as info:
            require_valid_trace_id(value)
        if isinstance(value, str) and value:
            assert value not in str(info.value)  # the offending value is never echoed

    @pytest.mark.postgres
    def test_the_database_accepts_a_valid_id(self, owner_session: Session) -> None:
        owner_session.add(_trace(owner_session, uuid.uuid4().hex))
        owner_session.flush()

    @pytest.mark.postgres
    @pytest.mark.parametrize("value", ["0" * 32, "a" * 31, "z" * 32, "A" * 32, ("a" * 31) + "\n"])
    def test_the_database_refuses_an_invalid_id(self, owner_session: Session, value: str) -> None:
        owner_session.add(_trace(owner_session, value))
        with pytest.raises(IntegrityError, match="trace_id_is_w3c_trace_id"):
            owner_session.flush()

    @pytest.mark.postgres
    def test_null_is_refused(self, owner_session: Session) -> None:
        trace = _trace(owner_session, uuid.uuid4().hex)
        trace.trace_id = None  # type: ignore[assignment]
        owner_session.add(trace)
        with pytest.raises(IntegrityError, match="null value"):
            owner_session.flush()


class TestPersistedTraceIdFailsSafely:
    """A historical row may hold a malformed id. It must fail loudly, never be re-minted."""

    @pytest.mark.parametrize("bad", ["not-hex-not-hex-not-hex-not-hex-", "0" * 32, "abc", ""])
    def test_a_recorder_refuses_a_malformed_persisted_id(self, bad: str) -> None:
        from asic.domain.clock import SystemClock
        from asic.observability.tracing import TraceRecorder

        with pytest.raises(InvalidTraceId):
            TraceRecorder(
                tenant_id=uuid.uuid4(),
                execution_trace_id=uuid.uuid4(),
                trace_id=bad,
                clock=SystemClock(),
            )

    def test_a_recorder_accepts_a_valid_id_and_keeps_it_verbatim(self) -> None:
        from asic.domain.clock import SystemClock
        from asic.observability.tracing import TraceRecorder

        good = uuid.uuid4().hex
        recorder = TraceRecorder(
            tenant_id=uuid.uuid4(),
            execution_trace_id=uuid.uuid4(),
            trace_id=good,
            clock=SystemClock(),
        )
        assert recorder.trace_id == good

    def test_the_nil_correlation_id_cannot_derive_a_trace_id(self) -> None:
        from asic.observability.tracing import derive_trace_id

        with pytest.raises(InvalidTraceId):
            derive_trace_id(uuid.UUID(int=0))
        assert derive_trace_id(uuid.UUID(int=1)) == "0" * 31 + "1"

    @pytest.mark.parametrize(
        ("trace", "span", "expected"),
        [
            ("a" * 32, "b" * 16, True),
            ("0" * 32, "b" * 16, False),
            ("a" * 32, "0" * 16, False),
            ("g" * 32, "b" * 16, False),
            ("A" * 32, "b" * 16, False),
            ("a" * 31, "b" * 16, False),
            ("a" * 32, "b" * 15, False),
        ],
    )
    def test_outbound_traceparent_is_only_built_from_valid_ids(
        self, trace: str, span: str, expected: bool
    ) -> None:
        from asic.tools.broker import _traceparent

        header = _traceparent(trace, span)
        assert (header is not None) is expected
        if expected:
            assert header == f"00-{trace}-{span}-01"
