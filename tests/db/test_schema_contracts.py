"""Schema-level contracts.

These tests assert properties of the schema as a whole rather than of any one table, so a
new table cannot quietly opt out of tenancy, auditability or the safety guards.
"""

from __future__ import annotations

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from asic.db.models import (
    GLOBAL_TABLES,
    Base,
    append_only_tables,
    metadata_obj,
    tenant_scoped_tables,
)
from asic.domain.safety import (
    check_field_names,
    is_forbidden_execution_field,
    is_secret_reference,
)

pytestmark = pytest.mark.postgres


class TestNoArbitraryExecutionChannel:
    """Master specification section 6: no arbitrary command execution, structurally."""

    def test_no_table_has_a_free_form_command_column(self) -> None:
        offenders: list[str] = []
        for table in metadata_obj.tables.values():
            for column in table.columns:
                if is_forbidden_execution_field(column.name):
                    offenders.append(f"{table.name}.{column.name}")
        assert offenders == [], (
            "these columns would create an arbitrary-execution channel: " + ", ".join(offenders)
        )

    def test_no_table_stores_secret_material(self) -> None:
        """A ``credential_ref`` naming a secret is fine; a column holding one is not."""
        offenders: list[str] = []
        for table in metadata_obj.tables.values():
            for column in table.columns:
                if is_secret_reference(column.name):
                    continue
                if check_field_names([column.name]):
                    offenders.append(f"{table.name}.{column.name}")
        # Execution channels are reported by the test above; here we care about secrets.
        secrets = [o for o in offenders if not is_forbidden_execution_field(o.split(".")[-1])]
        assert secrets == [], "these columns would store secret material: " + ", ".join(secrets)

    def test_the_guard_itself_detects_a_planted_offender(self) -> None:
        """A guard that never fires is indistinguishable from a guard that does not work."""
        assert check_field_names(["namespace", "shell_command"]) != []


class TestTenancyContract:
    def test_every_tenant_scoped_table_has_a_tenant_id_column(self) -> None:
        for name in sorted(tenant_scoped_tables()):
            table = metadata_obj.tables[name]
            assert "tenant_id" in table.columns, f"{name} is tenant-scoped without tenant_id"
            assert not table.columns["tenant_id"].nullable, f"{name}.tenant_id is nullable"

    def test_every_table_is_classified(self) -> None:
        """A table that is neither tenant-scoped nor explicitly global is unreviewed."""
        unclassified = set(metadata_obj.tables) - tenant_scoped_tables() - GLOBAL_TABLES
        assert unclassified == set(), (
            f"tables with no tenancy decision: {sorted(unclassified)}. Add TenantScoped "
            "or list the table in GLOBAL_TABLES with a justification."
        )

    def test_tenant_scoped_tables_expose_a_composite_identity(self) -> None:
        """``(tenant_id, id)`` uniqueness is what composite foreign keys reference."""
        for name in sorted(tenant_scoped_tables()):
            table = metadata_obj.tables[name]
            has_composite = any(
                {c.name for c in constraint.columns} == {"tenant_id", "id"}
                for constraint in table.constraints
                if isinstance(constraint, sa.UniqueConstraint)
            )
            assert has_composite, f"{name} lacks a UNIQUE (tenant_id, id) constraint"

    def test_references_between_tenant_scoped_tables_carry_the_tenant(self) -> None:
        """A single-column foreign key between tenant-scoped tables would allow a
        cross-tenant reference that RLS alone does not prevent."""
        scoped = tenant_scoped_tables()
        offenders: list[str] = []
        for name in sorted(scoped):
            table = metadata_obj.tables[name]
            for fk in table.foreign_key_constraints:
                referred = fk.referred_table.name
                if referred not in scoped or (referred == name and len(fk.columns) == 2):
                    continue
                if referred == "tenant":
                    continue
                local = {c.name for c in fk.columns}
                if "tenant_id" not in local:
                    offenders.append(f"{name} -> {referred} via {sorted(local)}")
        assert offenders == [], (
            "these references between tenant-scoped tables omit tenant_id: " + "; ".join(offenders)
        )


class TestAppendOnlyEnforcement:
    def test_application_role_cannot_update_or_delete_history(self, app_session: Session) -> None:
        """History cannot be rewritten by application code."""
        for table in sorted(append_only_tables()):
            can_update = app_session.execute(
                sa.text("SELECT has_table_privilege(current_user, :t, 'UPDATE')"),
                {"t": table},
            ).scalar_one()
            can_delete = app_session.execute(
                sa.text("SELECT has_table_privilege(current_user, :t, 'DELETE')"),
                {"t": table},
            ).scalar_one()
            assert not can_update, f"{table} is append-only but the app role may UPDATE it"
            assert not can_delete, f"{table} is append-only but the app role may DELETE it"

    def test_application_role_can_still_insert_history(self, app_session: Session) -> None:
        """Append-only must not mean unwritable."""
        for table in sorted(append_only_tables()):
            can_insert = app_session.execute(
                sa.text("SELECT has_table_privilege(current_user, :t, 'INSERT')"),
                {"t": table},
            ).scalar_one()
            assert can_insert, f"{table} is append-only but the app role cannot INSERT"

    def test_the_audit_trail_is_append_only(self) -> None:
        assert "audit_record" in append_only_tables()
        assert "incident_event" in append_only_tables()
        assert "policy_decision" in append_only_tables()
        assert "approval" in append_only_tables()
        assert "verification" in append_only_tables()

    def test_a_delete_attempt_actually_fails(self, app_session: Session) -> None:
        """Privilege introspection is necessary but not sufficient; try it."""
        with pytest.raises(ProgrammingError, match="permission denied"):
            app_session.execute(sa.text("DELETE FROM audit_record"))


class TestNamingAndIndexes:
    def test_all_constraints_are_explicitly_named(self) -> None:
        """Unnamed constraints make Alembic diffs unstable and reviews unreadable."""
        unnamed: list[str] = []
        for table in metadata_obj.tables.values():
            for constraint in table.constraints:
                if constraint.name is None:
                    unnamed.append(f"{table.name}:{type(constraint).__name__}")
        assert unnamed == []

    def test_every_tenant_scoped_table_indexes_the_tenant_column(self) -> None:
        """Every query is tenant-filtered, so every table needs the tenant leading an
        index - otherwise RLS turns every read into a sequential scan."""
        missing: list[str] = []
        for name in sorted(tenant_scoped_tables()):
            table = metadata_obj.tables[name]
            indexed = any(
                index.columns.keys() and index.columns.keys()[0] == "tenant_id"
                for index in table.indexes
            )
            constrained = any(
                constraint.columns.keys() and constraint.columns.keys()[0] == "tenant_id"
                for constraint in table.constraints
                if isinstance(constraint, sa.UniqueConstraint)
            )
            if not (indexed or constrained):
                missing.append(name)
        assert missing == [], f"no tenant-leading index on: {missing}"


class TestEnumTypeParity:
    """Native enum types in the database must match the domain vocabularies exactly.

    Alembic's autogenerated ``op.drop_table`` does not drop the ENUM types the tables
    depended on, so a downgrade used to leave orphan types behind and the next upgrade
    failed with "type ... already exists". The 0002 downgrade now drops them explicitly;
    these tests keep the two sides in step.
    """

    def _model_enum_names(self) -> set[str]:
        return {
            column.type.name
            for table in metadata_obj.tables.values()
            for column in table.columns
            if isinstance(column.type, sa.Enum) and column.type.name
        }

    def test_database_enum_types_match_the_models(self, owner_session: Session) -> None:
        in_database = set(
            owner_session.execute(
                sa.text(
                    """
                    SELECT t.typname FROM pg_type t
                    JOIN pg_namespace n ON n.oid = t.typnamespace
                    WHERE n.nspname = 'public' AND t.typtype = 'e'
                    """
                )
            ).scalars()
        )
        in_models = self._model_enum_names()

        orphaned = in_database - in_models
        missing = in_models - in_database
        assert orphaned == set(), (
            f"enum types exist in the database but not in the models: {sorted(orphaned)}. "
            "A downgrade that failed to drop them will break the next upgrade."
        )
        assert missing == set(), f"enum types declared but not created: {sorted(missing)}"

    def test_enum_members_match_the_python_vocabulary(self, owner_session: Session) -> None:
        """A value added to a Python enum without a migration would be rejected at write
        time - far later, and far less clearly, than here."""
        rows = owner_session.execute(
            sa.text(
                """
                SELECT t.typname, e.enumlabel FROM pg_type t
                JOIN pg_enum e ON e.enumtypid = t.oid
                JOIN pg_namespace n ON n.oid = t.typnamespace
                WHERE n.nspname = 'public'
                """
            )
        ).all()
        in_database: dict[str, set[str]] = {}
        for type_name, label in rows:
            in_database.setdefault(type_name, set()).add(label)

        for table in metadata_obj.tables.values():
            for column in table.columns:
                if not isinstance(column.type, sa.Enum) or not column.type.name:
                    continue
                expected = set(column.type.enums)
                actual = in_database.get(column.type.name, set())
                assert actual == expected, (
                    f"{column.type.name}: database has {sorted(actual)}, "
                    f"models expect {sorted(expected)}"
                )


class TestModelRegistrationContract:
    def test_every_mapped_class_is_exported(self) -> None:
        """A model not imported in ``asic.db.models`` is invisible to migrations."""
        import asic.db.models as models

        mapped = {m.class_.__name__ for m in Base.registry.mappers}
        exported = set(models.__all__)
        missing = mapped - exported
        assert missing == set(), f"mapped but not exported: {sorted(missing)}"
