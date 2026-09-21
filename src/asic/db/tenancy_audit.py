"""Mechanical tenancy, role and privilege audit of a live schema (Phase 13, ADR-0030).

RLS coverage used to be proved by a handful of tests over the tables their authors
remembered. This module derives every expectation from the model registry and checks the
*live database* against it, so a new table, a non-canonical or additional policy, a missing
or changed model-declared foreign key, a single-column tenant foreign key, or a widened grant
fails one function rather than depending on a reviewer noticing. The security gate
(``scripts/security_gate.py``) and the test suite call the same code.

It answers, per table: is a tenant boundary present and forced; is the complete policy set
exactly the canonical read/write predicate; does every required cross-tenant-table reference
exist with its modeled signature and unique parent key; and, per role: can the application
role bypass RLS, own a table (owners are exempt without ``FORCE``), or hold a privilege the
runtime does not use.

Findings are data, not exceptions: callers decide what is fatal.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import sqlalchemy as sa
from sqlalchemy.engine import Connection

from asic.db.models import GLOBAL_TABLES, append_only_tables, metadata_obj, tenant_scoped_tables

APP_ROLE: Final[str] = "asic_app"
POLICY_NAME: Final[str] = "tenant_isolation"

#: Provisioned by the owner/administrative path and only *read* by the runtime: identity,
#: role assignment, tool grants and the scope catalogue that decides blast radius. A runtime
#: that could write them could grant itself authority. Mirrors migration 0018.
RUNTIME_READ_ONLY_TABLES: Final[frozenset[str]] = frozenset(
    {
        "app_user",
        "environment",
        "service",
        "service_dependency",
        "tenant_tool_grant",
        "user_role_assignment",
        "integration_connector",
        "connector_scope_binding",
    }
)

#: Privileges the runtime role must never hold on any table.
FORBIDDEN_EVERYWHERE: Final[tuple[str, ...]] = ("DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")

_ALL_PRIVILEGES: Final[tuple[str, ...]] = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    subject: str
    detail: str

    def render(self) -> str:
        return f"{self.code}: {self.subject} - {self.detail}"


@dataclass(frozen=True, slots=True)
class ForeignKeySignature:
    """Security-relevant shape of one tenant-to-tenant foreign key."""

    child_table: str
    child_columns: tuple[str, ...]
    parent_table: str
    parent_columns: tuple[str, ...]
    on_delete: str
    on_update: str


def _normalise_policy_expression(expression: str | None, table: str) -> str | None:
    """Return a narrow fingerprint for the one accepted tenant predicate.

    ``pg_get_expr`` (used by ``pg_policies``) may add redundant parentheses, whitespace,
    identifier quotes, relation qualification, and no-op UUID casts. Removing only those
    tokens lets PostgreSQL's equivalent spellings compare equal without treating Boolean
    algebra as text. Any operator, literal, branch, column, or function change remains in
    the fingerprint and therefore fails closed.
    """
    if expression is None:
        return None
    value = "".join(expression.split())
    for identifier in ("public", table, "tenant_id", "app", "current_tenant_id"):
        value = value.replace(f'"{identifier}"', identifier)
    value = value.lower()
    value = value.replace("::pg_catalog.uuid", "").replace("::uuid", "")
    value = value.replace("(", "").replace(")", "")
    for prefix in (f"public.{table}.", f"{table}."):
        if value.startswith(prefix):
            value = value.removeprefix(prefix)
            break
    return value


def _is_canonical_tenant_predicate(expression: str | None, table: str) -> bool:
    return _normalise_policy_expression(expression, table) == ("tenant_id=app.current_tenant_id")


def _expected_foreign_keys() -> dict[tuple[str, str], ForeignKeySignature]:
    """Derive the mandatory tenant-boundary inventory from trusted ORM metadata."""
    scoped = tenant_scoped_tables()
    expected: dict[tuple[str, str], ForeignKeySignature] = {}
    for table in metadata_obj.tables.values():
        if table.name not in scoped:
            continue
        for constraint in table.foreign_key_constraints:
            elements = tuple(constraint.elements)
            if not elements:
                continue
            parent_table = elements[0].column.table.name
            if parent_table not in scoped:
                continue
            constraint_name = constraint.name
            if constraint_name is None:
                raise RuntimeError(f"tenant foreign key on {table.name} has no canonical name")
            canonical_name = str(constraint_name)
            signature = ForeignKeySignature(
                child_table=table.name,
                child_columns=tuple(element.parent.name for element in elements),
                parent_table=parent_table,
                parent_columns=tuple(element.column.name for element in elements),
                on_delete=(constraint.ondelete or "NO ACTION").upper(),
                on_update=(constraint.onupdate or "NO ACTION").upper(),
            )
            expected[(table.name, canonical_name)] = signature
    return expected


def _tables(conn: Connection) -> dict[str, tuple[bool, bool, str]]:
    rows = conn.execute(
        sa.text(
            """
            SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, pg_get_userbyid(c.relowner)
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'r'
            """
        )
    ).all()
    return {name: (bool(rls), bool(force), owner) for name, rls, force, owner in rows}


def privilege_inventory(conn: Connection, role: str = APP_ROLE) -> dict[str, tuple[str, ...]]:
    """Table -> the privileges ``role`` holds on it (sorted by privilege order)."""
    inventory: dict[str, tuple[str, ...]] = {}
    for table in sorted(_tables(conn)):
        held = tuple(
            privilege
            for privilege in _ALL_PRIVILEGES
            if conn.scalar(
                sa.text("SELECT has_table_privilege(:role, :table, :privilege)"),
                {"role": role, "table": f"public.{table}", "privilege": privilege},
            )
        )
        inventory[table] = held
    return inventory


def audit_schema(conn: Connection, *, role: str = APP_ROLE) -> list[Finding]:
    findings: list[Finding] = []
    findings += _audit_rls(conn)
    findings += _audit_foreign_keys(conn)
    findings += _audit_role(conn, role)
    findings += _audit_grants(conn, role)
    return findings


def _audit_rls(conn: Connection) -> list[Finding]:
    findings: list[Finding] = []
    state = _tables(conn)
    scoped = tenant_scoped_tables()
    policies: dict[str, list[tuple[str, str, tuple[str, ...], str, str | None, str | None]]] = {}
    for table, name, permissive, roles, command, qual, check in conn.execute(
        sa.text(
            "SELECT tablename, policyname, permissive, roles, cmd, qual, with_check "
            "FROM pg_policies WHERE schemaname = 'public' ORDER BY tablename, policyname"
        )
    ):
        policies.setdefault(str(table), []).append(
            (
                str(name),
                str(permissive),
                tuple(str(role) for role in roles),
                str(command),
                qual,
                check,
            )
        )
    tenant_id_tables: dict[str, bool] = {
        str(table): bool(nullable)
        for table, nullable in conn.execute(
            sa.text(
                "SELECT table_name, is_nullable = 'YES' FROM information_schema.columns "
                "WHERE table_schema = 'public' AND column_name = 'tenant_id'"
            )
        ).all()
    }
    for table in sorted(scoped):
        if table not in state:
            findings.append(Finding("table_missing", table, "tenant-scoped model has no table"))
            continue
        rls, force, _ = state[table]
        if not rls:
            findings.append(Finding("rls_disabled", table, "row-level security is not enabled"))
        if not force:
            findings.append(
                Finding(
                    "rls_not_forced", table, "FORCE ROW LEVEL SECURITY is not set (owner bypass)"
                )
            )
        if table not in tenant_id_tables:
            findings.append(Finding("no_tenant_id", table, "no tenant_id column"))
        elif tenant_id_tables[table]:
            findings.append(Finding("tenant_id_nullable", table, "tenant_id may be NULL"))
        table_policies = policies.get(table, [])
        if not table_policies:
            findings.append(Finding("no_policy", table, f"no {POLICY_NAME} policy"))
            continue
        if len(table_policies) != 1:
            names = [policy[0] for policy in table_policies]
            findings.append(
                Finding(
                    "policy_inventory",
                    table,
                    f"expected exactly one canonical policy; found {names}",
                )
            )
            # PostgreSQL OR-combines permissive policies. Finding one correct policy among
            # several is therefore not evidence of isolation; reject the whole inventory.
            continue
        name, permissive, roles, command, qual, check = table_policies[0]
        if name != POLICY_NAME:
            findings.append(Finding("policy_name", table, f"expected {POLICY_NAME}; found {name}"))
        if permissive != "PERMISSIVE":
            findings.append(
                Finding("policy_mode", table, f"expected PERMISSIVE; found {permissive}")
            )
        if roles != ("public",):
            findings.append(Finding("policy_roles", table, f"expected PUBLIC; found {roles}"))
        if command != "ALL":
            findings.append(Finding("policy_command", table, f"expected ALL; found {command}"))
        if not _is_canonical_tenant_predicate(qual, table):
            findings.append(
                Finding(
                    "policy_using",
                    table,
                    "USING is not the canonical tenant_id = app.current_tenant_id() predicate",
                )
            )
        if not _is_canonical_tenant_predicate(check, table):
            findings.append(
                Finding(
                    "policy_with_check",
                    table,
                    "WITH CHECK is not the canonical tenant_id = app.current_tenant_id() predicate",
                )
            )
    for table in sorted(set(state) - scoped):
        if table in tenant_id_tables:
            findings.append(
                Finding(
                    "unregistered_tenant_table", table, "has tenant_id but is not tenant-scoped"
                )
            )
        elif table not in GLOBAL_TABLES:
            findings.append(
                Finding(
                    "unclassified_table", table, "neither tenant-scoped nor a declared global table"
                )
            )
        elif state[table][0]:
            findings.append(
                Finding("global_table_has_rls", table, "global table unexpectedly has RLS")
            )
    return findings


def _audit_foreign_keys(conn: Connection) -> list[Finding]:
    scoped = tenant_scoped_tables()
    rows = conn.execute(
        sa.text(
            """
            SELECT c.conname, s.relname, t.relname,
                   ARRAY(SELECT a.attname::text
                         FROM unnest(c.conkey) WITH ORDINALITY k(n, o)
                         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.n
                         ORDER BY k.o),
                   ARRAY(SELECT a.attname::text
                         FROM unnest(c.confkey) WITH ORDINALITY k(n, o)
                         JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.n
                         ORDER BY k.o),
                   CASE c.confdeltype
                       WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT'
                       WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL'
                       WHEN 'd' THEN 'SET DEFAULT'
                   END,
                   CASE c.confupdtype
                       WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT'
                       WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL'
                       WHEN 'd' THEN 'SET DEFAULT'
                   END
            FROM pg_constraint c
            JOIN pg_class s ON s.oid = c.conrelid
            JOIN pg_class t ON t.oid = c.confrelid
            JOIN pg_namespace n ON n.oid = s.relnamespace
            JOIN pg_namespace tn ON tn.oid = t.relnamespace
            WHERE c.contype = 'f' AND n.nspname = 'public' AND tn.nspname = 'public'
            """
        )
    ).all()
    findings: list[Finding] = []
    actual: dict[tuple[str, str], ForeignKeySignature] = {}
    for name, source, target, source_columns, target_columns, on_delete, on_update in rows:
        signature = ForeignKeySignature(
            child_table=str(source),
            child_columns=tuple(source_columns),
            parent_table=str(target),
            parent_columns=tuple(target_columns),
            on_delete=str(on_delete),
            on_update=str(on_update),
        )
        actual[(str(source), str(name))] = signature
        if source not in scoped or target not in scoped:
            continue
        carries_tenant = any(
            s == "tenant_id" and t == "tenant_id"
            for s, t in zip(source_columns, target_columns, strict=True)
        )
        if not carries_tenant:
            findings.append(
                Finding(
                    "fk_not_tenant_composite",
                    f"{source}.{name}",
                    f"references {target} without carrying tenant_id "
                    f"({source_columns} -> {target_columns})",
                )
            )

    expected = _expected_foreign_keys()
    unique_keys = {
        (str(table), tuple(columns))
        for table, columns in conn.execute(
            sa.text(
                """
                SELECT t.relname,
                       ARRAY(SELECT a.attname::text
                             FROM unnest(c.conkey) WITH ORDINALITY k(n, o)
                             JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.n
                             ORDER BY k.o)
                FROM pg_constraint c
                JOIN pg_class t ON t.oid = c.conrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                WHERE c.contype IN ('p', 'u') AND n.nspname = 'public'
                """
            )
        ).all()
    }
    for key, required in sorted(expected.items()):
        subject = f"{required.child_table}.{key[1]}"
        found = actual.get(key)
        if found is None:
            findings.append(Finding("fk_missing", subject, "required tenant-safe FK is absent"))
        else:
            required_shape = (
                required.child_columns,
                required.parent_table,
                required.parent_columns,
            )
            found_shape = (found.child_columns, found.parent_table, found.parent_columns)
            if found_shape != required_shape:
                findings.append(
                    Finding(
                        "fk_signature",
                        subject,
                        f"expected {required_shape}; found {found_shape}",
                    )
                )
            if (found.on_delete, found.on_update) != (
                required.on_delete,
                required.on_update,
            ):
                findings.append(
                    Finding(
                        "fk_action",
                        subject,
                        "expected "
                        f"ON DELETE {required.on_delete} ON UPDATE {required.on_update}; found "
                        f"ON DELETE {found.on_delete} ON UPDATE {found.on_update}",
                    )
                )
        parent_key = (required.parent_table, required.parent_columns)
        if parent_key not in unique_keys:
            findings.append(
                Finding(
                    "fk_parent_not_unique",
                    subject,
                    f"referenced key {required.parent_table}{required.parent_columns} is not unique",
                )
            )
    return findings


def _audit_role(conn: Connection, role: str) -> list[Finding]:
    findings: list[Finding] = []
    row = conn.execute(
        sa.text(
            "SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = :r"
        ),
        {"r": role},
    ).one_or_none()
    if row is None:
        return [Finding("role_missing", role, "application role does not exist")]
    if row.rolsuper or row.rolbypassrls:
        findings.append(Finding("role_bypasses_rls", role, "SUPERUSER or BYPASSRLS"))
    if row.rolcreatedb or row.rolcreaterole:
        findings.append(Finding("role_administrative", role, "CREATEDB or CREATEROLE"))
    privileged_parents = (
        conn.execute(
            sa.text(
                """
            WITH RECURSIVE parents(oid) AS (
                SELECT oid FROM pg_roles WHERE rolname = :r
                UNION
                SELECT m.roleid FROM pg_auth_members m JOIN parents p ON m.member = p.oid
            )
            SELECT r.rolname FROM pg_roles r JOIN parents p ON p.oid = r.oid
            WHERE (r.rolsuper OR r.rolbypassrls) AND r.rolname <> :r
            """
            ),
            {"r": role},
        )
        .scalars()
        .all()
    )
    for parent in privileged_parents:
        findings.append(
            Finding("role_inherits_bypass", role, f"member of privileged role {parent}")
        )
    owned = [t for t, (_, _, owner) in _tables(conn).items() if owner == role]
    for table in owned:
        findings.append(Finding("role_owns_table", table, "owner is exempt from RLS without FORCE"))
    if conn.scalar(sa.text("SELECT has_schema_privilege(:r, 'public', 'CREATE')"), {"r": role}):
        findings.append(Finding("role_can_create", role, "CREATE on schema public (DDL)"))
    return findings


def _audit_grants(conn: Connection, role: str) -> list[Finding]:
    findings: list[Finding] = []
    inventory = privilege_inventory(conn, role)
    append_only = append_only_tables()
    for table, held in inventory.items():
        for privilege in FORBIDDEN_EVERYWHERE:
            if privilege in held:
                findings.append(Finding("grant_forbidden", table, f"{role} holds {privilege}"))
        if table in append_only:
            for privilege in ("UPDATE",):
                if privilege in held:
                    findings.append(
                        Finding("grant_append_only", table, f"{role} holds {privilege}")
                    )
        writable = {"INSERT", "UPDATE"} & set(held)
        if (table in RUNTIME_READ_ONLY_TABLES or table in GLOBAL_TABLES) and writable:
            findings.append(
                Finding(
                    "grant_read_only",
                    table,
                    f"{role} holds {sorted(writable)} on a read-only table",
                )
            )
    return findings


__all__ = [
    "APP_ROLE",
    "FORBIDDEN_EVERYWHERE",
    "RUNTIME_READ_ONLY_TABLES",
    "Finding",
    "audit_schema",
    "privilege_inventory",
]
