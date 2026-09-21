"""Mechanical tenancy, role and privilege audit of a live schema (Phase 13, ADR-0030).

RLS coverage used to be proved by a handful of tests over the tables their authors
remembered. This module derives every expectation from the model registry and checks the
*live database* against it, so a new table, a weakened policy, a single-column foreign key
between tenant tables, or a widened grant fails one function rather than depending on a
reviewer noticing. The security gate (``scripts/security_gate.py``) and the test suite call
the same code.

It answers, per table: is a tenant boundary present and forced; does the policy constrain
reads *and* writes; is every cross-tenant-table reference composite so that a foreign key
cannot point into another tenant; and, per role: can the application role bypass RLS, own a
table (owners are exempt without ``FORCE``), or hold a privilege the runtime does not use.

Findings are data, not exceptions: callers decide what is fatal.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import sqlalchemy as sa
from sqlalchemy.engine import Connection

from asic.db.models import GLOBAL_TABLES, append_only_tables, tenant_scoped_tables

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
    policies = {
        table: (qual, check)
        for table, qual, check in conn.execute(
            sa.text(
                "SELECT tablename, qual, with_check FROM pg_policies "
                "WHERE schemaname = 'public' AND policyname = :name"
            ),
            {"name": POLICY_NAME},
        )
    }
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
        policy = policies.get(table)
        if policy is None:
            findings.append(Finding("no_policy", table, f"no {POLICY_NAME} policy"))
            continue
        qual, check = policy
        if not qual or "current_tenant_id" not in qual:
            findings.append(
                Finding("policy_using", table, "USING does not bind app.current_tenant_id()")
            )
        if not check or "current_tenant_id" not in check:
            findings.append(
                Finding(
                    "policy_with_check", table, "WITH CHECK does not bind app.current_tenant_id()"
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
                         ORDER BY k.o)
            FROM pg_constraint c
            JOIN pg_class s ON s.oid = c.conrelid
            JOIN pg_class t ON t.oid = c.confrelid
            JOIN pg_namespace n ON n.oid = s.relnamespace
            WHERE c.contype = 'f' AND n.nspname = 'public'
            """
        )
    ).all()
    findings: list[Finding] = []
    for name, source, target, source_columns, target_columns in rows:
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
