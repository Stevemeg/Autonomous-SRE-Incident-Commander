"""Seed the read-only capability catalogue into ``tool_definition``.

The catalogue lives in code (``asic.tools.catalogue``) so it is reviewed like code, and is
mirrored here so a tenant cannot edit it: ``tool_definition`` is a global table with
``INSERT``, ``UPDATE`` and ``DELETE`` revoked from the application role. A tenant that
could register a tool - or reclassify one's risk tier - could widen its own authority,
which is the thing the whole capability model exists to prevent.

Rows are derived from the descriptors rather than retyped, so the two cannot disagree
through a transcription slip. ``ToolRegistry.assert_matches_database`` compares them field
by field at start-up and refuses to run on any divergence.

Everything seeded here is risk tier ``RO``. Write capabilities arrive with the policy gate,
the approval service and the executor - and not before, because a registered write tool
with no gate in front of it is a capability with nothing to authorize it.

Revision ID: 0005_seed_ro_catalogue
Revises: 0004_workflow_checkpoint
Create Date: 2026-09-07
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from alembic import op

from asic.tools.catalogue import READ_ONLY_CATALOGUE

revision: str = "0005_seed_ro_catalogue"
down_revision: str | None = "0004_workflow_checkpoint"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Named credentials the broker resolves per tool. These are *references* into the secret
#: manager, never secrets: nothing in this repository holds a credential, and the read
#: paths deliberately name different credentials from any future write path so that
#: investigation is physically incapable of mutation (SI-4).
_CREDENTIAL_REF = {
    "metrics.query": "asic/read/prometheus",
    "logs.query": "asic/read/loki",
    "traces.query": "asic/read/otel",
    "deploy.list": "asic/read/deployments",
    "k8s.workload.read": "asic/read/kubernetes",
    "knowledge.search": "asic/read/knowledge",
}


def upgrade() -> None:
    for descriptor in READ_ONLY_CATALOGUE:
        op.execute(
            f"""
            INSERT INTO tool_definition (
                id, name, version, major_version, capability, description,
                provider_kind, risk_tier, input_schema, output_schema,
                permission_scope_template, timeout_seconds, settling_seconds,
                is_idempotent, idempotency_key_fields, retry_policy, preconditions,
                rollback_tool_name, audit_requirements, credential_ref, is_enabled
            ) VALUES (
                gen_random_uuid(),
                {_q(descriptor.name)},
                {_q(descriptor.version)},
                {descriptor.major_version},
                {_q(descriptor.capability)},
                {_q(descriptor.description)},
                '{descriptor.provider_kind.value}'::tool_provider_kind,
                '{descriptor.risk_tier.value}'::risk_tier,
                {_q(json.dumps(descriptor.to_input_schema(), sort_keys=True))}::jsonb,
                {_q(json.dumps(descriptor.to_output_schema(), sort_keys=True))}::jsonb,
                {_q(json.dumps(_scope_template(descriptor), sort_keys=True))}::jsonb,
                {descriptor.timeout_seconds},
                {descriptor.settling_seconds},
                {str(descriptor.is_idempotent).lower()},
                {_array(descriptor.idempotency_key_fields)},
                {_q(json.dumps(_retry_policy(descriptor), sort_keys=True))}::jsonb,
                {_array(descriptor.preconditions)},
                NULL,
                {
                _q(json.dumps({"required_events": list(descriptor.audit_events)}, sort_keys=True))
            }::jsonb,
                {_q(_CREDENTIAL_REF[descriptor.name])},
                true
            )
            ON CONFLICT ON CONSTRAINT uq_tool_definition_name_version DO NOTHING
            """
        )


def downgrade() -> None:
    """Remove the seeded catalogue rows.

    **This downgrade fails, by design, on a database that has executed anything.**
    ``fk_tool_execution_tool_definition`` is ``ON DELETE RESTRICT``, so a catalogue row
    cannot be removed while an execution record points at it. That is the constraint doing
    its job: an execution record must stay interpretable without joining to configuration
    that has since been deleted, and silently orphaning it would be worse than refusing.

    A downgrade is therefore clean on a fresh database and refused on one with history. If a
    catalogue entry genuinely has to go, deprecate it (``is_enabled = false``,
    ``deprecated_at``) rather than deleting the row its history depends on.
    """
    names = ", ".join(_q(descriptor.name) for descriptor in READ_ONLY_CATALOGUE)
    # Restricted to this catalogue's versions so a downgrade cannot remove a tool some
    # later migration registered.
    versions = ", ".join(f"({_q(d.name)}, {_q(d.version)})" for d in READ_ONLY_CATALOGUE)
    op.execute(
        f"DELETE FROM tool_definition WHERE name IN ({names}) AND (name, version) IN ({versions})"
    )


def _q(value: str) -> str:
    """Single-quote a literal for inline SQL, doubling any embedded quote."""
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def _array(values: Sequence[str]) -> str:
    if not values:
        return "'{}'::varchar[]"
    inner = ", ".join(_q(value) for value in values)
    return f"ARRAY[{inner}]::varchar[]"


def _scope_template(descriptor: object) -> dict[str, str]:
    """How each scope argument is resolved. Recorded so the rule is visible in the row.

    ``from_incident_context`` and ``from_service_ownership`` are the two sources; neither
    is ever "from the caller", which is the whole point.
    """
    names = sorted(getattr(descriptor, "scope_argument_names", frozenset()))
    return {
        name: ("from_service_ownership" if name == "namespace" else "from_incident_context")
        for name in names
    }


def _retry_policy(descriptor: object) -> dict[str, object]:
    attempts = int(getattr(descriptor, "max_attempts", 1))
    if attempts <= 1:
        return {}
    return {
        "max_attempts": attempts,
        "backoff": "linear",
        "backoff_seconds": float(getattr(descriptor, "retry_backoff_seconds", 0.0)),
        # Class C1 (pure read): retried on transient upstream errors only. An empty result
        # is class C5 - a finding, never retried.
        "operation_class": "c1_pure_read",
        "retry_on": ["transient_adapter_error", "timeout"],
    }
