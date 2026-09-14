"""Seed the Phase 8 write catalogue and remediation approval permission.

Pinned SQL captured from the reviewed catalogue before this migration was published.
Historical migrations must not import live application descriptors (ADR-0018).
No existing read capability or tenant grant changes.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0011_remediation_safety"
down_revision: str | None = "0010_p6_correction"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SEED_SQL = (
    r"""INSERT INTO tool_definition (
                id, name, version, major_version, capability, description,
                provider_kind, risk_tier, input_schema, output_schema,
                permission_scope_template, timeout_seconds, settling_seconds,
                is_idempotent, idempotency_key_fields, retry_policy, preconditions,
                rollback_tool_name, audit_requirements, credential_ref, is_enabled
            ) VALUES (
                gen_random_uuid(),
                'k8s.deployment.rollback',
                '1.0.0',
                1,
                'mutate.k8s_deployment',
                'Roll a Deployment back to a specific prior revision. The same tool, with the target revision as its own parameter, is this action''s declared rollback: rolling forward again is rolling back to a different revision, not a different operation.',
                'simulator'::tool_provider_kind,
                'r1'::risk_tier,
                '{"deployment": {"description": "Deployment name.", "kind": "bounded_string", "max_length": 253, "pattern": "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", "required": true, "scope_resolved": false}, "environment": {"description": "Environment name resolved from the incident.", "kind": "bounded_string", "max_length": 32, "pattern": "[a-z][a-z0-9_-]{0,31}", "required": true, "scope_resolved": true}, "namespace": {"description": "Namespace, resolved from the service''s registered ownership.", "kind": "bounded_string", "max_length": 253, "pattern": "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", "required": true, "scope_resolved": true}, "service": {"description": "Service resolved from the incident''s affected services.", "kind": "bounded_string", "max_length": 253, "pattern": "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", "required": true, "scope_resolved": true}, "tenant_id": {"description": "Owning tenant. Resolved from the bound session, never supplied.", "kind": "uuid", "required": true, "scope_resolved": true}, "to_revision": {"description": "Target revision to roll back to.", "kind": "integer", "max_value": 1000000.0, "min_value": 1.0, "required": true, "scope_resolved": false}}'::jsonb,
                '{"new_revision": {"kind": "integer", "required": true}, "previous_revision": {"kind": "integer", "required": true}, "schema_version": {"kind": "integer", "required": true}, "source": {"kind": "bounded_string", "required": true}}'::jsonb,
                '{"environment": "from_incident_context", "namespace": "from_service_ownership", "service": "from_incident_context", "tenant_id": "from_incident_context"}'::jsonb,
                150,
                60,
                true,
                ARRAY['tenant_id', 'environment', 'namespace', 'deployment', 'to_revision']::varchar[],
                '{}'::jsonb,
                ARRAY['deployment_exists', 'target_revision_available', 'no_other_rollout_in_progress']::varchar[],
                'k8s.deployment.rollback',
                '{"required_events": ["tool.executed"]}'::jsonb,
                'asic/write/kubernetes',
                true
            )
            ON CONFLICT ON CONSTRAINT uq_tool_definition_name_version DO NOTHING""",
    r"""INSERT INTO tool_definition (
                id, name, version, major_version, capability, description,
                provider_kind, risk_tier, input_schema, output_schema,
                permission_scope_template, timeout_seconds, settling_seconds,
                is_idempotent, idempotency_key_fields, retry_policy, preconditions,
                rollback_tool_name, audit_requirements, credential_ref, is_enabled
            ) VALUES (
                gen_random_uuid(),
                'k8s.hpa.adjust',
                '1.0.0',
                1,
                'mutate.k8s_scale',
                'Adjust a HorizontalPodAutoscaler''s min/max replica bounds within the range the registry has pre-registered for this workload. The same tool restores the prior bounds and is its own rollback.',
                'simulator'::tool_provider_kind,
                'r1'::risk_tier,
                '{"environment": {"description": "Environment name resolved from the incident.", "kind": "bounded_string", "max_length": 32, "pattern": "[a-z][a-z0-9_-]{0,31}", "required": true, "scope_resolved": true}, "hpa_name": {"description": "HorizontalPodAutoscaler name.", "kind": "bounded_string", "max_length": 253, "pattern": "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", "required": true, "scope_resolved": false}, "max_replicas": {"description": "New maximum replica count.", "kind": "integer", "max_value": 100.0, "min_value": 1.0, "required": true, "scope_resolved": false}, "min_replicas": {"description": "New minimum replica count.", "kind": "integer", "max_value": 100.0, "min_value": 1.0, "required": true, "scope_resolved": false}, "namespace": {"description": "Namespace, resolved from the service''s registered ownership.", "kind": "bounded_string", "max_length": 253, "pattern": "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", "required": true, "scope_resolved": true}, "service": {"description": "Service resolved from the incident''s affected services.", "kind": "bounded_string", "max_length": 253, "pattern": "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", "required": true, "scope_resolved": true}, "tenant_id": {"description": "Owning tenant. Resolved from the bound session, never supplied.", "kind": "uuid", "required": true, "scope_resolved": true}}'::jsonb,
                '{"previous_max": {"kind": "integer", "required": true}, "previous_min": {"kind": "integer", "required": true}, "schema_version": {"kind": "integer", "required": true}, "source": {"kind": "bounded_string", "required": true}}'::jsonb,
                '{"environment": "from_incident_context", "namespace": "from_service_ownership", "service": "from_incident_context", "tenant_id": "from_incident_context"}'::jsonb,
                120,
                120,
                true,
                ARRAY['tenant_id', 'environment', 'namespace', 'hpa_name', 'min_replicas', 'max_replicas']::varchar[],
                '{}'::jsonb,
                ARRAY['hpa_exists', 'bounds_within_registered_maxima']::varchar[],
                'k8s.hpa.adjust',
                '{"required_events": ["tool.executed"]}'::jsonb,
                'asic/write/kubernetes',
                true
            )
            ON CONFLICT ON CONSTRAINT uq_tool_definition_name_version DO NOTHING""",
    r"""INSERT INTO tool_definition (
                id, name, version, major_version, capability, description,
                provider_kind, risk_tier, input_schema, output_schema,
                permission_scope_template, timeout_seconds, settling_seconds,
                is_idempotent, idempotency_key_fields, retry_policy, preconditions,
                rollback_tool_name, audit_requirements, credential_ref, is_enabled
            ) VALUES (
                gen_random_uuid(),
                'k8s.node.cordon',
                '1.0.0',
                1,
                'mutate.k8s_node',
                'Mark a node unschedulable. Never autonomous (R2): draining or losing a node affects every workload on it, not only the one under investigation.',
                'simulator'::tool_provider_kind,
                'r2'::risk_tier,
                '{"environment": {"description": "Environment name resolved from the incident.", "kind": "bounded_string", "max_length": 32, "pattern": "[a-z][a-z0-9_-]{0,31}", "required": true, "scope_resolved": true}, "node": {"description": "Node name.", "kind": "bounded_string", "max_length": 253, "pattern": "[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?", "required": true, "scope_resolved": false}, "tenant_id": {"description": "Owning tenant. Resolved from the bound session, never supplied.", "kind": "uuid", "required": true, "scope_resolved": true}}'::jsonb,
                '{"schema_version": {"kind": "integer", "required": true}, "source": {"kind": "bounded_string", "required": true}, "was_schedulable": {"kind": "boolean", "required": true}}'::jsonb,
                '{"environment": "from_incident_context", "tenant_id": "from_incident_context"}'::jsonb,
                60,
                10,
                true,
                ARRAY['tenant_id', 'environment', 'node']::varchar[],
                '{}'::jsonb,
                ARRAY['node_exists', 'node_not_already_cordoned']::varchar[],
                'k8s.node.uncordon',
                '{"required_events": ["tool.executed"]}'::jsonb,
                'asic/write/kubernetes',
                true
            )
            ON CONFLICT ON CONSTRAINT uq_tool_definition_name_version DO NOTHING""",
    r"""INSERT INTO tool_definition (
                id, name, version, major_version, capability, description,
                provider_kind, risk_tier, input_schema, output_schema,
                permission_scope_template, timeout_seconds, settling_seconds,
                is_idempotent, idempotency_key_fields, retry_policy, preconditions,
                rollback_tool_name, audit_requirements, credential_ref, is_enabled
            ) VALUES (
                gen_random_uuid(),
                'k8s.node.uncordon',
                '1.0.0',
                1,
                'mutate.k8s_node',
                'Mark a node schedulable again. The declared rollback of k8s.node.cordon.',
                'simulator'::tool_provider_kind,
                'r2'::risk_tier,
                '{"environment": {"description": "Environment name resolved from the incident.", "kind": "bounded_string", "max_length": 32, "pattern": "[a-z][a-z0-9_-]{0,31}", "required": true, "scope_resolved": true}, "node": {"description": "Node name.", "kind": "bounded_string", "max_length": 253, "pattern": "[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?", "required": true, "scope_resolved": false}, "tenant_id": {"description": "Owning tenant. Resolved from the bound session, never supplied.", "kind": "uuid", "required": true, "scope_resolved": true}}'::jsonb,
                '{"schema_version": {"kind": "integer", "required": true}, "source": {"kind": "bounded_string", "required": true}, "was_schedulable": {"kind": "boolean", "required": true}}'::jsonb,
                '{"environment": "from_incident_context", "tenant_id": "from_incident_context"}'::jsonb,
                60,
                10,
                true,
                ARRAY['tenant_id', 'environment', 'node']::varchar[],
                '{}'::jsonb,
                ARRAY['node_exists', 'node_currently_cordoned']::varchar[],
                'k8s.node.cordon',
                '{"required_events": ["tool.executed"]}'::jsonb,
                'asic/write/kubernetes',
                true
            )
            ON CONFLICT ON CONSTRAINT uq_tool_definition_name_version DO NOTHING""",
    r"""INSERT INTO permission (id, key, description, resource, action, max_risk_tier) VALUES (gen_random_uuid(), 'remediation.approve', 'Decide (approve or reject) a proposed remediation action awaiting human approval.', 'remediation_action', 'approve', 'r2'::risk_tier) ON CONFLICT (key) DO NOTHING""",
)


def upgrade() -> None:
    for statement in _SEED_SQL:
        op.execute(statement)


def downgrade() -> None:
    """Remove unused seeds; existing action/execution references refuse deletion."""
    op.execute(
        """DELETE FROM tool_definition WHERE (name, version) IN (
        ('k8s.deployment.rollback', '1.0.0'),
        ('k8s.hpa.adjust', '1.0.0'),
        ('k8s.node.cordon', '1.0.0'),
        ('k8s.node.uncordon', '1.0.0'))"""
    )
    op.execute("DELETE FROM permission WHERE key = 'remediation.approve'")
