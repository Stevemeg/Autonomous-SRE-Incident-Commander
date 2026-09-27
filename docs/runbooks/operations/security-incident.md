# Runbook: Tenant isolation or security alert

> Operational runbook (no alert fires it directly). Metric names are Prometheus names of the
> catalogue in `src/asic/observability/catalogue.py`. Nothing here has been exercised in a real
> production environment; each step names the command or signal it relies on.

## Triggers

A cross-tenant access report; unexpected `asic_authorization_denials_total` spikes; many
`asic_security_injection_flags_total`; a leaked credential; a suspicious approval.

## First steps (contain)

1. Preserve evidence: audit records (`audit_record`) are append-only - query them, do not export
   them into chat. Note the time window, tenant and principal.
2. Remove the principal's role assignments (`user_role_assignment`) or set the user's status to
   disabled, as the schema owner - the API's administration surface is read-only by design. Grants
   are reloaded from the database on every request, so the next request is refused.
3. For a leaked credential: rotate it ([secret-rotation](secret-rotation.md)); connector credentials
   take effect immediately.
4. For a suspicious approval: pending actions can be rejected; executed actions are recorded with
   approver, justification and action hash - verify the target state independently.

## Investigate

* Tenant isolation is enforced by row-level security, not only by application code: confirm the
  runtime login still lacks `BYPASSRLS` and superuser (`SELECT rolsuper, rolbypassrls FROM pg_roles
  WHERE rolname = current_user` as the runtime login) and that the tenancy audit passes
  (`python scripts/security_gate.py --only tenancy_schema`).
* Injection flags are signals, not breaches: hostile text is fenced as untrusted data and cannot
  change tools, tenants or approvals. Check the source and remove the content if it is a
  knowledge document.

## Do not

Do not delete audit records or evidence; do not share raw evidence or credentials in tickets.
