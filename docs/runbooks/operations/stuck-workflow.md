# Runbook: Workflow run not progressing

> Operational runbook (no alert fires it directly). Metric names are Prometheus names of the
> catalogue in `src/asic/observability/catalogue.py`. Nothing here has been exercised in a real
> production environment; each step names the command or signal it relies on.

## Symptoms

An incident stays `investigating` (or `awaiting_approval`) far longer than its budget allows;
`asic_workflow_runs_started_total` grows faster than `asic_workflow_runs_finished_total`; no new
`asic_workflow_checkpoints_total` for a run.

## Diagnose

1. Look up the run: `SELECT id, status, lease_owner, lease_expires_at, updated_at FROM workflow_run
   WHERE incident_id = ...` (bound to the tenant).
2. **Lease held, not expired, no recent checkpoint:** the owning worker process died or hung. A new
   worker can take the run over only after the lease expires (15 minutes, `LEASE_DURATION`); until
   then it is refused on purpose, so two workers never act on one run (GAP-26).
3. **`awaiting_approval`:** this is a human wait, not a hang. Check `GET /api/v1/approvals/pending`;
   an approval that expires escalates the incident rather than executing.
4. **Dead-lettered:** see [workflow-run-dead-lettered](../workflow-run-dead-lettered.md).

## Mitigate

* Let the lease expire, then resume the run through the dispatcher; it continues from its last
  checkpoint and reapplies no completed side effect (crash/resume matrix,
  `tests/resilience/test_crash_resume_matrix.py`).
* If a remediation was dispatched before the crash, recovery reconciles its outcome by query; see
  [tool-unknown-outcome](../tool-unknown-outcome.md).

## Do not

* Do not clear `lease_owner` by hand while the old process might still be alive.
* Do not mark the incident resolved manually to "unstick" it; resolution requires verification.
