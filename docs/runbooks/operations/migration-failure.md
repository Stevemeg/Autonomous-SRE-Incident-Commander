# Runbook: Migration failed or will not start

> Operational runbook (no alert fires it directly). Metric names are Prometheus names of the
> catalogue in `src/asic/observability/catalogue.py`. Nothing here has been exercised in a real
> production environment; each step names the command or signal it relies on.

## Symptoms

The deploy workflow (or `scripts/deploy_release.py`) stopped with one of:

| Message | Meaning |
|---|---|
| `MigrationFailed: migration failed; application manifests were NOT applied` | The `asic-migration` Job reached `Failed`. Its conditions, pod termination reasons and a redacted log tail are in the same output |
| `migration timeout` | Neither complete nor failed within 600 s |
| `migration disappeared` | The Job this deployment created was deleted or replaced while it ran |
| `migration Job asic-migration is still active` (`MigrationActive`) | Another migration may be running; nothing was deleted or created |
| `previous migration pod(s) still running ... the replacement was NOT created` | A previous migration pod is still inside its termination grace period |

## Impact

The application was **not** rolled out; the previous release keeps serving against the previous
schema. Nothing needs an emergency rollback.

## Diagnose

1. Read the diagnostics already printed by the orchestrator (they are redacted and bounded).
2. `kubectl -n asic-system describe job asic-migration` and
   `kubectl -n asic-system logs job/asic-migration --tail=200`.
3. Authentication failures (`role ... does not exist`, `password authentication failed`) point at
   the `asic-migration-database` Secret; network timeouts point at the `migration-egress` policy or
   the database CIDR.
4. For `MigrationActive`: `kubectl -n asic-system get jobs,pods -l job-name=asic-migration`. Decide
   whether a migration really is running before touching anything.

## Mitigate

* Fix forward: correct the release (or the Secret/policy) and re-dispatch. A `Failed` or `Complete`
  previous Job is replaced automatically.
* A stuck-but-running previous pod: wait for it to finish; if it is genuinely hung, delete the pod
  deliberately (`kubectl delete pod <name>`) and re-dispatch - the orchestrator waits for it to be
  gone before creating the next Job.

## Do not

* Do not run `alembic downgrade` to "roll back": downgrades that would lose history refuse, and
  others may destroy data. Do not apply the application manifests by hand after a failed migration.
