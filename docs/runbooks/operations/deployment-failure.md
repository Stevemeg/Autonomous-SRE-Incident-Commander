# Runbook: Container or deployment failure

> Operational runbook (no alert fires it directly). Metric names are Prometheus names of the
> catalogue in `src/asic/observability/catalogue.py`. Nothing here has been exercised in a real
> production environment; each step names the command or signal it relies on.

## Symptoms

The deploy workflow failed after the migration step with `RolloutFailed` (a Deployment did not
become available) or `SmokeFailed` (`<service> did not converge within 60s`); or pods show
`ImagePullBackOff`, `CrashLoopBackOff` or `CreateContainerConfigError`.

## Diagnose

1. `kubectl -n asic-system get pods` and `kubectl describe pod <pod>`.
2. `CreateContainerConfigError`: a platform Secret or a required OIDC ConfigMap key is missing.
3. `ImagePullBackOff`: the digest does not exist in the registry or pull credentials are missing.
4. `CrashLoopBackOff`: `kubectl logs <pod> --previous`; configuration refused at startup (for example
   an unsafe OTLP endpoint or development auth in production) is logged without secrets.
5. `violates PodSecurity`: the workload's security context changed; the namespace enforces
   `restricted`.
6. Smoke failure: the message carries the last failing check (endpoints, path, status).

## Mitigate

* Roll back the Deployments to the previous attested digests (`kubectl rollout undo` after checking
  `kubectl rollout history`), or re-dispatch the previous release. The database is not downgraded.
* The new pods may already be serving when the smoke fails; treat it as a failed rollout.

## Do not

Do not relax Pod Security Admission, network policies or the container scan to get a release out.
