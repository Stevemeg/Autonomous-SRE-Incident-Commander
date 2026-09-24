# Phase 14 Deployment and Release Guide

This is an operator contract, not evidence of a remote production deployment. The repository has
been designed for local kind validation; a real cluster, ingress controller, certificate manager,
managed PostgreSQL, external secret manager and protected GitHub environment are platform inputs.

## Prerequisites and ownership

Terraform owns the `asic-system` namespace (including its Pod Security Admission labels) and the
`asic-api`, `asic-frontend` and `asic-migration` service accounts. Kustomize owns all workload, Service, Ingress, PDB, ConfigMap and
NetworkPolicy resources. Production PostgreSQL must provide pgvector, backups/PITR and separate URLs
for the schema owner/migration role and `asic_app`-equivalent runtime role.

Required platform-provisioned Secrets:

| Secret | Key | Consumer | Meaning |
|---|---|---|---|
| `asic-runtime-database` | `url` | API | least-privilege runtime database URL |
| `asic-migration-database` | `url` | migration Job | schema-owner migration URL |
| `asic-tls` | controller-specific | Ingress | TLS certificate/private key managed outside Git |

Production must patch these ConfigMap values: `ASIC_JWT_ISSUER`, `ASIC_JWT_AUDIENCE`,
`ASIC_OIDC_JWKS_URL` (HTTPS), `OTEL_EXPORTER_OTLP_ENDPOINT`, public API origin and ingress details.
Development HS256 is refused when `ASIC_DEPLOYMENT_ENVIRONMENT=production`. Configure IdP token
lifetimes conservatively; maximum JWT lifetime enforcement remains P13-SEC-05.

## Build, scan and release

The trusted release workflow runs only for `main` or a `v*` tag whose commit is reachable from
protected `main`. It has two jobs with separate authority:

```text
build-validate   (contents: read; checkout without persisted credentials; no packages/id-token)
  full golden simulator (18) -> full strict replay (18)
  docker build asic-backend/asic-frontend:phase14-$GITHUB_SHA   (the only build)
  security_gate.py --strict --require-container-scan --container-image <backend> --container-image <frontend>
  Trivy CycloneDX SBOM -> validate_sbom.py known-package + image-ID check
  deployment_smoke.py on disposable kind with the same images
  docker save -> archive SHA-256 + image ID recorded as job outputs -> upload (1-day retention)

publish-attest   (packages/id-token/attestations: write; production environment; no checkout)
  download -> sha256sum --check against build outputs -> docker load -> image ID must match
  push GHCR SHA tags -> bind registry identity to the scanned image ID (single manifest: config
  digest == image ID; OCI index/list: index digest == image ID or its single linux/amd64
  runtime manifest's config == image ID; anything else fails)
  GitHub OIDC build-provenance attestation on the registry digests
  gh attestation verify --signer-workflow release.yml --source-ref <ref> --source-digest <sha>
```

The publish job executes no repository code, tests or builds after it receives write authority, so
the artifact that was scanned, SBOM'd and smoke-deployed is the one pushed and attested.

HIGH or CRITICAL image vulnerabilities block release, including vulnerabilities without a known
fix. Any temporary acceptance is a reviewed, expiry-bearing repository policy change. Scanner DB
failure, missing scanner, malformed report, missing image ID or an empty result fails closed.

## Production sequence

1. Review the image attestations and SBOM artifacts against both supplied digests.
2. Apply Terraform with an encrypted, locked, versioned remote backend and explicit kube context.
3. Provision runtime/migration database Secrets and OIDC/OTLP ConfigMap values through the platform
   secret/config system. Never pass secret values to Terraform.
4. Patch `192.0.2.1/32` to the managed database egress CIDR. Route dynamic vendor egress through the
   approved DNS-aware gateway; do not add unrestricted internet egress.
5. Patch hostname, ingress class, TLS secret and the two immutable image digests.
6. Free the migration Job slot (see below), create the new Job and watch it to a terminal state;
   stop immediately if it fails.
7. Only then apply the base and wait for both Deployment rollouts and readiness.
8. Automatic post-rollout smoke: Service endpoints ready; API `/livez`, `/readyz` 200 and
   unauthenticated `/api/v1/incidents` 401; frontend `/livez`, `/readyz` 200. Each service's checks
   are retried as a unit (2 s interval, 5 s per request) within a 60 s **deployment convergence
   allowance** (`--smoke-deadline`), because `rollout status` returns while old API pods are still
   terminating and endpoints are settling, and the frontend's `/readyz` legitimately reports the API
   as briefly unavailable. The allowance tolerates convergence only: a release whose checks do not
   all pass by the deadline fails, with the last (redacted) error. Optionally also check `/metrics`
   and one authenticated read-only path with an operator credential.
9. Record deployed image digests, release commit, migration revision and validation output.

The manual `production-deploy` workflow enforces steps 6-8 through `scripts/deploy_release.py`, the
same orchestrator the kind smoke runs, and serializes deployments (`cancel-in-progress: false`, so a
newer dispatch never cancels one mid-migration). Its sequence is:

```text
validate inputs (two ghcr.io digests, 40-hex release_commit)          no cluster credential
verify_release_attestation.py: gh attestation verify --format json    no cluster credential
  + repository, release.yml signer, main/v* source ref, source revision, subject digest
pip install + render_deployment.py                                     no cluster credential
single step: KUBE_CONFIG_DATA -> 0600 temp kubeconfig -> deploy_release.py -> removed on exit
always(): rm -f kubeconfig
```

Its generic protected kubeconfig secret is the provider-neutral fallback. Once a cloud is selected,
replace it with short-lived OIDC federation; do not add long-lived cloud keys.

## Protected deployment configuration

The protected environment variable `DEPLOYMENT_CONFIG_JSON` supplies the non-secret contract below.
`scripts/render_deployment.py` validates it and produces temporary manifests, rejecting placeholders,
mutable images, credential-bearing URLs and unrestricted CIDRs. A set of CIDRs is also rejected when
its collapsed union covers all IPv4 or all IPv6 space (e.g. `0.0.0.0/1` + `128.0.0.0/1`), even though
each entry looks narrow. Do not include secret values.

```json
{
  "hostname": "asic.example.com",
  "ingress_class": "nginx",
  "ingress_namespace": "ingress-nginx",
  "tls_secret": "asic-tls",
  "db_cidr": "10.20.0.12/32",
  "issuer": "https://identity.example.com",
  "audience": "asic",
  "jwks_url": "https://identity.example.com/.well-known/jwks.json",
  "otlp_endpoint": "https://collector.example.com",
  "https_egress_cidrs": ["203.0.113.12/32"]
}
```

These are illustrative addresses, not working production endpoints. Use real, reviewed platform
values. The HTTPS list must cover JWKS, the configured HTTPS collector, and enabled connector
destinations. Direct CIDR policy needs updating when vendor IPs change; prefer a transparent,
DNS-aware platform egress firewall rather than assuming the application supports an HTTP proxy.
Configure the ingress controller to redirect HTTP to HTTPS and confirm certificate issuance before
opening traffic. Neither a local kind run nor an Ingress manifest proves TLS termination.

Protect the `production` GitHub environment with required reviewers and trusted release refs.
Repository administrators must configure those protections; YAML does not create them. Environment
rules are defense in depth: the deploy workflow independently verifies the attestation's source
repository, signer workflow, source ref (`refs/heads/main` or `refs/tags/v*`), source revision (the
`release_commit` input) and subject digest from the signed certificate claims, before the cluster
credential exists. Prefer short-lived cluster
identity; the generic protected kubeconfig fallback must be scoped and rotated by the platform.

## Rollback and failure handling

### Migration Job lifecycle and redeployment

The migration Job has a fixed name (`asic-migration`) and is kept for an hour after it finishes
(`ttlSecondsAfterFinished: 3600`), while a Job's pod template is immutable. Every deployment
therefore handles the previous Job explicitly before it validates the new one:

| Previous `asic-migration` Job | Deployment behavior |
|---|---|
| absent | proceed |
| `Complete` (any earlier release, same or different template) | log its UID/conditions, delete (foreground), wait up to 180 s until it is gone, then create the new Job |
| `Failed` (e.g. a failed earlier release) | also log its bounded, redacted diagnostics, then delete and recreate as above: this is the fix-forward path |
| already being deleted (`deletionTimestamp`, no terminal condition) | do not delete; wait (180 s bound) for that deletion to finish, then proceed |
| active (no terminal condition) | **fail closed**: another migration may be running; it is not deleted, no second Job is created and nothing is applied |

The new Job is validated with a server-side dry-run only after the old one is gone, then created with
`kubectl create` (never adopted), and the watcher only accepts a result from the UID it created. If
the old Job cannot be deleted in time (e.g. a stuck finalizer) the deployment fails without creating
the replacement. Repeat deployments of the same release, new image digests and fix-forward releases
after a failed migration all work without manual cleanup. If an active Job is reported and no other
deployment is running, inspect it (`kubectl -n asic-system describe job asic-migration`) and let it
finish or deliberately delete it; the workflow never does that for you.

If migration fails, stop. The orchestrator detects the Job's `Failed` condition within one poll
interval (2 s) rather than waiting for the 10-minute deadline, prints the Job conditions, pod
termination reasons and a bounded, credential-redacted log tail, exits nonzero and never applies the
application manifests. A migration that neither completes nor fails within 10 minutes is a failure. If the Job this
deployment created is deleted (by anyone) before it finishes, or replaced by a different UID, the
deployment fails immediately instead of waiting for the deadline; transient API errors while
polling are retried.
Do not start or describe the application as degraded-success against an unknown schema.

If the post-rollout smoke fails, the workflow fails; the new pods may already be serving, so treat it
exactly like a failed rollout below. If rollout/readiness fails after migration, roll back the Deployments to their prior
image digest. Do **not** automatically run `alembic downgrade`: database rollback may destroy data or
make the old application less compatible. Choose a forward fix or an explicitly reviewed database
recovery procedure.

For a compatible prior deployment, re-dispatch with its two previously attested digests. Do not
rebuild old source and assume it is the old artifact. For an emergency in-place rollback, inspect
`kubectl rollout history`, confirm the prior revision and schema compatibility, then use
`kubectl rollout undo --to-revision=<reviewed-revision>` and wait for readiness. This restores the
pod template, not ConfigMaps, Secrets or database contents; restore compatible configuration through
its owning platform process as necessary.

Rolling old/new versions require schema overlap. The current repository does not claim every
migration is expand/contract or zero-downtime compatible. Drain or constrain a rollout if review
cannot establish overlap.

## Local Kubernetes smoke

With Docker, kind 0.30.0, kubectl and the locked Python development environment:

```bash
docker build -t asic-backend:phase14-local .
docker build -t asic-frontend:phase14-local frontend
python scripts/deployment_smoke.py --backend asic-backend:phase14-local --frontend asic-frontend:phase14-local
```

The script consumes both images without rebuilding, creates kind Kubernetes 1.34 with a
checksum-pinned Cilium 1.20.2 chart (digest-pinned images) for policy enforcement, and uses no
project or production data. It checks:

- Terraform apply, a no-drift re-plan, `restricted`/`v1.34` PSA labels, and admission rejection of a
  privileged, root, host-network/PID pod with added capabilities; restricted workloads admitted;
- the renderer refusing a CIDR set whose union is `0.0.0.0/0`;
- migration through `deploy_release.run_deployment` with a nonexistent database role: fast `Failed`
  detection, no application apply recorded, no `asic-api` Deployment; then the same run from an
  outside-repo copy with the guard mutated away, which must create `asic-api` (non-vacuity);
- the real migration, rollout and automatic post-rollout smoke through the same function;
- non-root/tokenless runtime; frontend-to-API, API-to-DB and DNS allowed; frontend-to-DB, internet
  egress and another namespace to the API denied;
- API scaled to zero: frontend `/livez` 200, `/readyz` 503 in well under the 3 s probe timeout, no
  frontend restart after 45 s, frontend removed from endpoints, post-rollout smoke fails;
- failed application rollout recovery, image IDs unchanged, and Terraform destroy.

Terraform state and kubeconfig live in a temporary directory, destroyed with the cluster.

## Troubleshooting

- `CreateContainerConfigError`: one of the platform-created Secrets or required OIDC ConfigMap keys
  is absent. Do not replace it with a committed value.
- Migration failed/timeout: the workflow log already contains the Job conditions, termination reason
  and a redacted log tail. Check DB network policy/role; keep application rollout stopped. Fix
  forward by re-dispatching a corrected release; the failed Job is replaced automatically.
- `migration Job asic-migration is still active`: another migration is running (or stuck). Wait for it,
  or inspect and deliberately remove it; the deploy workflow refuses to delete a running migration.
- Long kubectl errors are shown as their first and last 1500 characters, so the cause (e.g.
  `field is immutable`, `forbidden`) stays visible. Redaction runs first and replaces credential
  values (keeping the field name) in DSNs (`scheme://user:***@host`, including `DATABASE_URL=`),
  `key=value`/`key: value`/JSON forms of password, secret, token, api-key and access-key keys (e.g.
  `PGPASSWORD`), `Authorization: Bearer|Basic|Token`, and `--password`/`--token`-style flags. It is a
  defensive filter, not a guarantee; do not print secrets into migration output.
- `<service> did not converge within 60s`: the new release never passed its checks during the
  convergence allowance; the message carries the last failing check. Treat it as a failed rollout.
- Frontend not ready but live: the frontend `/readyz` reports the API dependency; fix the API rather
  than restarting the frontend.
- Pod rejected with `violates PodSecurity`: fix the workload security context. Do not relax the
  namespace's Terraform-owned PSA labels.
- API not ready: inspect DB reachability and `alembic_version`; liveness may remain healthy by design.
- Vendor connector unreachable: confirm the egress gateway policy and connector allowlist. Never
  solve it with blanket `0.0.0.0/0` egress.
- Read-only filesystem error: add a narrowly sized `emptyDir` at the one required path rather than
  disabling the pod security baseline.
- Trivy DB unavailable: retry after service recovery; do not treat a missing/stale scan as clean.

## Deferred operational boundaries

The retention subsystem has classification, holds and a bounded dry-run planner, but no safe deletion
executor or durable deletion receipt. Therefore Phase 14 intentionally deploys no privileged
retention CronJob. P13-SEC-05 and F-07/F-09/F-10/F-12/F-17 remain tracked. Phase 15 owns load,
resilience, chaos, penetration, broader network-policy and recovery campaigns.
