# Phase 14 Deployment and Release Guide

This is an operator contract, not evidence of a remote production deployment. The repository has
been designed for local kind validation; a real cluster, ingress controller, certificate manager,
managed PostgreSQL, external secret manager and protected GitHub environment are platform inputs.

## Prerequisites and ownership

Terraform owns the `asic-system` namespace and the `asic-api`, `asic-frontend` and
`asic-migration` service accounts. Kustomize owns all workload, Service, Ingress, PDB, ConfigMap and
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

The trusted release workflow builds `asic-backend:phase14-$GITHUB_SHA` and
`asic-frontend:phase14-$GITHUB_SHA`, then runs:

```text
security_gate.py --strict --require-container-scan --container-image <backend> --container-image <frontend>
full golden simulator (18) -> full strict replay (18)
Trivy CycloneDX SBOM -> validate_sbom.py known-package check
push GHCR SHA tags -> record digests -> GitHub OIDC build-provenance attestation
```

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
6. Apply the migration Kustomization and wait for `job/asic-migration` to complete.
7. Only then apply the base and wait for both Deployment rollouts and readiness.
8. Probe `/livez`, `/readyz`, `/metrics`, the frontend, and one authenticated read-only API path.
9. Record deployed image digests, migration revision and validation output in the release record.

The manual `production-deploy` workflow enforces steps 6-7 and serializes deployments. Its generic
protected kubeconfig secret is the provider-neutral fallback. Once a cloud is selected, replace it
with short-lived OIDC federation; do not add long-lived cloud keys.

## Protected deployment configuration

The protected environment variable `DEPLOYMENT_CONFIG_JSON` supplies the non-secret contract below.
`scripts/render_deployment.py` validates it and produces temporary manifests, rejecting placeholders,
mutable images, credential-bearing URLs and unrestricted CIDRs. Do not include secret values.

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
Repository administrators must configure those protections; YAML does not create them. The deploy
workflow verifies attestations before loading the cluster credential. Prefer short-lived cluster
identity; the generic protected kubeconfig fallback must be scoped and rotated by the platform.

## Rollback and failure handling

If migration fails, stop. Do not start or describe the application as degraded-success against an
unknown schema. If rollout/readiness fails after migration, roll back the Deployments to their prior
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

The script consumes both images without rebuilding, creates kind Kubernetes 1.34, applies Terraform prerequisites,
deploys disposable PostgreSQL/pgvector, runs Alembic, rolls out API/frontend, probes health,
readiness, metrics and UI, checks non-root/token settings, then destroys the cluster. It uses no
project or production data. A checksum-pinned Cilium 1.20.2 chart (whose images are digest-pinned)
provides policy enforcement. A frontend-to-database timeout must be positively observed while
frontend-to-API and API-to-database succeed. Image IDs are checked before and after the smoke.
Terraform state and kubeconfig live in a temporary directory, destroyed with the cluster.

## Troubleshooting

- `CreateContainerConfigError`: one of the platform-created Secrets or required OIDC ConfigMap keys
  is absent. Do not replace it with a committed value.
- Migration timeout: inspect Job logs and DB network policy/role; keep application rollout stopped.
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
