# ADR-0031: Production delivery boundary

- **Status:** Accepted
- **Date:** 2026-09-22

## Context

Phase 14 needs production artifacts without inventing a cloud, a worker runtime or a retention
deletion engine that the application does not yet have. Terraform and Kubernetes must not both own
the same resource, and the scanned artifact must be the released artifact.

## Decision

Build two digest-based images: API/migration and Next.js frontend. Use Kustomize for workloads and
provider-neutral Terraform for namespace and explicit tokenless service accounts. Assume managed
PostgreSQL in production; keep disposable pgvector in a local-only overlay. Publish commit-SHA images
to GHCR, scan them with one fail-closed Trivy policy, emit CycloneDX SBOMs, and use GitHub OIDC build
provenance attestations. Release and deployment are separate manual/trusted boundaries; migrations
finish before rollout, and application rollback never auto-downgrades the database.

Post-audit hardening (Phase 14 LOW findings) tightens the trust boundaries without changing
the architecture:

- Release is split by authority: an unprivileged `build-validate` job does all repository-controlled
  work and hands checksummed `docker save` archives to a `publish-attest` job that alone holds
  `packages`/`id-token` write, has no checkout and never rebuilds. The pushed manifest's config digest
  must equal the scanned image ID.
- Deploy verifies attestation repository, signer workflow, source ref (`main` or `v*` tag), source
  revision and subject digest from certificate claims before any cluster credential exists; the
  kubeconfig is scoped to one step and removed afterwards.
- One orchestrator (`scripts/deploy_release.py`) owns migrate -> guard -> rollout -> automatic smoke
  for both the workflow and the kind smoke, and fails fast on a `Failed` migration Job.
- Terraform enforces Pod Security Admission `restricted` (pinned `v1.34`) on the namespace it owns.

No production orchestration worker is shipped until there is a real durable worker entry point. No
retention Job is shipped until a bounded executor and durable receipt exist. Dynamic vendor egress
uses a platform egress gateway contract because NetworkPolicy cannot authorize DNS names reliably.

## Consequences

The design is portable and testable locally, with small ownership surfaces and no secret-bearing
Terraform state. It does not provision a cluster, managed database, external secret manager, ingress
controller or observability backend. Remote identity remains a platform integration. Initial
resources and replica counts are defaults, not capacity evidence.

## Evidence

Docker builds/scans/SBOM validation; Kustomize renders; Terraform fmt/init/validate/plan/apply;
packaging contract tests, workflow trust-graph tests, attestation policy tests, orchestrator behavior
tests and the frontend health contract; and `scripts/local_deployment_smoke.sh` against disposable
kind (PSA rejection, fail-fast migration with mutation control, API-outage probe behavior, network
policy and automatic smoke).
