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
packaging contract tests; and `scripts/local_deployment_smoke.sh` against disposable kind.
