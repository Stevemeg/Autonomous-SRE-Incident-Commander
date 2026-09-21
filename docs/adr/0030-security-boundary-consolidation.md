# ADR-0030: Security boundary consolidation: explicit production authentication, one permission vocabulary, mechanical tenancy proof, hash-locked supply chain

- **Status:** Accepted
- **Date:** 2026-09-21
- **Deciders:** Project owner (Phase 13 implementation)
- **Spec reference:** §6, §7, §8, §14, §15, §17, §18, §20
- **Supersedes / Superseded by:** refines ADR-0011 (authentication, authorization, tenancy) and
  ADR-0026 (external integrations behind the broker); corrects the RBAC role table in
  `docs/security/THREAT_MODEL.md` §5.2

## Context

Security had been built into every earlier phase. Phase 13 therefore was not "add security"; it
was inventory, find gaps, consolidate, enforce, attack and prove. The inventory found real
gaps, each of which shaped a decision below:

1. **Authentication was a shared secret only.** HS256 with one environment secret is a fine
   development stand-in and not a production boundary: any holder of the secret can mint any
   tenant's token, and nothing stopped a production deployment from running it.
2. **Permission names were spelled four times** (API, approval service, memory service,
   knowledge service), and one enforcement site hard-coded the string again.
3. **Tenancy proof was a hand-picked test list.** A table added without a policy, a
   single-column foreign key between tenant tables, or a widened grant would not have failed
   anything.
4. **The application role held far more than it used:** `DELETE` on 18 tables although no code
   path deletes, write access to `alembic_version` (the readiness signal), and write access to
   the identity, role-assignment, tool-grant and scope-catalogue tables the runtime only reads.
5. **Referential and integrity gaps** carried from the Phases 10-12 audit: no foreign key from a
   connector binding to its connector (F-13), unvalidated persisted trace ids (F-11), an
   unbounded request body, a NUL byte in a justification returning HTTP 500, readiness with no
   connect deadline and no abuse bound (F-15), a request object whose `repr` printed its
   Authorization header (F-16), unsanitised Loki level labels (F-06), and node cordon/uncordon
   documented as if they were service-scoped (F-08).
6. **Supply chain:** ranges only, no committed resolution; a frontend lockfile in which 26 of 34
   packages carried no integrity digest; one beta runtime dependency with no stated policy.

## Decision

**Authentication.** `asic.api.tokens` defines a `TokenVerifier` with two implementations that
are not interchangeable. `OidcJwksVerifier` accepts only an explicit *asymmetric* algorithm set
(`alg=none` and HS/RS confusion are unrepresentable, and the algorithm must also match the
selected key's type), requires `kid`, refuses token-supplied key material (`jku`/`x5u`/`jwk`),
requires issuer, audience, expiry, `sub` and `tenant_id`, and fetches keys through the *same*
hardened transport as connectors (HTTPS, no redirects, timeout, size ceiling) into a bounded,
rotation-aware cache (unknown `kid` refreshes at most once per interval; stale keys are served
briefly then fail closed; a duplicate `kid` makes the set ambiguous and refuses it).
`Hs256DevelopmentVerifier` declares `is_development`; `build_token_verifier` refuses it, and
plain-HTTP JWKS, in a production deployment, at startup. Every failure is a closed reason code
that is logged and never returned; no token content reaches an error, log or trace.

**One vocabulary.** `asic.domain.permissions` defines `PermissionKey`, the per-permission scope
rule (environment-scoped or tenant-wide) and the seven system roles' grants. Every enforcement
site imports it; tests assert it equals the migrated catalogue and the seeded roles, that no
permission string is spelled anywhere else, and that each route guard agrees with the scope
rule. Human RBAC, human approval and connector authority remain three separate things.

**Mechanical tenancy proof.** `asic.db.tenancy_audit` derives every expectation from the model
registry and checks the live schema: RLS enabled and forced, USING and WITH CHECK bound to
`app.current_tenant_id()`, `tenant_id` present and not null, every table classified, every
foreign key between tenant tables composite, the application role neither privileged nor an
owner nor able to create objects, and grants within policy. The security gate and the tests
call the same function; each guard has a mutation test proving it can fail.

**Least privilege, migration 0018.** `DELETE` and `TRUNCATE` are revoked from `asic_app`
everywhere; write access is revoked on `alembic_version` and on identity, role assignment, tool
grants, environments, services and their dependencies (provisioned by the owner path, read by the
runtime). Cascading foreign-key deletes run with the owner's rights and are unaffected. History
is retired by an owner-run lifecycle job, never by the application role.

**Integrity.** `connector_scope_binding` references `integration_connector` through a composite,
tenant-carrying key with `ON DELETE RESTRICT` (authority history is never cascaded away): an
inbound connector identity must be registered in the connector catalogue. `execution_trace`
gains a W3C trace-id CHECK. Both are added `NOT VALID` and validated in the same step only when
no historical row violates them, so an existing database upgrades, keeps its rows untouched and is
still protected for new rows. One trace-id rule (`asic.observability.trace_ids`) is applied at
construction, in the database and at the span-context boundary; a malformed persisted id fails
loudly and is never replaced.

**Node authority (F-08).** A node is shared infrastructure with no service label; forcing a
service rule on it would be false. Its authority is explicit: tenant and environment from the
frozen target, the node identity as an argument bound into the approved action hash, R2, and a
current human approval on every dispatch: a node action is never admitted by policy alone.

**Boundaries, not detection.** Request bodies are bounded at the ASGI edge (128 KiB, JSON only,
including streamed bodies). Human text refuses control and invisible characters. The Loki level
is mapped onto a closed vocabulary. Egress hosts refuse link-local, metadata, unspecified,
multicast and ambiguous numeric addresses. `SecretValue` redacts by type; requests and responses
never render credentials or bodies; name- and shape-based redaction is only a backup layer.
Denials of state changes and of tenant-wide reads are durable, tenant-bound audit records;
ordinary denied reads are not (a caller must not be able to fill the trail).

**Supply chain.** `pyproject.toml` keeps compatibility ranges (all upper-bounded); installations
derive from committed, universal, hash-pinned locks (`requirements/*.lock`, generated by
`uv pip compile --generate-hashes`). `scripts/check_dependency_lock.py` enforces hashes, no URL or
index sources, range agreement, a reasoned prerelease allowlist and frontend integrity digests.
SAST is `ruff check --select S` (no new scanner) plus tests that pin the one policy exception
(`assert` narrowing). Secret scanning is gitleaks with an allowance narrowed to one rule, one
file and one exact matched text. `scripts/security_gate.py` orchestrates everything, fails
closed, and reports container scanning as *not executable until a Phase 14 image exists*.

**Retention.** A complete table classification, a tenant policy schema with platform minimums
and holds, and a dry-run planner. No deletion engine: the application role cannot delete, and
safe deletion needs an owner-role job under change control (Phase 14).

## Alternatives considered

- **A generic authorization framework / policy engine.** Rejected: the existing checks are small,
  database-backed and already correct; a second engine would be a duplicate to keep consistent.
- **Making OIDC mandatory everywhere.** Rejected: the portfolio must run without an identity
  provider. Instead the development verifier exists, is explicit, and is refused in production.
- **Bandit or Semgrep for SAST.** Rejected: ruff is already the linter, its `S` rules cover the
  relevant classes, and a second overlapping scanner adds false-positive handling for no gain.
- **Redis for distributed rate limiting.** Rejected here (ADR-0006): the single-process limit is
  bounded and documented; a shared limiter is a deployment concern.
- **A retention deletion engine now.** Rejected: an application-role `DELETE ... WHERE created_at
  < X` would violate audit immutability, replay reproducibility and verification lineage.
- **Failing the upgrade on historical bad rows.** Rejected: it would block real databases.
  `NOT VALID` then conditional validation keeps the upgrade safe without rewriting evidence.

## Consequences

- Production must supply `ASIC_AUTH_MODE=oidc_jwks` configuration; a misconfiguration is a
  startup failure, by design.
- Inbound connector identities must exist in `integration_connector` (an inbound-only identity
  can be registered disabled). This is a real schema constraint on provisioning.
- Test fixtures needed write grants the runtime no longer has; they are granted to the test login
  role only, and a test asserts `asic_app` itself holds none of them.
- The trace-id CHECK and connector FK may remain `NOT VALID` on a database with historical bad
  rows; the migration says so (`RAISE NOTICE`) and the tenancy audit and tests report it.
- Container scanning, TLS/mTLS, encryption at rest, network egress policy and a shared rate limiter
  are Phase 14/15 deployment obligations, listed in `docs/security/SECURITY_ARCHITECTURE.md`.

## Interview concepts

Algorithm-confusion attacks and why the algorithm set must be explicit and key-type-checked;
JWKS rotation vs revocation latency; authentication vs authorization vs approval as three
authorities; why `FORCE ROW LEVEL SECURITY` is meaningless for a superuser and how to prove the
runtime role is not one; `NOT VALID` constraints and validating without rewriting history;
composite foreign keys as tenant isolation; mutation testing a security audit so it cannot pass
vacuously; why an allowlist that matches the *line* can hide an appended secret.

## Future improvements

Separate permission tiers for R1 and R2 approval (today every approve-holder may decide through
R2); step-up authentication for administration; a distributed rate limiter; an owner-role
retention lifecycle job; SBOM and image signing (Phase 14); a penetration-style campaign (Phase 15).
