# Security hardening campaigns (Phase 15.13–15.22, 15.29)

Phase 13 built the security boundary (ADR-0030); Phase 15 attacked it. Every campaign is an
automated, seeded, repeatable test suite in the normal matrix — not a one-off manual probe — and
each asserts on what the system *recorded or emitted*, not on a return value. Measured results for
the validation run are in [`PHASE15_RESULTS.md`](PHASE15_RESULTS.md).

## Campaigns

| Area | Suite | Tests | What is attacked | Invariant asserted |
|---|---|---|---|---|
| Prompt injection (15.15) | `tests/security/test_injection_campaign.py` + `injection_corpus.py` | 3 (over a 40-case corpus) | Versioned, digest-pinned corpus with canary tokens (`PI-CANARY-NNN`), invisible/bidi characters built with `chr`; planted in logs, runbooks, knowledge documents, postmortems, Kubernetes events/annotations/labels, change records, trace/integration responses, incident titles; also via the ingestion edge and as vendor responses | Hostile text may appear only fenced and labelled `retrieved`; it never changes tenant, environment, identity, permissions, tool menu, risk tier, target, approvals, verification or connector authority, and no tool runs that the deterministic plan did not select |
| Tool abuse (15.16) | `test_tool_abuse_campaign.py` | 27 | Unknown capability, model-invented tool names, wrong node contract, read/write confusion, wrong tenant/target/environment, undeclared or scope-changing arguments, malformed/oversized arguments, control/invisible characters, caller-set fields (tool name, credential, tenant, risk tier, idempotency key, connector); approval replay, wrong hash, expiry, unauthorised or revoked approver | Refused **before any adapter is called** (the simulator records every call), at a named broker stage, audited |
| Tenant isolation (15.17) | `test_tenant_campaign.py` | 4 (schema-wide) | Tenant B populated through real product paths (full remediation to `resolved`, knowledge ingestion, idempotent API call); tenant A, as the real non-owner role, reads/updates/deletes/inserts on **every tenant-scoped table** in the model registry; guessed ids on every GET route, forged cursors, B's connector ingesting into A | Nothing visible or reachable; no DELETE anywhere; RLS refuses mislabelled inserts; composite tenant FKs refuse cross-tenant references |
| Authentication (15.18) | `test_auth_campaign.py` (+ Phase 13 `test_authentication.py`) | 34 | Token lifetime (P13-SEC-05), claim boundary times at exactly the leeway, audience arrays, token size at the exact ceiling, concurrent refresh under an unknown-`kid` storm while the IdP is slow | `iat` required; `exp − iat` ≤ configured maximum (default 3600 s, platform range 300–5400 s) in **both** verifiers; bounded JWKS refresh |
| SSRF / egress (15.19) | `test_ssrf_campaign.py` | 36 | URL normalisation tricks (credentials in authority, mixed-case schemes, percent-encoded/IDN/numeric hosts, IPv4-mapped IPv6, metadata names); renderer CIDR policy | Application `check_egress_host` and the deployment renderer's CIDR policy refuse the same dangerous destinations. **Non-claim:** DNS rebinding is *not* prevented by the application (a test pins this limitation); it is a network-policy / egress-gateway responsibility |
| API fuzz + abuse cost (15.20/15.22) | `test_api_fuzz_campaign.py` | 19 | Seeded hostile inputs on every route: malformed and deeply nested JSON, duplicate keys, NaN/Infinity, wrong types, oversized strings, bodies at and one byte over the ceiling, wrong content types, invalid UUIDs/cursors, unexpected Unicode; invalid-token floods | Always a bounded 4xx or the documented classified 503 — never a 500, hang or crash; invalid-token floods do **zero** database statements and are throttled per peer |
| Secret leakage (15.21) | `test_secret_leak_campaign.py` | 4 (many entry points × sinks) | Canary credentials (JWT, DSN with password, `PGPASSWORD`, API key, cloud access key, chat token) through the Authorization header, query, JSON bodies, vendor errors, model exceptions, adapter failures, tool output, retrieved documents, evaluation-gate failures and kubectl diagnostics | The canary appears in no sink: log records and formatted lines, exported and persisted spans, Prometheus exposition, audit records, API error bodies, evaluation reports, deployment diagnostics |
| Redaction performance (15.14) | `test_redaction_complexity.py` | 26 | 100 KB inputs shaped to defeat each redaction pattern; seeded equivalence corpus against the original patterns | Linear time; detection identical to the pre-fix patterns |
| Retention executor (15.28) | `test_retention_executor.py` | 20 | Runs as a real login holding only `asic_maintenance` | See [Retention](#retention-lifecycle-executor-1528) |

## Defects found by the campaigns and fixed in Phase 15

| Defect | Found by | Fix |
|---|---|---|
| Four redaction regexes were quadratic: 20 KB of `a.a.a…` took 7 s (DSN rule) and 51 s (key=value rule) before the fix | redaction complexity | Run-start lookbehind anchors, possessive quantifiers and atomic groups; equivalence proven against the originals |
| Secrets could persist in stored trace spans, checkpoint failure messages and planner rationale | secret-leak campaign | `NodeFailureRef.message` and planner `gap`/`rationale`/`overridden_reason` are `ScrubbedText`; `tracing.fail()` scrubs |
| A client-chosen JSON key was echoed in 422 `loc` (a token sent as a key leaked back) | secret-leak + fuzz | Only identifier-shaped locations are echoed; anything else is replaced |
| Bare tokens (JWT, AKIA/ASIA keys, `sk-`, Slack `xox*`, GitHub `gh*_`, Google `AIza`) survived deployment diagnostics redaction | secret-leak campaign | Bare-token rules added to `scripts/deploy_release.py` |
| Percent-encoded hosts were accepted by `check_egress_host` | SSRF campaign | Host names must match an RFC 1123 pattern after parsing |
| The default 422 echoed the client's input; a `NaN`/`Infinity` input could not even be serialised and surfaced as a 500 | API fuzz | 422 bodies carry only location, error type and our own message, never the input |
| Database failures surfaced as opaque 500s | database stress | Classified 503s with `Retry-After` (`database_busy`/`_timeout`/`_contention`/`_unavailable`); a lost optimistic-locking race is a 409 `concurrent_modification` |
| Rate limiter pruned in O(n) per request | abuse cost | Prune bounded by a not-before watermark |
| Tokens without `iat` or with unbounded lifetime accepted (P13-SEC-05) | auth campaign | Lifetime policy in both verifiers |
| Renderer accepted `0.0.0.0/0`-minus-a-host sets, link-local and broad public prefixes (N-3) | SSRF campaign | Public prefixes no broader than /24 (IPv4) or /48 (IPv6), at most 64 reviewed entries, special-purpose ranges refused, union check kept |

## Retention lifecycle executor (15.28)

Decision (recorded in [DATA_RETENTION.md](../security/DATA_RETENTION.md)): early enterprise
operation needs an executor for data whose value genuinely expires, but only where deletion cannot
break evidence, replay, verification lineage or memory governance. Exactly one class qualifies —
the API idempotency replay cache — and the executor deletes nothing else.

* Separate identity: migration 0019 adds `asic_maintenance` (`NOLOGIN NOBYPASSRLS`); it may read
  and delete `api_idempotency_record`, read tenant policy and write receipts — nothing else. The
  application role still holds no `DELETE` anywhere.
* Tenant-bound (RLS), bounded batches (≤ 10 000 rows, ≤ 1 000 batches), oldest first, holds
  respected, dry run by default, each batch committed atomically with an immutable
  `retention_run` receipt.
* Delivered as a **suspended**, dry-run `CronJob` (`deploy/kubernetes/maintenance`) with its own
  tokenless service account and database Secret. Verified on kind: admitted under
  `restricted`, dry run (3 eligible, 0 deleted), then `--execute` (3 deleted, the recent row
  kept), receipts written.
* Not implemented, deliberately: deletion of any other class. Prerequisites (lineage-aware
  cascades, backup/PITR coordination, legal-hold integration) are in the gap register.

## Security tool reruns (15.29)

Recorded in [`PHASE15_RESULTS.md`](PHASE15_RESULTS.md#2-security-tools) with the exact commands.
No threshold was lowered and no finding was suppressed to make a tool pass.

## Explicit non-claims

* Rate limiting is **per process** (in-memory). A multi-replica deployment needs an edge or
  gateway limiter; the application does not provide a distributed one.
* DNS rebinding is not an application control (see the SSRF row).
* No penetration test by an independent party has been performed.
