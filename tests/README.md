# `tests/` — Test suites

**This directory is intentionally empty.**

No tests exist yet because no implementation exists yet.

Master specification section 17 requires the following test categories, and section 20
states plainly that the happy path working is NOT completion:

- unit
- schema/contract
- API
- database
- adapter
- agent state-transition
- deterministic incident simulation
- historical replay
- evaluation regression
- end-to-end
- load/performance
- resilience/fault injection
- security
- prompt-injection/tool-abuse
- deployment smoke

The suite layout will be established alongside the first implemented component in
Phase 3. Tests are written with the code they cover, not retrofitted afterwards.

Note that evaluation (master specification section 9) is a separate first-class
subsystem, not a test category: it is designed in
[`../docs/evaluation/EVALUATION_ARCHITECTURE.md`](../docs/evaluation/EVALUATION_ARCHITECTURE.md)
and built in Phase 11.
