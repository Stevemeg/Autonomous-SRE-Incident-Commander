"""Pure domain layer: vocabularies, rules and invariants.

Nothing here touches the database, the network or a model. Everything is deterministic
and unit-testable in isolation, which is what allows the state machine, the idempotency
rules and the safety guards to be verified without infrastructure.
"""
