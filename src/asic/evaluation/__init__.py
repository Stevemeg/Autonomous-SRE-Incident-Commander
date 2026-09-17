"""The evaluation harness (Phase 11): golden scenarios, replay, scoring and the regression gate.

The harness executes the same kernels, broker, persistence and traces as production and
scores what they recorded. It never grants authority: a judge score, a gate decision or a
replay fixture is evaluation data and nothing in the product reads it as permission.

Results produced from deterministic simulators or replay fixtures are labelled
``simulator`` / ``replay`` and are never reported as production measurements.
"""
