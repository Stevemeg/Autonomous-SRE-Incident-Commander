"""The remediation domain services: what a human actor does, outside the graph.

:mod:`asic.orchestration.remediation` holds the graph and its nodes - the machinery an
incident's own workflow runs through. This package holds the operations a *human* performs
on a remediation action from outside that workflow: deciding an approval. Phase 9's API is
expected to be a thin HTTP wrapper over exactly this module, not a second implementation of
the same authorization logic.
"""

from __future__ import annotations
