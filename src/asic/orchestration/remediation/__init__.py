"""The remediation graph: G6 Remediation Planner through G10 Verifier (Phase 8).

A separate graph from investigation's (:mod:`asic.orchestration.graph`), sharing its
kernel-level abstractions (:class:`~asic.orchestration.context.RunContext`,
:class:`~asic.orchestration.context.UnitOfWork`) but not its state shape or its nodes - see
ADR-0023 for why. Entered only against an incident already in
:attr:`~asic.domain.enums.IncidentStatus.INVESTIGATING` with a persisted, accepted
hypothesis: the accepted state machine (Phase 3) has no edge from ``escalated`` into
remediation, only a human-authored, justified ``escalated -> investigating`` return.
"""

from __future__ import annotations
