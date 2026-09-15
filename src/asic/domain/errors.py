"""Domain error types.

These are raised by deterministic domain logic. They carry no remediation advice and no
model output; they describe what rule was violated so that the caller (and the audit
record) can record it precisely.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - import cycle guard, types only
    from asic.domain.enums import BudgetKind


class DomainError(Exception):
    """Base class for all domain rule violations."""


class IllegalStateTransition(DomainError):
    """A state change was attempted that the state machine does not permit."""


class TenantContextMissing(DomainError):
    """A tenant-scoped operation was attempted with no tenant context bound.

    This is deliberately an error rather than a silent fall-through to "all tenants".
    The database enforces the same rule through row-level security; this exception exists
    to fail fast with a useful message instead of returning an empty result set.
    """


class TenantContextMismatch(DomainError):
    """An operation referenced a tenant other than the one bound to the session."""


class ProvenanceViolation(DomainError):
    """Untrusted content was used where only authority-bearing content is permitted.

    Guards SEC-I4: authority flows only from ``SYSTEM`` and ``HUMAN`` provenance.
    """


class UnregisteredCapability(DomainError):
    """A tool or capability was referenced that the registry does not define.

    Never repaired, only rejected: repairing teaches a planning loop to negotiate for
    capability it was not granted.
    """


class IdempotencyViolation(DomainError):
    """The same logical operation was submitted twice with conflicting content."""


# ------------------------------------------------------------------ orchestration (P4)


class BudgetExhausted(DomainError):
    """A hard limit was reached, or would be by the step about to be taken.

    Carries the dimension so the caller can terminate with the correct reason -
    ``wall_clock_timeout`` and ``budget_exhausted`` are different outcomes with different
    operational responses (master specification section 5).
    """

    def __init__(self, message: str, *, kind: BudgetKind) -> None:
        super().__init__(message)
        self.kind = kind


class ContractViolation(DomainError):
    """A node did something its declared contract does not permit.

    The common case is writing a state key the contract does not list. Declaring allowed
    state mutations and never checking them would make the contract documentation rather
    than a constraint.
    """


class SchemaViolation(DomainError):
    """Structured output failed validation against its declared schema.

    Raised for model output, tool arguments and tool results alike. It is deliberately a
    *typed failure* rather than a coercion: silently repairing a malformed result is how a
    system ends up reasoning over data that does not mean what it appears to mean.
    """


class CapabilityNotGranted(DomainError):
    """A registered capability exists but this tenant, environment or node lacks it.

    Distinct from :class:`UnregisteredCapability` because the two have different
    responses: an unregistered capability is a defect or an attack, whereas an ungranted
    one may be a legitimate configuration difference between environments.
    """


class RiskTierNotPermitted(DomainError):
    """A capability was requested whose risk tier this deployment does not execute.

    In the read-only orchestration kernel every write tier is refused here, before any
    adapter is reached. Fails closed.
    """


class BrokerBypassAttempt(DomainError):
    """Something tried to reach an adapter without going through the tool broker."""


class LeaseNotHeld(DomainError):
    """A worker tried to advance a workflow run whose lease it does not hold.

    Two orchestrators believing they own the same incident is the failure mode with the
    worst consequence in this system, so losing a lease stops work immediately rather than
    being retried.
    """


class ToolFailure(DomainError):
    """A tool invocation failed. Subclassed by the failure classes that differ in retry."""


class ToolTimeout(ToolFailure):
    """A tool call exceeded its declared timeout.

    For a read tool the outcome is known-clean: nothing was changed. For a write tool the
    outcome is *unknown* and must be reconciled by querying actual state, never retried
    blindly - which is why the two are not the same exception.
    """


class ToolAdapterError(ToolFailure):
    """The adapter or upstream system returned an error.

    ``transient`` distinguishes something worth retrying from something that will fail
    identically next time.
    """

    def __init__(self, message: str, *, transient: bool = False) -> None:
        super().__init__(message)
        self.transient = transient


class ModelProviderError(DomainError):
    """A model provider failed to produce a response.

    ``transient`` drives retry and, in a later phase, provider failover. A model outage is
    a reason to pause and preserve gathered evidence, not to discard it.
    """

    def __init__(self, message: str, *, transient: bool = True) -> None:
        super().__init__(message)
        self.transient = transient


# --------------------------------------------------------------- remediation safety (P8)


class PolicyEvaluationFailed(DomainError):
    """The deterministic policy gate could not reach a verdict.

    SI-14: the system fails closed. Raised when a dependency the gate needs - the tenant's
    policy configuration, the registry - is unavailable; the caller treats this exactly
    like a deny, never like an allow.
    """


class ApprovalInvalid(DomainError):
    """An approval exists but does not authorise the action as it currently stands.

    Covers every way SI-6/SI-7 close the "approve a small change, execute a large one"
    attack: the action's parameters changed since approval (hash mismatch), the approval
    expired, it was already decided, or the approver was not authorised for this tier,
    tenant and environment. Never distinguishes further for the caller - all of these mean
    the same thing: do not execute.
    """


class SelfApprovalAttempt(DomainError):
    """An actor attempted to approve an action they proposed.

    INV-10: separation of duties applies to humans exactly as it does to nodes.
    """


class PreconditionDrift(DomainError):
    """State re-checked immediately before execution no longer matches what was proposed.

    SI-7. Raised by the executor after an approval is otherwise valid; the correct
    response is to fail closed, not to execute against state that has moved on.
    """


class BlastRadiusExceeded(DomainError):
    """A configured autonomous-remediation limit was reached.

    Halts autonomous remediation for the scope the limit protects (tenant, incident or
    service) and escalates, rather than continuing under an override no code path grants.
    """
