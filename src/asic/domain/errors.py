"""Domain error types.

These are raised by deterministic domain logic. They carry no remediation advice and no
model output; they describe what rule was violated so that the caller (and the audit
record) can record it precisely.
"""

from __future__ import annotations


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
