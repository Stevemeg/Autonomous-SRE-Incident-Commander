"""Governed operational memory.

Memory is not "whatever the model wants to remember". A write request is classified into
one of five :class:`~asic.domain.enums.MemoryCategory` values, evaluated by a deterministic
policy (:mod:`asic.memory.policy`), and - only if it passes - becomes a *proposal*. Nothing
reaches durable memory without a human decision, and only a proposal backed by a
``verified`` verification record can become a ``VERIFIED_FACT``. The request type has no
field in which a caller could claim provenance or verification: both are derived from
records, never declared.
"""
