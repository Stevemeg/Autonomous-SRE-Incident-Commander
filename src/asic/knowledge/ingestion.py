"""Deterministic, idempotent, versioned knowledge ingestion.

The pipeline, in order::

    validate -> canonicalize -> hash -> chunk -> (unchanged? stop) -> embed
             -> lock source -> re-check -> version + chunks + receipt   (one transaction)

**Idempotency is structural, not hopeful.** The version identity is the canonical content
hash together with the pipeline that produced it (parser, chunker, embedding model).
Re-importing identical content returns the current version and writes nothing but a
receipt - no new chunks, no new embeddings. Changed content, or the same content under a
new pipeline version, becomes a new immutable version and the previous one is marked
superseded. Concurrent imports of the same source serialize on a transaction-scoped
PostgreSQL advisory lock in a namespace of their own, and a partial unique index allows at
most one current version per source as the database backstop.

**Embedding happens outside the transaction.** A slow provider must not hold a lock or a
connection. Vectors are computed first and the write transaction is short; a provider that
fails or times out produces a durable ``failed`` receipt and the typed error, never a
version with missing vectors.

**Authority is never read from the document.** Tenant, scope, access labels, document type
and trust class come from the trusted :class:`~asic.knowledge.contracts.ImportContext`. A
routine re-import cannot change a source's access policy: that is an explicit, audited
operation (:meth:`KnowledgeIngestionService.update_source_access`).
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Final

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import (
    Environment,
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeIngestion,
    KnowledgeSource,
    Permission,
    RolePermission,
    Service,
    User,
    UserRoleAssignment,
)
from asic.db.session import apply_statement_timeouts, bind_tenant
from asic.domain.clock import Clock, SystemClock
from asic.domain.enums import (
    ActorType,
    AuditEventType,
    KnowledgeIngestionOutcome,
    KnowledgeSourceStatus,
    KnowledgeVersionState,
    UserStatus,
)
from asic.knowledge import telemetry
from asic.knowledge.canonical import PARSER_VERSION, CanonicalDocument, canonicalize, sanitize
from asic.knowledge.chunking import CHUNKER_VERSION, ChunkDraft, ChunkLimits, chunk_document
from asic.knowledge.contracts import (
    ImportActor,
    ImportContext,
    IngestionResult,
    SourceAccessPolicy,
    SourceDocument,
)
from asic.knowledge.embedding import EmbeddingService
from asic.knowledge.errors import EmbeddingFailure, EmbeddingTimeout, KnowledgeRejected
from asic.observability.audit import AuditWriter

#: Advisory-lock namespace for per-source ingestion serialization. Distinct from every
#: other lock family by construction of the first key (``asic.ingestion.tenant.v1`` is
#: Phase 5's).
SOURCE_LOCK_NAMESPACE: Final[str] = "asic.knowledge.source.v1"

MAX_TITLE_CHARS: Final[int] = 300

#: The permission required to change a knowledge source's access policy (P6-04). Seeded by
#: migration 0010, the same way ``memory.promotion.decide`` was seeded by migration 0008.
ACCESS_MANAGE_PERMISSION: Final[str] = "knowledge.source.access.manage"

_REASON = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def source_lock_key(tenant_id: uuid.UUID, provider: str, source_ref: str) -> tuple[int, int]:
    """PostgreSQL two-int advisory key: (namespace, source identity).

    A 32-bit collision between two sources can only make them serialize against each
    other; it cannot merge their data, which is keyed by the unique source identity.
    """
    namespace = int.from_bytes(
        hashlib.sha256(SOURCE_LOCK_NAMESPACE.encode("utf-8")).digest()[:4], "big", signed=True
    )
    identity = tenant_id.bytes + provider.encode("utf-8") + b"\x00" + source_ref.encode("utf-8")
    key = int.from_bytes(hashlib.sha256(identity).digest()[:4], "big", signed=True)
    return namespace, key


class KnowledgeIngestionService:
    """Imports documents into immutable, retrievable versions."""

    __slots__ = ("_clock", "_embeddings", "_factory", "_limits")

    def __init__(
        self,
        session_factory: Callable[[], Session],
        embeddings: EmbeddingService,
        *,
        clock: Clock | None = None,
        limits: ChunkLimits | None = None,
    ) -> None:
        self._factory = session_factory
        self._embeddings = embeddings
        self._clock = clock or SystemClock()
        self._limits = limits or ChunkLimits()

    # ------------------------------------------------------------------- ingestion

    def ingest(self, context: ImportContext, document: SourceDocument) -> IngestionResult:
        """Import one document revision.

        Returns the recorded outcome for ``created``, ``unchanged`` and ``rejected``.

        Raises:
            EmbeddingFailure: the embedding dependency failed; a ``failed`` receipt has
                been recorded and nothing else was written. Retrying may succeed.
        """
        correlation_id = uuid.uuid4()
        raw_digest = hashlib.sha256(document.body).hexdigest()
        with telemetry.stage(
            "ingest",
            tenant_id=str(context.tenant_id),
            correlation_id=str(correlation_id),
            provider=context.provider,
        ) as span:
            try:
                canonical = canonicalize(document.body, document.content_format)
                title = _clean_title(document.title)
                with telemetry.stage("chunk"):
                    drafts = chunk_document(canonical.text, self._limits)
            except KnowledgeRejected as exc:
                result = self._record(
                    context,
                    document,
                    correlation_id=correlation_id,
                    raw_digest=raw_digest,
                    outcome=KnowledgeIngestionOutcome.REJECTED,
                    reason=exc.code,
                )
                span.set_attribute("outcome", result.outcome.value)
                return result

            policy = context.policy.canonical()
            unchanged = self._current_if_unchanged(context, policy, canonical)
            if unchanged is not None:
                result = self._record(
                    context,
                    document,
                    correlation_id=correlation_id,
                    raw_digest=raw_digest,
                    outcome=KnowledgeIngestionOutcome.UNCHANGED,
                    reason="content_unchanged",
                    canonical=canonical,
                    version=unchanged,
                )
                span.set_attribute("outcome", result.outcome.value)
                return result

            try:
                with telemetry.stage("embed", model=self._embeddings.model.identifier):
                    vectors = self._embeddings.embed(
                        [_embedding_input(title, draft) for draft in drafts]
                    )
                telemetry.embedding_calls.add(1, {"outcome": "ok"})
            except EmbeddingFailure as exc:
                telemetry.embedding_calls.add(
                    1, {"outcome": "timeout" if isinstance(exc, EmbeddingTimeout) else "failed"}
                )
                self._record(
                    context,
                    document,
                    correlation_id=correlation_id,
                    raw_digest=raw_digest,
                    outcome=KnowledgeIngestionOutcome.FAILED,
                    reason=_reason(exc.code),
                    canonical=canonical,
                )
                raise

            result = self._commit(
                context,
                document,
                policy=policy,
                canonical=canonical,
                title=title,
                drafts=drafts,
                vectors=vectors,
                raw_digest=raw_digest,
                correlation_id=correlation_id,
            )
            span.set_attribute("outcome", result.outcome.value)
            if result.version_id is not None:
                span.set_attribute("document_version_id", str(result.version_id))
            return result

    def _commit(
        self,
        context: ImportContext,
        document: SourceDocument,
        *,
        policy: SourceAccessPolicy,
        canonical: CanonicalDocument,
        title: str,
        drafts: tuple[ChunkDraft, ...],
        vectors: list[list[float]],
        raw_digest: str,
        correlation_id: uuid.UUID,
    ) -> IngestionResult:
        with self._factory() as session, session.begin():
            bind_tenant(session, context.tenant_id)
            apply_statement_timeouts(session)
            namespace, key = source_lock_key(
                context.tenant_id, context.provider, context.source_ref
            )
            session.execute(
                sa.text("SELECT pg_advisory_xact_lock(:namespace, :key)"),
                {"namespace": namespace, "key": key},
            )

            def receipt(
                outcome: KnowledgeIngestionOutcome,
                reason: str,
                *,
                source: KnowledgeSource | None,
                version: KnowledgeDocument | None = None,
            ) -> IngestionResult:
                return self._receipt(
                    session,
                    context,
                    document,
                    correlation_id=correlation_id,
                    raw_digest=raw_digest,
                    outcome=outcome,
                    reason=reason,
                    source_id=source.id if source else None,
                    canonical=canonical,
                    version=(version.id, version.version, version.chunk_count or 0)
                    if version
                    else None,
                )

            missing = _missing_scope(session, context.tenant_id, policy)
            if missing is not None:
                return receipt(KnowledgeIngestionOutcome.REJECTED, missing, source=None)

            source = _source(session, context)
            if source is None:
                source = KnowledgeSource(
                    id=uuid.uuid4(),
                    tenant_id=context.tenant_id,
                    provider=context.provider,
                    source_ref=context.source_ref,
                    document_type=policy.document_type,
                    trust_class=policy.trust_class,
                    service_ids=list(policy.service_ids),
                    environment_ids=list(policy.environment_ids),
                    acl_labels=list(policy.acl_labels),
                    review_interval_days=policy.review_interval_days,
                    status=KnowledgeSourceStatus.ACTIVE,
                    created_by_type=context.actor.actor_type,
                    created_by_id=context.actor.actor_id,
                )
                session.add(source)
                session.flush()
            elif source.status is not KnowledgeSourceStatus.ACTIVE:
                return receipt(KnowledgeIngestionOutcome.REJECTED, "source_inactive", source=source)
            elif not _same_policy(source, policy):
                return receipt(
                    KnowledgeIngestionOutcome.REJECTED,
                    "source_access_policy_changed",
                    source=source,
                )

            current = _current_version(session, context.tenant_id, source.id)
            if current is not None and _same_content(current, canonical, self._embeddings):
                return receipt(
                    KnowledgeIngestionOutcome.UNCHANGED,
                    "content_unchanged",
                    source=source,
                    version=current,
                )

            now = self._clock.now()
            highest = session.scalar(
                sa.select(sa.func.max(KnowledgeDocument.version)).where(
                    KnowledgeDocument.tenant_id == context.tenant_id,
                    KnowledgeDocument.source_id == source.id,
                )
            )
            if current is not None:
                # State first, successor link after the insert: the one-current index
                # forbids two current versions even for the length of a statement.
                current.lifecycle = KnowledgeVersionState.SUPERSEDED
                current.superseded_at = now
                session.flush()

            model = self._embeddings.model
            version = KnowledgeDocument(
                id=uuid.uuid4(),
                tenant_id=context.tenant_id,
                source_uri=f"{context.provider}:{context.source_ref}"[:1024],
                title=title,
                document_type=policy.document_type,
                trust_class=policy.trust_class,
                version=(highest or 0) + 1,
                service_ids=list(policy.service_ids),
                environment_ids=list(policy.environment_ids),
                acl_labels=list(policy.acl_labels),
                source_updated_at=document.source_updated_at,
                ingested_at=now,
                content_hash=canonical.content_hash,
                injection_flagged=bool(canonical.injection_flags),
                source_id=source.id,
                lifecycle=KnowledgeVersionState.CURRENT,
                content_format=canonical.content_format,
                source_revision=document.source_revision,
                parser_version=PARSER_VERSION,
                chunker_version=CHUNKER_VERSION,
                embedding_model_id=model.identifier,
                embedding_dimensions=model.dimensions,
                byte_size=len(document.body),
                chunk_count=len(drafts),
                effective_at=now,
                fresh_until=_fresh_until(policy, document.source_updated_at, now),
            )
            session.add(version)
            session.flush()
            if current is not None:
                current.superseded_by_id = version.id
                session.flush()

            session.add_all(
                KnowledgeChunk(
                    id=uuid.uuid4(),
                    tenant_id=context.tenant_id,
                    document_id=version.id,
                    sequence=draft.sequence,
                    text=draft.text,
                    embedding=vector,
                    embedding_model_id=model.identifier,
                    chunk_strategy=draft.strategy,
                    service_ids=list(policy.service_ids),
                    acl_labels=list(policy.acl_labels),
                    content_hash=draft.content_hash,
                    section_path=list(draft.section_path),
                    start_offset=draft.start_offset,
                    end_offset=draft.end_offset,
                    start_line=draft.start_line,
                    end_line=draft.end_line,
                    char_count=len(draft.text),
                )
                for draft, vector in zip(drafts, vectors, strict=True)
            )
            session.flush()
            telemetry.versions_created.add(1, {"document_type": policy.document_type.value})
            telemetry.chunks_per_version.record(len(drafts))
            return receipt(
                KnowledgeIngestionOutcome.CREATED, "version_created", source=source, version=version
            )

    def _current_if_unchanged(
        self, context: ImportContext, policy: SourceAccessPolicy, canonical: CanonicalDocument
    ) -> tuple[uuid.UUID, int, int] | None:
        """Read-only fast path, so unchanged content is never re-embedded."""
        with self._factory() as session, session.begin():
            bind_tenant(session, context.tenant_id)
            apply_statement_timeouts(session)
            source = _source(session, context)
            if source is None or source.status is not KnowledgeSourceStatus.ACTIVE:
                return None
            if not _same_policy(source, policy):
                return None  # the locked path records the refusal
            current = _current_version(session, context.tenant_id, source.id)
            if current is None or not _same_content(current, canonical, self._embeddings):
                return None
            return current.id, current.version, current.chunk_count or 0

    def _record(
        self,
        context: ImportContext,
        document: SourceDocument,
        *,
        correlation_id: uuid.UUID,
        raw_digest: str,
        outcome: KnowledgeIngestionOutcome,
        reason: str,
        canonical: CanonicalDocument | None = None,
        version: tuple[uuid.UUID, int, int] | None = None,
    ) -> IngestionResult:
        """Record an outcome in its own short transaction."""
        with self._factory() as session, session.begin():
            bind_tenant(session, context.tenant_id)
            apply_statement_timeouts(session)
            source = _source(session, context)
            return self._receipt(
                session,
                context,
                document,
                correlation_id=correlation_id,
                raw_digest=raw_digest,
                outcome=outcome,
                reason=reason,
                source_id=source.id if source else None,
                canonical=canonical,
                version=version,
            )

    def _receipt(
        self,
        session: Session,
        context: ImportContext,
        document: SourceDocument,
        *,
        correlation_id: uuid.UUID,
        raw_digest: str,
        outcome: KnowledgeIngestionOutcome,
        reason: str,
        source_id: uuid.UUID | None,
        canonical: CanonicalDocument | None,
        version: tuple[uuid.UUID, int, int] | None,
    ) -> IngestionResult:
        committed = outcome in (
            KnowledgeIngestionOutcome.CREATED,
            KnowledgeIngestionOutcome.UNCHANGED,
        )
        record = KnowledgeIngestion(
            id=uuid.uuid4(),
            tenant_id=context.tenant_id,
            source_id=source_id,
            document_version_id=version[0] if version and committed else None,
            provider=context.provider,
            source_ref=context.source_ref,
            outcome=outcome,
            reason=_reason(reason),
            content_hash=canonical.content_hash if canonical else None,
            raw_digest=raw_digest,
            source_revision=document.source_revision,
            byte_size=len(document.body),
            chunk_count=version[2] if version and committed else None,
            parser_version=PARSER_VERSION if canonical else None,
            chunker_version=CHUNKER_VERSION if canonical else None,
            embedding_model_id=self._embeddings.model.identifier if canonical else None,
            actor_type=context.actor.actor_type,
            actor_id=context.actor.actor_id,
            correlation_id=correlation_id,
        )
        session.add(record)
        session.flush()
        telemetry.ingestion_outcomes.add(1, {"outcome": outcome.value, "reason": record.reason})
        return IngestionResult(
            outcome=outcome,
            reason=record.reason,
            receipt_id=record.id,
            source_id=source_id,
            version_id=record.document_version_id,
            version=version[1] if version and committed else None,
            chunk_count=version[2] if version and committed else 0,
            content_hash=record.content_hash,
            injection_flags=canonical.injection_flags if canonical else (),
        )

    # ----------------------------------------------------------------- lifecycle

    def revoke_source(
        self, tenant_id: uuid.UUID, source_id: uuid.UUID, *, reason: str, actor: ImportActor
    ) -> None:
        """Withdraw a source from every read path, including replay of past retrievals."""
        self._set_source_status(
            tenant_id,
            source_id,
            KnowledgeSourceStatus.REVOKED,
            reason=reason,
            actor=actor,
            event=AuditEventType.CONFIGURATION_CHANGED,
        )

    def delete_source(
        self, tenant_id: uuid.UUID, source_id: uuid.UUID, *, reason: str, actor: ImportActor
    ) -> None:
        """Logically delete a source. Physical purge is retention automation (C8)."""
        self._set_source_status(
            tenant_id,
            source_id,
            KnowledgeSourceStatus.DELETED,
            reason=reason,
            actor=actor,
            event=AuditEventType.DATA_DELETED,
        )

    def revoke_version(
        self, tenant_id: uuid.UUID, version_id: uuid.UUID, *, reason: str, actor: ImportActor
    ) -> None:
        """Withdraw one version. If it was current, the source has no current version."""
        with self._factory() as session, session.begin():
            bind_tenant(session, tenant_id)
            apply_statement_timeouts(session)
            version = session.scalars(
                sa.select(KnowledgeDocument).where(
                    KnowledgeDocument.tenant_id == tenant_id,
                    KnowledgeDocument.id == version_id,
                    KnowledgeDocument.source_id.is_not(None),
                )
            ).one_or_none()
            if version is None:
                raise KnowledgeRejected("unknown_version")
            version.lifecycle = KnowledgeVersionState.REVOKED
            session.flush()
            AuditWriter(tenant_id=tenant_id, clock=self._clock).record(
                session,
                event_type=AuditEventType.CONFIGURATION_CHANGED,
                outcome="succeeded",
                actor_type=actor.actor_type,
                actor_id=actor.actor_id,
                target_type="knowledge_version",
                target_id=str(version_id),
                payload={"change": "version_revoked", "reason": _reason(reason)},
            )

    def update_source_access(
        self,
        tenant_id: uuid.UUID,
        source_id: uuid.UUID,
        policy: SourceAccessPolicy,
        *,
        actor: ImportActor,
    ) -> None:
        """Change who may read a source. Takes effect for every existing version at once.

        Document type and trust class are part of a source's identity and cannot change
        here.

        **Requires ``knowledge.source.access.manage`` (P6-04).** ``actor`` is never trusted
        to already hold this permission: it must be a human, and the permission is
        re-resolved against the RBAC tables - ``app_user``, ``user_role_assignment``,
        ``role_permission``, ``permission`` - through a current, unexpired role
        assignment, the same way :func:`asic.memory.service._may_decide` re-resolves
        ``memory.promotion.decide``. A caller-supplied actor name, an actor type of
        ``system``, or a ``user_id`` naming someone who does not hold the permission are
        refused before the advisory lock is even acquired, let alone before either
        the ACL or the scope changes.

        Raises:
            KnowledgeRejected: ``access_manage_not_authorized`` if the permission check
                fails; ``source_identity_immutable`` or a missing-scope code otherwise.
        """
        canonical = policy.canonical()
        with self._factory() as session, session.begin():
            bind_tenant(session, tenant_id)
            apply_statement_timeouts(session)
            if not _may_manage_access(session, tenant_id, actor, self._clock.now()):
                AuditWriter(tenant_id=tenant_id, clock=self._clock).record(
                    session,
                    event_type=AuditEventType.AUTHORIZATION_DENIED,
                    outcome="denied",
                    actor_type=actor.actor_type,
                    actor_id=actor.actor_id,
                    target_type="knowledge_source",
                    target_id=str(source_id),
                    payload={"reason": "access_manage_not_authorized"},
                )
                session.commit()
                raise KnowledgeRejected("access_manage_not_authorized")
            source = _source_by_id(session, tenant_id, source_id)
            namespace, key = source_lock_key(tenant_id, source.provider, source.source_ref)
            session.execute(
                sa.text("SELECT pg_advisory_xact_lock(:namespace, :key)"),
                {"namespace": namespace, "key": key},
            )
            if (
                canonical.document_type is not source.document_type
                or canonical.trust_class is not source.trust_class
            ):
                raise KnowledgeRejected("source_identity_immutable")
            missing = _missing_scope(session, tenant_id, canonical)
            if missing is not None:
                raise KnowledgeRejected(missing)
            before = _policy_snapshot(source)
            source.service_ids = list(canonical.service_ids)
            source.environment_ids = list(canonical.environment_ids)
            source.acl_labels = list(canonical.acl_labels)
            source.review_interval_days = canonical.review_interval_days
            session.flush()
            AuditWriter(tenant_id=tenant_id, clock=self._clock).record(
                session,
                event_type=AuditEventType.SECURITY_SETTING_CHANGED,
                outcome="succeeded",
                actor_type=actor.actor_type,
                actor_id=actor.actor_id,
                target_type="knowledge_source",
                target_id=str(source_id),
                payload={"before": before, "after": _policy_snapshot(source)},
            )

    def _set_source_status(
        self,
        tenant_id: uuid.UUID,
        source_id: uuid.UUID,
        status: KnowledgeSourceStatus,
        *,
        reason: str,
        actor: ImportActor,
        event: AuditEventType,
    ) -> None:
        with self._factory() as session, session.begin():
            bind_tenant(session, tenant_id)
            apply_statement_timeouts(session)
            source = _source_by_id(session, tenant_id, source_id)
            namespace, key = source_lock_key(tenant_id, source.provider, source.source_ref)
            session.execute(
                sa.text("SELECT pg_advisory_xact_lock(:namespace, :key)"),
                {"namespace": namespace, "key": key},
            )
            if source.status is KnowledgeSourceStatus.DELETED:
                raise KnowledgeRejected("source_deleted")
            source.status = status
            source.status_reason = _reason(reason)
            source.status_changed_at = self._clock.now()
            session.flush()
            AuditWriter(tenant_id=tenant_id, clock=self._clock).record(
                session,
                event_type=event,
                outcome="succeeded",
                actor_type=actor.actor_type,
                actor_id=actor.actor_id,
                target_type="knowledge_source",
                target_id=str(source_id),
                payload={"status": status.value, "reason": source.status_reason},
            )


# ------------------------------------------------------------------------ helpers


def _clean_title(title: str) -> str:
    cleaned, _ = sanitize(title)
    single_line = " ".join(cleaned.split())[:MAX_TITLE_CHARS].strip()
    if not single_line:
        raise KnowledgeRejected("empty_title")
    return single_line


def _embedding_input(title: str, draft: ChunkDraft) -> str:
    """Title and section give a chunk its context; the text is what is cited."""
    return "\n".join((title, " > ".join(draft.section_path), draft.text))


def _reason(code: str) -> str:
    """Reason codes are bounded vocabulary. Anything else is normalised, never echoed."""
    return code if _REASON.match(code) else "unclassified"


def _fresh_until(
    policy: SourceAccessPolicy, source_updated_at: datetime | None, now: datetime
) -> datetime | None:
    """Freshness from the source's own update time, capped at now.

    The cap matters: a document claiming it was updated next year must not buy itself a
    year of extra freshness. Its timestamp is data, not authority.
    """
    if policy.review_interval_days is None:
        return None
    base = min(source_updated_at, now) if source_updated_at else now
    return base + timedelta(days=policy.review_interval_days)


def _source(session: Session, context: ImportContext) -> KnowledgeSource | None:
    return session.scalars(
        sa.select(KnowledgeSource).where(
            KnowledgeSource.tenant_id == context.tenant_id,
            KnowledgeSource.provider == context.provider,
            KnowledgeSource.source_ref == context.source_ref,
        )
    ).one_or_none()


def _source_by_id(session: Session, tenant_id: uuid.UUID, source_id: uuid.UUID) -> KnowledgeSource:
    source = session.scalars(
        sa.select(KnowledgeSource).where(
            KnowledgeSource.tenant_id == tenant_id, KnowledgeSource.id == source_id
        )
    ).one_or_none()
    if source is None:
        raise KnowledgeRejected("unknown_source")
    return source


def _may_manage_access(
    session: Session, tenant_id: uuid.UUID, actor: ImportActor, now: datetime
) -> bool:
    """P6-04: an active human in this tenant, holding the permission through a current
    role - never a caller's self-asserted actor type, name or ``user_id``.

    A ``system`` (connector) actor is refused outright: this schema's RBAC tables
    (:class:`~asic.db.models.tenancy.User` and its role assignments) model human
    principals only, and ``update_source_access`` is exactly the operation SI-4/SI-9-style
    separation exists for - an automated pipeline cannot grant itself broader access than
    the human administrators who configured it.
    """
    if actor.actor_type is not ActorType.HUMAN or actor.user_id is None:
        return False
    return (
        session.scalar(
            sa.select(sa.literal(1))
            .select_from(User)
            .join(
                UserRoleAssignment,
                sa.and_(
                    UserRoleAssignment.tenant_id == User.tenant_id,
                    UserRoleAssignment.user_id == User.id,
                ),
            )
            .join(RolePermission, RolePermission.role_id == UserRoleAssignment.role_id)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(
                User.tenant_id == tenant_id,
                User.id == actor.user_id,
                User.status == UserStatus.ACTIVE,
                Permission.key == ACCESS_MANAGE_PERMISSION,
                sa.or_(
                    UserRoleAssignment.expires_at.is_(None), UserRoleAssignment.expires_at > now
                ),
            )
            .limit(1)
        )
        is not None
    )


def _current_version(
    session: Session, tenant_id: uuid.UUID, source_id: uuid.UUID
) -> KnowledgeDocument | None:
    return session.scalars(
        sa.select(KnowledgeDocument).where(
            KnowledgeDocument.tenant_id == tenant_id,
            KnowledgeDocument.source_id == source_id,
            KnowledgeDocument.lifecycle == KnowledgeVersionState.CURRENT,
        )
    ).one_or_none()


def _same_content(
    version: KnowledgeDocument, canonical: CanonicalDocument, embeddings: EmbeddingService
) -> bool:
    """Same content under the same pipeline. A pipeline change is a re-index."""
    return (
        version.content_hash == canonical.content_hash
        and version.parser_version == PARSER_VERSION
        and version.chunker_version == CHUNKER_VERSION
        and version.embedding_model_id == embeddings.model.identifier
    )


def _same_policy(source: KnowledgeSource, policy: SourceAccessPolicy) -> bool:
    return (
        source.document_type is policy.document_type
        and source.trust_class is policy.trust_class
        and sorted(map(str, source.service_ids)) == [str(s) for s in policy.service_ids]
        and sorted(map(str, source.environment_ids)) == [str(e) for e in policy.environment_ids]
        and sorted(source.acl_labels) == list(policy.acl_labels)
        and source.review_interval_days == policy.review_interval_days
    )


def _policy_snapshot(source: KnowledgeSource) -> dict[str, object]:
    return {
        "service_ids": sorted(map(str, source.service_ids)),
        "environment_ids": sorted(map(str, source.environment_ids)),
        "acl_labels": sorted(source.acl_labels),
        "review_interval_days": source.review_interval_days,
    }


def _missing_scope(
    session: Session, tenant_id: uuid.UUID, policy: SourceAccessPolicy
) -> str | None:
    """Scope must name real catalogue entries in this tenant (RLS applies here too)."""
    if policy.service_ids:
        found = set(
            session.scalars(
                sa.select(Service.id).where(
                    Service.tenant_id == tenant_id, Service.id.in_(policy.service_ids)
                )
            )
        )
        if found != set(policy.service_ids):
            return "unknown_service_scope"
    if policy.environment_ids:
        found = set(
            session.scalars(
                sa.select(Environment.id).where(
                    Environment.tenant_id == tenant_id,
                    Environment.id.in_(policy.environment_ids),
                )
            )
        )
        if found != set(policy.environment_ids):
            return "unknown_environment_scope"
    return None


__all__ = [
    "ACCESS_MANAGE_PERMISSION",
    "SOURCE_LOCK_NAMESPACE",
    "KnowledgeIngestionService",
    "source_lock_key",
]
