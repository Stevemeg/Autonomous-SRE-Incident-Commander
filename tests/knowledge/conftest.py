"""A committed, tenant-isolated knowledge world for database-backed Phase 6 tests.

Every test gets its own tenant, so tests are isolated by tenancy rather than by rollback,
and concurrency tests can use genuinely separate connections. All access is through the
unprivileged application role.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from asic.db.models import (
    Environment,
    Permission,
    Role,
    RolePermission,
    Service,
    User,
    UserRoleAssignment,
)
from asic.db.session import bind_tenant
from asic.domain.clock import FrozenClock
from asic.domain.enums import (
    ActorType,
    KnowledgeContentFormat,
    KnowledgeDocumentType,
    RetrievalPrincipalKind,
    TrustClass,
)
from asic.knowledge.contracts import (
    ImportActor,
    ImportContext,
    IngestionResult,
    RetrievalPrincipal,
    RetrievalQuery,
    RetrievalResultSet,
    RetrievalScope,
    SourceAccessPolicy,
    SourceDocument,
)
from asic.knowledge.embedding import (
    DeterministicEmbeddingProvider,
    EmbeddingModel,
    EmbeddingService,
)
from asic.knowledge.ingestion import ACCESS_MANAGE_PERMISSION, KnowledgeIngestionService
from asic.knowledge.retrieval import KnowledgeRetriever, RetrievalPolicy
from tests.kernel_fixtures import build_fixture

CLOCK_START = datetime(2026, 9, 11, 10, 0, tzinfo=UTC)
IMPORTER = ImportActor(actor_type=ActorType.SYSTEM, actor_id="connector:git-runbooks")


class CountingProvider:
    """The deterministic provider, counting calls so re-embedding is observable."""

    def __init__(self) -> None:
        self.inner = DeterministicEmbeddingProvider()
        self.calls = 0

    @property
    def model(self) -> EmbeddingModel:
        return self.inner.model

    def embed(self, texts: Sequence[str]) -> Sequence[Sequence[float]]:
        self.calls += 1
        return self.inner.embed(texts)


@dataclass
class KnowledgeWorld:
    factory: sessionmaker[Session]
    tenant_id: uuid.UUID
    checkout: uuid.UUID
    payments: uuid.UUID
    production: uuid.UUID
    staging: uuid.UUID
    incident_id: uuid.UUID
    behaviour_id: uuid.UUID
    clock: FrozenClock
    provider: CountingProvider
    embeddings: EmbeddingService
    ingestion: KnowledgeIngestionService
    retriever: KnowledgeRetriever

    def context(
        self,
        ref: str,
        *,
        document_type: KnowledgeDocumentType = KnowledgeDocumentType.RUNBOOK,
        trust_class: TrustClass = TrustClass.OFFICIAL_RUNBOOK,
        services: tuple[uuid.UUID, ...] = (),
        environments: tuple[uuid.UUID, ...] = (),
        acl: tuple[str, ...] = (),
        review_days: int | None = None,
        provider: str = "git",
    ) -> ImportContext:
        return ImportContext(
            tenant_id=self.tenant_id,
            provider=provider,
            source_ref=ref,
            policy=SourceAccessPolicy(
                document_type=document_type,
                trust_class=trust_class,
                service_ids=services,
                environment_ids=environments,
                acl_labels=acl,
                review_interval_days=review_days,
            ),
            actor=IMPORTER,
        )

    def ingest(
        self,
        ref: str,
        body: str | bytes,
        *,
        title: str = "Runbook",
        content_format: KnowledgeContentFormat = KnowledgeContentFormat.MARKDOWN,
        revision: str | None = None,
        updated_at: datetime | None = None,
        **policy: object,
    ) -> IngestionResult:
        return self.ingestion.ingest(
            self.context(ref, **policy),  # type: ignore[arg-type]
            SourceDocument(
                title=title,
                body=body.encode("utf-8") if isinstance(body, str) else body,
                content_format=content_format,
                source_revision=revision,
                source_updated_at=updated_at,
            ),
        )

    def principal(
        self,
        clearances: frozenset[str] = frozenset(),
        *,
        tenant_id: uuid.UUID | None = None,
    ) -> RetrievalPrincipal:
        return RetrievalPrincipal(
            tenant_id=tenant_id or self.tenant_id,
            kind=RetrievalPrincipalKind.USER,
            principal_id="user:reviewer",
            clearances=clearances,
        )

    def scope(
        self,
        *,
        services: tuple[uuid.UUID, ...] | None = None,
        environment: uuid.UUID | None = None,
    ) -> RetrievalScope:
        """The default scope :meth:`retrieve` uses - reusable by tests that need to call
        :func:`asic.knowledge.citations.resolve_citation` or
        :func:`asic.knowledge.retrieval.replay_retrieval`/``current_content`` directly with
        the same trusted principal and scope a retrieval was originally made under (or a
        deliberately different one, to prove P6-03's re-authorization)."""
        return RetrievalScope(
            environment_id=environment or self.production,
            service_ids=services or (self.checkout,),
        )

    def retrieve(
        self,
        text: str,
        *,
        services: tuple[uuid.UUID, ...] | None = None,
        environment: uuid.UUID | None = None,
        clearances: frozenset[str] = frozenset(),
        limit: int = 5,
        include_stale: bool = False,
        as_of: datetime | None = None,
        retriever: KnowledgeRetriever | None = None,
        record: bool = False,
    ) -> RetrievalResultSet:
        from asic.knowledge.retrieval import record_retrieval

        with self.factory() as session, session.begin():
            bind_tenant(session, self.tenant_id)
            result = (retriever or self.retriever).retrieve(
                session,
                principal=self.principal(clearances),
                scope=self.scope(services=services, environment=environment),
                query=RetrievalQuery(
                    text=text, limit=limit, include_stale=include_stale, as_of=as_of
                ),
            )
            if record:
                record_retrieval(session, result)
            return result

    def retriever_with(self, policy: RetrievalPolicy) -> KnowledgeRetriever:
        return KnowledgeRetriever(self.embeddings, policy=policy, clock=self.clock)

    def authorized_access_manager(self, subject: str = "access-admin") -> ImportActor:
        """A human holding ``knowledge.source.access.manage`` through a current role
        (P6-04) - the only kind of actor :meth:`~KnowledgeIngestionService.update_source_access`
        accepts."""
        with self.factory() as session, session.begin():
            bind_tenant(session, self.tenant_id)
            permission_id = session.scalar(
                sa.select(Permission.id).where(Permission.key == ACCESS_MANAGE_PERMISSION)
            )
            assert permission_id is not None, "migration 0010 must have seeded the permission"
            user = User(
                id=uuid.uuid4(),
                tenant_id=self.tenant_id,
                external_idp_subject=subject,
                email=f"{subject}@example.invalid",
                display_name=subject,
            )
            session.add(user)
            session.flush()
            role = Role(
                id=uuid.uuid4(),
                key=f"knowledge-admin-{uuid.uuid4().hex[:8]}",
                display_name="Knowledge Access Admin",
                description="Grants knowledge.source.access.manage for this test world.",
                is_system=False,
            )
            session.add(role)
            session.flush()
            session.add(RolePermission(role_id=role.id, permission_id=permission_id))
            session.add(
                UserRoleAssignment(
                    id=uuid.uuid4(),
                    tenant_id=self.tenant_id,
                    user_id=user.id,
                    role_id=role.id,
                    environment_id=None,
                )
            )
            session.flush()
            return ImportActor(actor_type=ActorType.HUMAN, actor_id=subject, user_id=user.id)

    def unauthorized_human(self, subject: str = "no-permissions") -> ImportActor:
        """A real, active human in the tenant who holds no permissions at all."""
        with self.factory() as session, session.begin():
            bind_tenant(session, self.tenant_id)
            user = User(
                id=uuid.uuid4(),
                tenant_id=self.tenant_id,
                external_idp_subject=subject,
                email=f"{subject}@example.invalid",
                display_name=subject,
            )
            session.add(user)
            session.flush()
            return ImportActor(actor_type=ActorType.HUMAN, actor_id=subject, user_id=user.id)

    def count(self, model: object, *where: object) -> int:
        with self.factory() as session:
            bind_tenant(session, self.tenant_id)
            stmt = sa.select(sa.func.count()).select_from(model)  # type: ignore[arg-type]
            for clause in where:
                stmt = stmt.where(clause)  # type: ignore[arg-type]
            return int(session.scalar(stmt) or 0)


def make_world(engine: sa.Engine, *, slug: str | None = None) -> KnowledgeWorld:
    factory = sessionmaker(engine, expire_on_commit=False, autoflush=False)
    with factory() as session, session.begin():
        fixture = build_fixture(session, slug=slug or f"kn-{uuid.uuid4().hex[:12]}")
        payments = Service(
            id=uuid.uuid4(),
            tenant_id=fixture.tenant.id,
            name="payments-api",
            display_name="payments-api",
            owner_team="payments",
            namespaces=["payments"],
        )
        staging = Environment(
            id=uuid.uuid4(),
            tenant_id=fixture.tenant.id,
            name="staging",
            display_name="Staging",
            is_production=False,
        )
        session.add_all([payments, staging])
        session.flush()
        ids = (
            fixture.tenant.id,
            fixture.service.id,
            payments.id,
            fixture.environment.id,
            staging.id,
            fixture.incident.id,
            fixture.behaviour_version.id,
        )
    clock = FrozenClock(start=CLOCK_START)
    provider = CountingProvider()
    embeddings = EmbeddingService(provider)
    return KnowledgeWorld(
        factory=factory,
        tenant_id=ids[0],
        checkout=ids[1],
        payments=ids[2],
        production=ids[3],
        staging=ids[4],
        incident_id=ids[5],
        behaviour_id=ids[6],
        clock=clock,
        provider=provider,
        embeddings=embeddings,
        ingestion=KnowledgeIngestionService(factory, embeddings, clock=clock),
        retriever=KnowledgeRetriever(embeddings, clock=clock),
    )


@pytest.fixture
def world(app_engine: sa.Engine) -> KnowledgeWorld:
    return make_world(app_engine)
