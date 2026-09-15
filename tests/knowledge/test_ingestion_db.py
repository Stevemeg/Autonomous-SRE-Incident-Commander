"""Versioned, idempotent ingestion against PostgreSQL under the application role."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
import sqlalchemy as sa

from asic.db.models import (
    AuditRecord,
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeIngestion,
    KnowledgeSource,
    UserRoleAssignment,
)
from asic.db.session import bind_tenant
from asic.domain.enums import (
    ActorType,
    KnowledgeContentFormat,
    KnowledgeIngestionOutcome,
    KnowledgeSourceStatus,
    KnowledgeVersionState,
)
from asic.knowledge.contracts import (
    ImportActor,
    LifecyclePrincipal,
    SourceAccessPolicy,
    SourceDocument,
)
from asic.knowledge.embedding import EmbeddingService
from asic.knowledge.errors import EmbeddingFailure, EmbeddingTimeout, KnowledgeRejected
from asic.knowledge.ingestion import KnowledgeIngestionService
from tests.knowledge.conftest import IMPORTER, KnowledgeWorld, make_world

pytestmark = pytest.mark.postgres

POOL_V1 = """# Checkout pool exhaustion

## Symptoms

Checkout requests fail with `PoolTimeoutError` when the connection pool is exhausted.

## Mitigation

1. Restart the checkout deployment.
2. Confirm p95 latency recovers.
"""

POOL_V2 = POOL_V1.replace(
    "Restart the checkout deployment.", "Raise the pool limit to 80, then restart."
)


def _versions(world: KnowledgeWorld, source_id: uuid.UUID | None) -> list[KnowledgeDocument]:
    with world.factory() as session:
        bind_tenant(session, world.tenant_id)
        return list(
            session.scalars(
                sa.select(KnowledgeDocument)
                .where(KnowledgeDocument.source_id == source_id)
                .order_by(KnowledgeDocument.version)
            )
        )


class TestVersioning:
    def test_a_first_import_creates_a_located_embedded_version(self, world: KnowledgeWorld) -> None:
        result = world.ingest("runbooks/pool.md", POOL_V1, revision="a1")
        assert result.outcome is KnowledgeIngestionOutcome.CREATED and result.version == 1
        with world.factory() as session:
            bind_tenant(session, world.tenant_id)
            version = session.get(KnowledgeDocument, result.version_id)
            assert version is not None and version.lifecycle is KnowledgeVersionState.CURRENT
            assert (
                version.parser_version
                and version.chunker_version
                and version.source_revision == "a1"
            )
            chunks = list(
                session.scalars(
                    sa.select(KnowledgeChunk).where(KnowledgeChunk.document_id == version.id)
                )
            )
            assert len(chunks) == result.chunk_count > 0
            for chunk in chunks:
                assert (
                    chunk.embedding is not None
                    and chunk.embedding_model_id == world.embeddings.model.identifier
                )
                assert chunk.start_line and chunk.end_line and chunk.content_hash
        assert world.count(KnowledgeIngestion) == 1

    def test_an_identical_reimport_writes_no_version_and_no_embedding(
        self, world: KnowledgeWorld
    ) -> None:
        first = world.ingest("runbooks/pool.md", POOL_V1)
        calls_after_first = world.provider.calls
        chunks_after_first = world.count(KnowledgeChunk)
        again = world.ingest("runbooks/pool.md", POOL_V1)
        assert again.outcome is KnowledgeIngestionOutcome.UNCHANGED
        assert again.version_id == first.version_id
        assert world.provider.calls == calls_after_first, "unchanged content was re-embedded"
        assert world.count(KnowledgeChunk) == chunks_after_first
        assert world.count(KnowledgeIngestion) == 2  # the attempt is still recorded

    def test_changed_content_supersedes_without_destroying_history(
        self, world: KnowledgeWorld
    ) -> None:
        first = world.ingest("runbooks/pool.md", POOL_V1)
        second = world.ingest("runbooks/pool.md", POOL_V2)
        assert second.outcome is KnowledgeIngestionOutcome.CREATED and second.version == 2
        old, new = _versions(world, first.source_id)
        assert old.lifecycle is KnowledgeVersionState.SUPERSEDED and old.superseded_by_id == new.id
        assert old.superseded_at is not None and new.lifecycle is KnowledgeVersionState.CURRENT
        with world.factory() as session:
            bind_tenant(session, world.tenant_id)
            old_text = " ".join(
                session.scalars(
                    sa.select(KnowledgeChunk.text).where(KnowledgeChunk.document_id == old.id)
                )
            )
        assert "Restart the checkout deployment." in old_text, "history was overwritten"

    def test_a_new_revision_with_the_same_content_is_unchanged_and_recorded(
        self, world: KnowledgeWorld
    ) -> None:
        world.ingest("runbooks/pool.md", POOL_V1, revision="a1")
        again = world.ingest("runbooks/pool.md", POOL_V1, revision="a2")
        assert again.outcome is KnowledgeIngestionOutcome.UNCHANGED
        with world.factory() as session:
            bind_tenant(session, world.tenant_id)
            revisions = list(
                session.scalars(
                    sa.select(KnowledgeIngestion.source_revision).order_by(
                        KnowledgeIngestion.created_at
                    )
                )
            )
        assert revisions == ["a1", "a2"]

    def test_content_returning_to_an_earlier_state_is_a_new_version(
        self, world: KnowledgeWorld
    ) -> None:
        first = world.ingest("runbooks/pool.md", POOL_V1)
        world.ingest("runbooks/pool.md", POOL_V2)
        third = world.ingest("runbooks/pool.md", POOL_V1)
        assert third.outcome is KnowledgeIngestionOutcome.CREATED and third.version == 3
        assert [v.lifecycle for v in _versions(world, first.source_id)] == [
            KnowledgeVersionState.SUPERSEDED,
            KnowledgeVersionState.SUPERSEDED,
            KnowledgeVersionState.CURRENT,
        ]

    def test_a_pipeline_change_is_a_reindex_not_a_no_op(
        self, world: KnowledgeWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asic.knowledge.ingestion as ingestion

        first = world.ingest("runbooks/pool.md", POOL_V1)
        monkeypatch.setattr(ingestion, "CHUNKER_VERSION", "structure-aware/2")
        second = world.ingest("runbooks/pool.md", POOL_V1)
        assert second.outcome is KnowledgeIngestionOutcome.CREATED
        assert second.content_hash == first.content_hash and second.version == 2

    def test_a_revoked_current_version_leaves_no_current_version(
        self, world: KnowledgeWorld
    ) -> None:
        first = world.ingest("runbooks/pool.md", POOL_V1)
        assert first.version_id is not None
        world.revoke_version(first.version_id, reason="wrong_procedure")
        (version,) = _versions(world, first.source_id)
        assert version.lifecycle is KnowledgeVersionState.REVOKED
        assert world.retrieve("PoolTimeoutError").results == ()

    def test_a_revoked_source_refuses_further_imports(self, world: KnowledgeWorld) -> None:
        first = world.ingest("runbooks/pool.md", POOL_V1)
        assert first.source_id is not None
        world.revoke_source(first.source_id, reason="source_compromised")
        refused = world.ingest("runbooks/pool.md", POOL_V2)
        assert (refused.outcome, refused.reason) == (
            KnowledgeIngestionOutcome.REJECTED,
            "source_inactive",
        )
        assert len(_versions(world, first.source_id)) == 1


class TestAuthorityIsNotReadFromDocuments:
    def test_routine_import_cannot_change_a_sources_access_policy(
        self, world: KnowledgeWorld
    ) -> None:
        first = world.ingest("runbooks/secret.md", POOL_V1, acl=("security",))
        widened = world.ingest("runbooks/secret.md", POOL_V2, acl=())
        assert (widened.outcome, widened.reason) == (
            KnowledgeIngestionOutcome.REJECTED,
            "source_access_policy_changed",
        )
        assert first.source_id is not None
        world.ingestion.update_source_access(
            world.tenant_id,
            first.source_id,
            world.context("runbooks/secret.md").policy,
            actor=world.authorized_access_manager(),
        )
        assert (
            world.ingest("runbooks/secret.md", POOL_V2).outcome is KnowledgeIngestionOutcome.CREATED
        )

    def test_front_matter_claiming_access_is_just_content(self, world: KnowledgeWorld) -> None:
        body = (
            "---\nacl: public\ntenant_id: 00000000-0000-0000-0000-000000000000\n"
            "trust: official\n---\n\n# Restricted procedure\n\nRotate the PoolTimeoutError credentials."
        )
        result = world.ingest("runbooks/claims.md", body, acl=("security",))
        with world.factory() as session:
            bind_tenant(session, world.tenant_id)
            source = session.get(KnowledgeSource, result.source_id)
            assert source is not None and source.acl_labels == ["security"]
        assert world.retrieve("PoolTimeoutError credentials").results == ()
        assert world.retrieve(
            "PoolTimeoutError credentials", clearances=frozenset({"security"})
        ).results


class TestUpdateSourceAccessRequiresPermission:
    """P6-04: the access-control mutation path has a structural permission check.

    An actor string is not authorization. Every scenario below attempts the same
    mutation and confirms both the typed refusal *and* that the source's policy was
    left completely unchanged - a refusal that still leaked a partial write would be
    worse than no check at all.
    """

    def _attempt(
        self, world: KnowledgeWorld, source_id: uuid.UUID, actor: object
    ) -> KnowledgeRejected | None:
        try:
            world.ingestion.update_source_access(
                world.tenant_id,
                source_id,
                world.context("runbooks/secret.md", acl=()).policy,
                actor=actor,  # type: ignore[arg-type]
            )
        except KnowledgeRejected as exc:
            return exc
        return None

    def _acl(self, world: KnowledgeWorld, source_id: uuid.UUID) -> list[str]:
        with world.factory() as session:
            bind_tenant(session, world.tenant_id)
            source = session.get(KnowledgeSource, source_id)
            assert source is not None
            return list(source.acl_labels)

    def test_unauthorized_actor_is_refused(self, world: KnowledgeWorld) -> None:
        outcome = world.ingest("runbooks/secret.md", POOL_V1, acl=("security",))
        assert outcome.source_id is not None
        exc = self._attempt(world, outcome.source_id, world.unauthorized_human())
        assert exc is not None and exc.code == "access_manage_not_authorized"
        assert self._acl(world, outcome.source_id) == ["security"]

    def test_a_system_connector_actor_is_refused_even_though_it_only_imports_routinely(
        self, world: KnowledgeWorld
    ) -> None:
        """The actor that may *create* a source is not automatically the actor that may
        *change its access policy* - the two are different operations with different
        authorization requirements."""
        outcome = world.ingest("runbooks/secret.md", POOL_V1, acl=("security",))
        assert outcome.source_id is not None
        exc = self._attempt(world, outcome.source_id, IMPORTER)
        assert exc is not None and exc.code == "access_manage_not_authorized"
        assert self._acl(world, outcome.source_id) == ["security"]

    def test_fabricated_actor_metadata_naming_a_real_grant_is_refused(
        self, world: KnowledgeWorld
    ) -> None:
        """A ``system``-typed actor cannot borrow a real, authorized human's ``user_id``:
        the actor *type* itself is part of what is checked, not merely the id."""
        outcome = world.ingest("runbooks/secret.md", POOL_V1, acl=("security",))
        assert outcome.source_id is not None
        real_admin = world.authorized_access_manager()
        forged = ImportActor(
            actor_type=ActorType.SYSTEM, actor_id="connector:pretending", user_id=real_admin.user_id
        )
        exc = self._attempt(world, outcome.source_id, forged)
        assert exc is not None and exc.code == "access_manage_not_authorized"
        assert self._acl(world, outcome.source_id) == ["security"]

    def test_fabricated_user_id_with_no_matching_grant_is_refused(
        self, world: KnowledgeWorld
    ) -> None:
        outcome = world.ingest("runbooks/secret.md", POOL_V1, acl=("security",))
        assert outcome.source_id is not None
        forged = ImportActor(actor_type=ActorType.HUMAN, actor_id="nobody", user_id=uuid.uuid4())
        exc = self._attempt(world, outcome.source_id, forged)
        assert exc is not None and exc.code == "access_manage_not_authorized"
        assert self._acl(world, outcome.source_id) == ["security"]

    def test_cross_tenant_actor_is_refused(self, world: KnowledgeWorld) -> None:
        outcome = world.ingest("runbooks/secret.md", POOL_V1, acl=("security",))
        assert outcome.source_id is not None
        other = make_world(world.factory.kw["bind"])
        other_admin = other.authorized_access_manager()
        exc = self._attempt(world, outcome.source_id, other_admin)
        assert exc is not None and exc.code == "access_manage_not_authorized"
        assert self._acl(world, outcome.source_id) == ["security"]

    def test_revoked_permission_is_refused(self, world: KnowledgeWorld) -> None:
        outcome = world.ingest("runbooks/secret.md", POOL_V1, acl=("security",))
        assert outcome.source_id is not None
        admin = world.authorized_access_manager()
        # Works while the grant is current.
        world.ingestion.update_source_access(
            world.tenant_id,
            outcome.source_id,
            world.context("runbooks/secret.md", acl=("security", "on-call")).policy,
            actor=admin,
        )
        assert self._acl(world, outcome.source_id) == ["on-call", "security"]
        # The grant is revoked (the role assignment removed).
        with world.factory() as session, session.begin():
            from asic.db.models import UserRoleAssignment

            bind_tenant(session, world.tenant_id)
            session.execute(
                sa.delete(UserRoleAssignment).where(
                    UserRoleAssignment.tenant_id == world.tenant_id,
                    UserRoleAssignment.user_id == admin.user_id,
                )
            )
        exc = self._attempt(world, outcome.source_id, admin)
        assert exc is not None and exc.code == "access_manage_not_authorized"
        assert self._acl(world, outcome.source_id) == ["on-call", "security"]

    def test_authorized_actor_succeeds(self, world: KnowledgeWorld) -> None:
        outcome = world.ingest("runbooks/secret.md", POOL_V1, acl=("security",))
        assert outcome.source_id is not None
        admin = world.authorized_access_manager()
        world.ingestion.update_source_access(
            world.tenant_id,
            outcome.source_id,
            world.context("runbooks/secret.md").policy,
            actor=admin,
        )
        assert self._acl(world, outcome.source_id) == []

    def test_concurrent_access_updates_serialize_without_corrupting_the_policy(
        self, world: KnowledgeWorld
    ) -> None:
        """Two authorized updates racing for the same source: the advisory lock still
        serializes them, so the result is one policy or the other, never a mix."""
        outcome = world.ingest("runbooks/secret.md", POOL_V1, acl=("security",))
        assert outcome.source_id is not None
        source_id = outcome.source_id
        admin = world.authorized_access_manager()
        barrier = Barrier(2)

        def widen() -> None:
            barrier.wait(timeout=5)
            world.ingestion.update_source_access(
                world.tenant_id,
                source_id,
                world.context("runbooks/secret.md", acl=("security", "on-call")).policy,
                actor=admin,
            )

        def narrow() -> None:
            barrier.wait(timeout=5)
            world.ingestion.update_source_access(
                world.tenant_id,
                source_id,
                world.context("runbooks/secret.md", acl=("security",)).policy,
                actor=admin,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(widen), pool.submit(narrow)]
            for future in futures:
                future.result(timeout=10)
        final = self._acl(world, source_id)
        assert final in (["security"], ["on-call", "security"])

    def test_a_document_cannot_extend_its_own_freshness(self, world: KnowledgeWorld) -> None:
        future = world.clock.now() + timedelta(days=3650)
        result = world.ingest("runbooks/fresh.md", POOL_V1, review_days=30, updated_at=future)
        (version,) = _versions(world, result.source_id)
        assert version.fresh_until == world.clock.now() + timedelta(days=30)

    def test_scope_must_name_this_tenants_catalogue(self, world: KnowledgeWorld) -> None:
        other = make_world(world.factory.kw["bind"])  # another tenant's service
        refused = world.ingest("runbooks/x.md", POOL_V1, services=(other.checkout,))
        assert (refused.outcome, refused.reason) == (
            KnowledgeIngestionOutcome.REJECTED,
            "unknown_service_scope",
        )
        assert world.count(KnowledgeSource) == 0


class TestFailures:
    @pytest.mark.parametrize(
        ("body", "reason"),
        [
            (b"x" * (512 * 1024 + 1), "document_too_large"),
            (b"\xff\xfe\xfd", "invalid_utf8"),
            (b"   ", "empty_document"),
        ],
        ids=["oversize", "invalid-utf8", "empty"],
    )
    def test_unusable_documents_leave_a_durable_typed_receipt(
        self, world: KnowledgeWorld, body: bytes, reason: str
    ) -> None:
        result = world.ingest("runbooks/bad.md", body)
        assert (result.outcome, result.reason) == (KnowledgeIngestionOutcome.REJECTED, reason)
        assert world.count(KnowledgeIngestion, KnowledgeIngestion.reason == reason) == 1
        assert world.count(KnowledgeDocument) == 0

    def test_an_unsupported_format_is_refused_by_the_type(self) -> None:
        from pydantic import ValidationError

        from asic.knowledge.contracts import SourceDocument

        with pytest.raises(ValidationError):
            SourceDocument.model_validate({"title": "t", "body": b"x", "content_format": "pdf"})

    def test_an_embedding_failure_is_recorded_and_writes_nothing(
        self, world: KnowledgeWorld
    ) -> None:
        class Broken:
            model = world.embeddings.model

            def embed(self, texts: Sequence[str]) -> Sequence[Sequence[float]]:
                raise RuntimeError("provider down")

        service = KnowledgeIngestionService(
            world.factory, EmbeddingService(Broken()), clock=world.clock
        )
        with pytest.raises(EmbeddingFailure):
            service.ingest(world.context("runbooks/pool.md"), _doc(POOL_V1))
        assert (
            world.count(
                KnowledgeIngestion, KnowledgeIngestion.outcome == KnowledgeIngestionOutcome.FAILED
            )
            == 1
        )
        assert world.count(KnowledgeDocument) == 0 and world.count(KnowledgeChunk) == 0

    def test_an_embedding_timeout_is_typed_and_recorded(self, world: KnowledgeWorld) -> None:
        import time

        class Slow:
            model = world.embeddings.model

            def embed(self, texts: Sequence[str]) -> Sequence[Sequence[float]]:
                time.sleep(3)
                return []

        service = KnowledgeIngestionService(
            world.factory, EmbeddingService(Slow(), timeout_seconds=0.2), clock=world.clock
        )
        with pytest.raises(EmbeddingTimeout):
            service.ingest(world.context("runbooks/pool.md"), _doc(POOL_V1))
        assert (
            world.count(KnowledgeIngestion, KnowledgeIngestion.reason == "embedding_timeout") == 1
        )


class TestConcurrency:
    def test_concurrent_identical_imports_create_exactly_one_version(
        self, world: KnowledgeWorld
    ) -> None:
        barrier = Barrier(6)

        def run(_: int) -> KnowledgeIngestionOutcome:
            barrier.wait(timeout=10)
            return world.ingest("runbooks/race.md", POOL_V1).outcome

        with ThreadPoolExecutor(max_workers=6) as pool:
            outcomes = list(pool.map(run, range(6)))
        assert outcomes.count(KnowledgeIngestionOutcome.CREATED) == 1
        assert outcomes.count(KnowledgeIngestionOutcome.UNCHANGED) == 5
        assert world.count(KnowledgeDocument) == 1

    def test_concurrent_different_revisions_serialize_into_distinct_versions(
        self, world: KnowledgeWorld
    ) -> None:
        barrier = Barrier(2)

        def run(body: str) -> int | None:
            barrier.wait(timeout=10)
            return world.ingest("runbooks/race.md", body).version

        with ThreadPoolExecutor(max_workers=2) as pool:
            versions = sorted(v or 0 for v in pool.map(run, [POOL_V1, POOL_V2]))
        assert versions == [1, 2]
        current = world.count(
            KnowledgeDocument, KnowledgeDocument.lifecycle == KnowledgeVersionState.CURRENT
        )
        assert current == 1


class TestImmutability:
    @pytest.mark.parametrize(
        "statement",
        [
            "UPDATE knowledge_chunk SET text = 'rewritten'",
            "UPDATE knowledge_document SET content_hash = repeat('0', 64)",
            "UPDATE knowledge_document SET title = 'rewritten'",
            "DELETE FROM knowledge_document",
            "DELETE FROM knowledge_chunk",
            "UPDATE knowledge_source SET provider = 'elsewhere'",
            "DELETE FROM knowledge_source",
            "UPDATE knowledge_ingestion SET reason = 'rewritten'",
        ],
    )
    def test_the_application_role_cannot_rewrite_knowledge(
        self, world: KnowledgeWorld, statement: str
    ) -> None:
        world.ingest("runbooks/pool.md", POOL_V1)
        with (
            world.factory() as session,
            pytest.raises(sa.exc.ProgrammingError, match="permission denied"),
        ):
            bind_tenant(session, world.tenant_id)
            session.execute(sa.text(statement))

    def test_another_tenant_sees_nothing(self, world: KnowledgeWorld) -> None:
        world.ingest("runbooks/pool.md", POOL_V1)
        other = make_world(world.factory.kw["bind"])
        assert other.count(KnowledgeSource) == 0 and other.count(KnowledgeChunk) == 0
        with other.factory() as session:
            bind_tenant(session, other.tenant_id)
            assert session.scalar(sa.text("SELECT count(*) FROM knowledge_document")) == 0

    def test_deleting_a_source_withdraws_it_and_cannot_be_undone_by_revocation(
        self, world: KnowledgeWorld
    ) -> None:
        result = world.ingest("runbooks/pool.md", POOL_V1)
        assert result.source_id is not None
        world.delete_source(result.source_id, reason="retired")
        with world.factory() as session:
            bind_tenant(session, world.tenant_id)
            source = session.get(KnowledgeSource, result.source_id)
            assert source is not None and source.status is KnowledgeSourceStatus.DELETED
        with pytest.raises(KnowledgeRejected, match="source_deleted"):
            world.revoke_source(result.source_id, reason="x")


class TestLifecycleAuthority:
    @pytest.mark.parametrize("operation", ["revoke_source", "delete_source", "revoke_version"])
    def test_attribution_object_never_grants_lifecycle_authority(
        self, world: KnowledgeWorld, operation: str
    ) -> None:
        result = world.ingest(f"runbooks/{operation}.md", POOL_V1)
        target_id = result.version_id if operation == "revoke_version" else result.source_id
        assert target_id is not None
        with pytest.raises(KnowledgeRejected, match="lifecycle_manage_not_authorized"):
            getattr(world.ingestion, operation)(
                world.tenant_id,
                target_id,
                reason="audit_probe",
                actor=IMPORTER,
                principal=LifecyclePrincipal(user_id=uuid.uuid4()),
            )
        with world.factory() as session:
            bind_tenant(session, world.tenant_id)
            denial = session.scalar(
                sa.select(AuditRecord)
                .where(AuditRecord.target_id == str(target_id), AuditRecord.outcome == "denied")
                .order_by(AuditRecord.occurred_at.desc())
                .limit(1)
            )
            assert denial is not None

    def test_authorized_lifecycle_change_records_the_authority_identity(
        self, world: KnowledgeWorld
    ) -> None:
        result = world.ingest("runbooks/authorized-lifecycle.md", POOL_V1)
        assert result.source_id is not None
        actor, principal = world.authorized_lifecycle_manager("audited-lifecycle-admin")
        world.ingestion.revoke_source(
            world.tenant_id,
            result.source_id,
            reason="retired",
            actor=actor,
            principal=principal,
        )
        with world.factory() as session:
            bind_tenant(session, world.tenant_id)
            success = session.scalar(
                sa.select(AuditRecord)
                .where(
                    AuditRecord.target_id == str(result.source_id),
                    AuditRecord.outcome == "succeeded",
                )
                .order_by(AuditRecord.occurred_at.desc())
                .limit(1)
            )
            assert success is not None
            assert success.payload_redacted["authorized_principal_id"] == str(principal.user_id)

    def test_current_role_revocation_immediately_removes_lifecycle_authority(
        self, world: KnowledgeWorld
    ) -> None:
        result = world.ingest("runbooks/revoked-admin.md", POOL_V1)
        assert result.source_id is not None
        actor, principal = world.authorized_lifecycle_manager("revoked-lifecycle-admin")
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            session.execute(
                sa.delete(UserRoleAssignment).where(UserRoleAssignment.user_id == principal.user_id)
            )
        with pytest.raises(KnowledgeRejected, match="lifecycle_manage_not_authorized"):
            world.ingestion.revoke_source(
                world.tenant_id,
                result.source_id,
                reason="must_fail",
                actor=actor,
                principal=principal,
            )

    def test_cross_tenant_lifecycle_authority_fails_closed(self, world: KnowledgeWorld) -> None:
        result = world.ingest("runbooks/cross-tenant.md", POOL_V1)
        assert result.source_id is not None
        other = make_world(world.factory.kw["bind"])
        actor, principal = other.authorized_lifecycle_manager("other-tenant-admin")
        with pytest.raises(KnowledgeRejected, match="lifecycle_manage_not_authorized"):
            world.ingestion.revoke_source(
                world.tenant_id,
                result.source_id,
                reason="cross_tenant",
                actor=actor,
                principal=principal,
            )


def _doc(body: str) -> SourceDocument:
    return SourceDocument(
        title="Runbook", body=body.encode(), content_format=KnowledgeContentFormat.MARKDOWN
    )


def _policy(world: KnowledgeWorld) -> SourceAccessPolicy:
    return world.context("x").policy
