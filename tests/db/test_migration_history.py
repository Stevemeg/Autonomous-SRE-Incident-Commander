"""Migrations are historical contracts, and these tests hold them to it.

Two properties, and the second is the one that was violated once already.

**A migration's effect must not change.** A database that ran migration `0003` in Phase 3
and a database that runs it today must end up in the same state. The pinned table lists in
`0003` are checked here against what the *Phase 3 models* actually produced, extracted from
the commit itself, so the claim is verified rather than asserted.

**A migration must not derive its effect from live application code.** `0003` originally
computed its table list from the model registry at run time. That was correct on the day it
was written and wrong the moment the models moved ahead: adding one tenant-scoped table in
Phase 4 changed what a Phase 3 migration would do, and a fresh ``upgrade head`` began
failing on a table `0002` had never created. :class:`TestMigrationsAreSelfContained` makes
that class of bug fail the build rather than fail an install.

The upgrade-path tests run real migrations against a throwaway database, because the only
convincing evidence that an existing deployment upgrades cleanly is that one does.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine

from asic.db.models import append_only_tables, tenant_scoped_tables
from tests.conftest import requires_postgres

REPO = Path(__file__).resolve().parents[2]
VERSIONS = REPO / "migrations" / "versions"

#: The commit that introduced migrations 0001-0003. The pinned lists in `0003` must equal
#: what the models at this commit produced.
PHASE_3_COMMIT = "0e263e1"

#: The head as it stood before Phase 4. An existing deployment sits here.
PRE_PHASE_4_HEAD = "0003_tenant_isolation_rls"

#: Helpers a migration must not call, because they read the *current* models rather than
#: the schema as it stood when the migration was written.
LIVE_REGISTRY_HELPERS = frozenset({"tenant_scoped_tables", "append_only_tables"})


def _migration_files() -> list[Path]:
    return sorted(p for p in VERSIONS.glob("*.py") if p.name != "__init__.py")


def _load_migration_module(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"_mig_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _module_for(revision: str) -> ModuleType:
    for path in _migration_files():
        module = _load_migration_module(path)
        if getattr(module, "revision", None) == revision:
            return module
    raise AssertionError(f"no migration file declares revision {revision!r}")


# --------------------------------------------------------------- historical equivalence


class TestPinnedListsMatchHistory:
    """The pinned lists in `0003` must equal what the Phase 3 models produced.

    Verified against the commit, not against a comment. If these ever diverge, migration
    `0003` has silently changed what it does to a database, which is the exact failure the
    pinning was introduced to prevent.
    """

    @pytest.fixture(scope="class")
    @classmethod
    def phase_3_tables(cls) -> dict[str, list[str]]:
        """Table sets computed from the models as they stood at the Phase 3 commit."""
        if not (REPO / ".git").exists():
            pytest.skip("not a git checkout; the historical comparison needs the commit")
        with tempfile.TemporaryDirectory() as workdir:
            archive = subprocess.run(
                ["git", "archive", PHASE_3_COMMIT, "src/asic"],
                cwd=REPO,
                capture_output=True,
                check=False,
            )
            if archive.returncode != 0:
                pytest.skip(f"commit {PHASE_3_COMMIT} unavailable: {archive.stderr[:120]!r}")
            tar = subprocess.run(
                ["tar", "-x", "-C", workdir],
                input=archive.stdout,
                capture_output=True,
                check=False,
            )
            if tar.returncode != 0:  # pragma: no cover - environment without tar
                pytest.skip("tar unavailable; cannot extract the historical tree")

            # A subprocess, because the historical package shares its name with the one
            # already imported: loading both into this interpreter would collide.
            probe = (
                "import sys, json; sys.path.insert(0, sys.argv[1]);"
                "from asic.db.models import tenant_scoped_tables, append_only_tables;"
                "print(json.dumps({'tenant': sorted(tenant_scoped_tables()),"
                " 'append_only': sorted(append_only_tables())}))"
            )
            result = subprocess.run(
                [sys.executable, "-c", probe, str(Path(workdir) / "src")],
                capture_output=True,
                text=True,
                check=False,
                cwd=workdir,
            )
            if result.returncode != 0:  # pragma: no cover - defensive
                pytest.skip(f"could not import the historical models: {result.stderr[-200:]}")
            parsed: dict[str, list[str]] = json.loads(result.stdout)
            return parsed

    def test_tenant_scoped_list_is_exactly_what_phase_3_produced(
        self, phase_3_tables: dict[str, list[str]]
    ) -> None:
        module = _module_for(PRE_PHASE_4_HEAD)
        pinned = sorted(module.TENANT_TABLES)
        assert pinned == phase_3_tables["tenant"], (
            "migration 0003 would now protect a different set of tables than it did in "
            "Phase 3; its effect on a database has changed, which a migration's must not"
        )

    def test_append_only_list_is_exactly_what_phase_3_produced(
        self, phase_3_tables: dict[str, list[str]]
    ) -> None:
        module = _module_for(PRE_PHASE_4_HEAD)
        pinned = sorted(module.APPEND_ONLY_TABLES)
        assert pinned == phase_3_tables["append_only"]

    def test_post_phase_3_tenant_scoped_additions(
        self, phase_3_tables: dict[str, list[str]]
    ) -> None:
        # The corollary: everything 0003 no longer covers must be covered by a later
        # migration. `tenant_scoped_tables()` reads the current models, so this set is
        # every tenant-scoped table added since Phase 3 - Phase 4/5's four, Phase 6's
        # five new knowledge/memory tables (`knowledge_document`, `knowledge_chunk`,
        # `memory_entry` and `memory_promotion` are Phase 3 tables that 0008 only extends),
        # Phase 9's API ledger and the audit correction's immutable remediation target.
        added = tenant_scoped_tables() - set(phase_3_tables["tenant"])
        assert added == {
            "workflow_checkpoint",
            "signal_receipt",
            "investigation_dispatch",
            "incident_reopen_candidate",
            "knowledge_source",
            "knowledge_ingestion",
            "knowledge_retrieval",
            "knowledge_retrieval_result",
            "memory_write_decision",
            "api_idempotency_record",
            "remediation_target",
            "remediation_baseline",
            "model_call_reservation",
            "connector_scope_binding",
            "integration_connector",
        }

    def test_post_phase_3_append_only_additions(self, phase_3_tables: dict[str, list[str]]) -> None:
        added = append_only_tables() - set(phase_3_tables["append_only"])
        assert added == {
            "workflow_checkpoint",
            "signal_receipt",
            "incident_reopen_candidate",
            "knowledge_ingestion",
            "knowledge_retrieval",
            "knowledge_retrieval_result",
            "memory_write_decision",
            "api_idempotency_record",
            "remediation_target",
            "remediation_baseline",
        }


# ------------------------------------------------------------------- self-containment


class TestMigrationsAreSelfContained:
    def test_no_migration_derives_its_tables_from_the_live_model_registry(self) -> None:
        """The guard against the bug that made this correction necessary.

        A migration calling ``tenant_scoped_tables()`` or ``append_only_tables()`` describes
        the schema as it is *now*, not as it was when the migration was written - so a later
        phase silently changes what an earlier migration does.
        """
        offenders: list[str] = []
        for path in _migration_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    offenders.extend(
                        f"{path.name} imports {alias.name}"
                        for alias in node.names
                        if alias.name in LIVE_REGISTRY_HELPERS
                    )
                elif (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in LIVE_REGISTRY_HELPERS
                ):
                    offenders.append(f"{path.name} calls {node.func.id}()")
        assert offenders == [], (
            "a migration reads the live model registry: "
            + "; ".join(offenders)
            + ". Pin the table list to the schema as it stood when the migration was "
            "written; coverage of current models is asserted by the RLS coverage test."
        )

    def test_every_tenant_scoped_table_is_protected_by_some_migration(self) -> None:
        """Pinning must not let a table fall between two migrations.

        The union of every migration's declared tenant table list has to cover the current
        models. A new tenant-scoped table with no protecting migration fails here as well
        as in the live-database coverage test.
        """
        covered: set[str] = set()
        for path in _migration_files():
            module = _load_migration_module(path)
            covered.update(getattr(module, "TENANT_TABLES", ()))
            single = getattr(module, "TABLE", None)
            if isinstance(single, str):
                covered.add(single)
        missing = tenant_scoped_tables() - covered
        assert missing == set(), (
            f"tenant-scoped table(s) {sorted(missing)} are named by no migration, so "
            "nothing enables row-level security on them"
        )

    def test_revision_identifiers_fit_the_alembic_version_column(self) -> None:
        # `alembic_version.version_num` is varchar(32). A longer identifier fails only at
        # the moment the migration is stamped, which is a miserable way to find out.
        for path in _migration_files():
            module = _load_migration_module(path)
            revision = str(getattr(module, "revision", ""))
            assert len(revision) <= 32, f"{path.name}: revision {revision!r} exceeds 32 chars"

    def test_the_revision_chain_is_linear_and_complete(self) -> None:
        modules = [_load_migration_module(p) for p in _migration_files()]
        revisions = {m.revision for m in modules}
        parents = {m.down_revision for m in modules}
        roots = [m for m in modules if m.down_revision is None]
        assert len(roots) == 1, "exactly one migration may have no parent"
        dangling = {p for p in parents if p is not None} - revisions
        assert dangling == set(), f"migration(s) reference missing parent(s) {dangling}"
        assert len(revisions) == len(modules), "duplicate revision identifier"


# -------------------------------------------------------------------- upgrade paths


def _alembic_config(url: str) -> Config:
    config = Config(str(REPO / "alembic.ini"))
    config.set_main_option("script_location", str(REPO / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    return config


@pytest.fixture
def throwaway_database(owner_engine: Engine, database_url: str) -> Iterator[str]:
    """A fresh, empty database that is dropped afterwards.

    The migration tests must not run against the database the rest of the suite is using:
    downgrading it to base mid-run would delete everything under the other tests' feet.
    """
    name = f"asic_migrate_{uuid.uuid4().hex[:12]}"
    url = sa.engine.make_url(database_url)
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
    probe_url = url.set(database=name).render_as_string(hide_password=False)
    previous = os.environ.get("ASIC_MIGRATION_DATABASE_URL")
    os.environ["ASIC_MIGRATION_DATABASE_URL"] = probe_url
    try:
        yield probe_url
    finally:
        if previous is None:
            os.environ.pop("ASIC_MIGRATION_DATABASE_URL", None)
        else:
            os.environ["ASIC_MIGRATION_DATABASE_URL"] = previous
        with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(
                sa.text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :n AND pid <> pg_backend_pid()"
                ),
                {"n": name},
            )
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}"'))


def _protected_tables(url: str) -> set[str]:
    engine = sa.create_engine(url)
    try:
        with engine.connect() as conn:
            return set(
                conn.execute(
                    sa.text(
                        "SELECT relname FROM pg_class WHERE relkind = 'r' "
                        "AND relrowsecurity AND relforcerowsecurity"
                    )
                ).scalars()
            )
    finally:
        engine.dispose()


def _table_names(url: str) -> set[str]:
    engine = sa.create_engine(url)
    try:
        with engine.connect() as conn:
            return set(
                conn.execute(
                    sa.text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = 'public'"
                    )
                ).scalars()
            )
    finally:
        engine.dispose()


@requires_postgres
class TestUpgradePaths:
    def test_accepted_phase_5_head_upgrades_and_correction_round_trips(
        self, throwaway_database: str
    ) -> None:
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "0006_telemetry_ingestion")
        assert "incident_reopen_candidate" not in _table_names(throwaway_database)
        command.upgrade(config, "head")
        assert "incident_reopen_candidate" in _table_names(throwaway_database)
        command.downgrade(config, "0006_telemetry_ingestion")
        assert "incident_reopen_candidate" not in _table_names(throwaway_database)
        command.upgrade(config, "head")
        command.check(config)

    def test_accepted_phase_4_head_upgrades_and_preserves_alerts(
        self, throwaway_database: str
    ) -> None:
        from sqlalchemy.orm import Session

        from asic.db.session import bind_tenant
        from tests.conftest import make_tenant

        config = _alembic_config(throwaway_database)
        command.upgrade(config, "0005_seed_ro_catalogue")
        engine = sa.create_engine(throwaway_database)
        with Session(engine) as session, session.begin():
            tenant = make_tenant(session, "phase4-upgrade-probe")
            bind_tenant(session, tenant.id)
            tenant_id = tenant.id
            # Raw SQL describes the accepted historical schema, not current models.
            alert_id = session.execute(
                sa.text("""INSERT INTO alert
                (tenant_id, source, source_fingerprint, idempotency_key, severity, status, title, started_at)
                VALUES (:t, 'simulator', 'historical', :k, 'high', 'normalised', 'Historical alert', now())
                RETURNING id"""),
                {"t": tenant_id, "k": "a" * 64},
            ).scalar_one()
        command.upgrade(config, "head")
        with engine.connect() as conn:
            row = conn.execute(
                sa.text("SELECT title, source_state FROM alert WHERE id=:i"), {"i": alert_id}
            ).one()
            assert row == ("Historical alert", None)
        command.check(config)
        engine.dispose()

    def test_phase_5_history_blocks_downgrade(self, throwaway_database: str) -> None:
        from sqlalchemy.orm import Session, sessionmaker

        from asic.ingestion.contracts import ConnectorContext
        from asic.ingestion.service import IngestionService
        from tests.conftest import make_tenant

        config = _alembic_config(throwaway_database)
        command.upgrade(config, "head")
        engine = sa.create_engine(throwaway_database)
        factory = sessionmaker(engine, expire_on_commit=False)
        with Session(engine) as session, session.begin():
            tenant = make_tenant(session, "phase5-history-probe")
            context = ConnectorContext(
                tenant_id=tenant.id,
                connector_id="fixture",
                source="simulator",
                service_id=uuid.uuid4(),
                environment_id=uuid.uuid4(),
            )
        IngestionService(factory).ingest(context, b"malformed")
        with pytest.raises(Exception, match="Phase 5 history exists"):
            command.downgrade(config, "0005_seed_ro_catalogue")
        assert "signal_receipt" in _table_names(throwaway_database)
        engine.dispose()

    def test_a_clean_database_upgrades_to_head(self, throwaway_database: str) -> None:
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "head")
        tables = _table_names(throwaway_database)
        assert "workflow_checkpoint" in tables
        assert "alembic_version" in tables

    def test_a_database_at_the_pre_phase_4_head_upgrades_to_head(
        self, throwaway_database: str
    ) -> None:
        """The path an existing deployment takes.

        This is the case the migration-history correction is really about: a database
        stamped at `0003` - the head before Phase 4 - must reach the current head without
        manual intervention.
        """
        config = _alembic_config(throwaway_database)
        command.upgrade(config, PRE_PHASE_4_HEAD)

        at_0003 = _table_names(throwaway_database)
        assert "workflow_checkpoint" not in at_0003, "0004 had not run yet"
        protected_before = _protected_tables(throwaway_database)
        assert len(protected_before) == 30, "0003 protects the Phase 3 tenant-scoped tables"

        command.upgrade(config, "head")

        assert "workflow_checkpoint" in _table_names(throwaway_database)
        protected_after = _protected_tables(throwaway_database)
        assert protected_after == protected_before | {
            "workflow_checkpoint",
            "signal_receipt",
            "investigation_dispatch",
            "incident_reopen_candidate",
            "knowledge_source",
            "knowledge_ingestion",
            "knowledge_retrieval",
            "knowledge_retrieval_result",
            "memory_write_decision",
            "api_idempotency_record",
            "remediation_target",
            "remediation_baseline",
            "model_call_reservation",
            "connector_scope_binding",
            "integration_connector",
        }

    def test_accepted_phase_5_head_upgrades_to_current_head(self, throwaway_database: str) -> None:
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "0006_telemetry_ingestion")
        assert "incident_reopen_candidate" not in _table_names(throwaway_database)
        command.upgrade(config, "head")
        assert "incident_reopen_candidate" in _table_names(throwaway_database)
        assert "knowledge_source" in _table_names(throwaway_database)
        engine = sa.create_engine(throwaway_database)
        try:
            with engine.connect() as conn:
                assert (
                    conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalar_one()
                    == "0016_external_integrations"
                )
        finally:
            engine.dispose()

    def test_phase10_integration_migration_round_trips_from_0015(
        self, throwaway_database: str
    ) -> None:
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "0015_verified_memory_ledger")
        engine = sa.create_engine(throwaway_database)

        def state() -> tuple[bool, bool, int, int]:
            with engine.connect() as connection:
                columns = {
                    column["name"]
                    for column in sa.inspect(connection).get_columns("tool_execution")
                }
                tables = set(sa.inspect(connection).get_table_names())
                trigger = connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM pg_trigger WHERE tgname = "
                        "'derive_tool_execution_effect_class' AND NOT tgisinternal"
                    )
                )
                records = connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM tool_definition WHERE capability LIKE 'notify.%' "
                        "OR capability LIKE 'write.%'"
                    )
                )
            return ("effect_class" in columns, "integration_connector" in tables, trigger, records)

        try:
            assert state() == (False, False, 0, 0)
            command.upgrade(config, "0016_external_integrations")
            assert state() == (True, True, 1, 6)
            command.downgrade(config, "0015_verified_memory_ledger")
            assert state() == (False, False, 0, 0)
            command.upgrade(config, "0016_external_integrations")
            assert state() == (True, True, 1, 6)
        finally:
            engine.dispose()

    def test_phase10_gate_migration_round_trips_from_0014(self, throwaway_database: str) -> None:
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "0014_pre_phase10_safety")
        engine = sa.create_engine(throwaway_database)
        try:
            assert "remediation_baseline_id" not in {
                column["name"] for column in sa.inspect(engine).get_columns("verification")
            }
            command.upgrade(config, "0015_verified_memory_ledger")
            assert "remediation_baseline_id" in {
                column["name"] for column in sa.inspect(engine).get_columns("verification")
            }
            with engine.connect() as connection:
                assert (
                    connection.scalar(
                        sa.text(
                            "SELECT count(*) FROM pg_trigger WHERE tgname = "
                            "'enforce_model_call_reservation_transition' AND NOT tgisinternal"
                        )
                    )
                    == 1
                )
            command.downgrade(config, "0014_pre_phase10_safety")
            assert "remediation_baseline_id" not in {
                column["name"] for column in sa.inspect(engine).get_columns("verification")
            }
            command.upgrade(config, "0015_verified_memory_ledger")
            assert "remediation_baseline_id" in {
                column["name"] for column in sa.inspect(engine).get_columns("verification")
            }
        finally:
            engine.dispose()

    def test_row_level_security_covers_every_tenant_scoped_table_after_upgrade(
        self, throwaway_database: str
    ) -> None:
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "head")
        missing = tenant_scoped_tables() - _protected_tables(throwaway_database)
        assert missing == set(), f"unprotected after upgrade: {sorted(missing)}"

    def test_the_catalogue_is_seeded_and_matches_the_accepted_ceiling(
        self, throwaway_database: str
    ) -> None:
        """Phase 4-7: entirely read-only. Phase 8 (ADR-0023): r1/r2 join it, r3 never does.

        The read catalogue's own rows (migration 0005) are unaffected by migration 0011 -
        asserted separately below - so this is "the write catalogue arrived and nothing
        about the read one changed", not "the ceiling was silently loosened everywhere".
        """
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "head")
        engine = sa.create_engine(throwaway_database)
        try:
            with engine.connect() as conn:
                rows = conn.execute(
                    sa.text("SELECT name, risk_tier::text FROM tool_definition ORDER BY name")
                ).all()
        finally:
            engine.dispose()
        assert rows, "the catalogue seeding migrations ran"
        tiers = {tier for _, tier in rows}
        assert tiers == {"ro", "r1", "r2"}, tiers
        assert "r3" not in tiers, "r3 is never expressible as a registered tool (SI-5)"

        from asic.tools.catalogue import READ_ONLY_CATALOGUE

        read_only_names = {d.name for d in READ_ONLY_CATALOGUE}
        assert all(tier == "ro" for name, tier in rows if name in read_only_names), (
            "the read catalogue's own rows must remain entirely read-only"
        )

    def test_a_full_downgrade_leaves_no_orphan_enum_types(self, throwaway_database: str) -> None:
        """Downgrade is legitimately supported on a database with no execution history.

        ``op.drop_table`` does not drop the ENUM types a table depended on, so an
        incomplete downgrade would leave types behind and the next upgrade would fail with
        "type already exists".
        """
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "head")
        command.downgrade(config, "base")

        engine = sa.create_engine(throwaway_database)
        try:
            with engine.connect() as conn:
                orphans = conn.execute(
                    sa.text(
                        "SELECT count(*) FROM pg_type t JOIN pg_namespace n "
                        "ON n.oid = t.typnamespace "
                        "WHERE n.nspname = 'public' AND t.typtype = 'e'"
                    )
                ).scalar_one()
        finally:
            engine.dispose()
        assert orphans == 0
        assert _table_names(throwaway_database) <= {"alembic_version"}

    def test_the_chain_survives_a_second_round_trip(self, throwaway_database: str) -> None:
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "head")
        command.downgrade(config, "base")
        command.upgrade(config, "head")
        assert tenant_scoped_tables() <= _table_names(throwaway_database)

    def test_head_has_no_schema_drift_from_the_models(self, throwaway_database: str) -> None:
        """``alembic check`` in test form: the models and the migrated schema agree."""
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "head")
        try:
            command.check(config)
        except Exception as exc:  # pragma: no cover - the failure message is the point
            pytest.fail(f"schema drift between the models and the migrations: {exc}")

    def test_a_downgrade_is_refused_once_execution_history_exists(
        self, throwaway_database: str
    ) -> None:
        """The seeding migration's downgrade fails by design once a tool has been used.

        ``fk_tool_execution_tool_definition`` is ``ON DELETE RESTRICT``, so a catalogue row
        cannot be removed while an execution record points at it. Refusing is correct:
        silently orphaning the record that explains what the system did would be worse.
        """
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "head")

        engine = sa.create_engine(throwaway_database)
        try:
            with engine.begin() as conn:
                tenant_id = conn.execute(
                    sa.text(
                        "INSERT INTO tenant (id, slug, display_name, status) "
                        "VALUES (gen_random_uuid(), 'downgrade-probe', 'Probe', 'active') "
                        "RETURNING id"
                    )
                ).scalar_one()
                tool_id = conn.execute(
                    sa.text("SELECT id FROM tool_definition ORDER BY name LIMIT 1")
                ).scalar_one()
                conn.execute(
                    sa.text(
                        "INSERT INTO tool_execution (id, tenant_id, tool_definition_id, "
                        "tool_name, tool_version, capability, risk_tier, idempotency_key, "
                        "actor_type, correlation_id) VALUES (gen_random_uuid(), :t, :d, "
                        "'metrics.query', '1.0.0', 'read.metrics', 'ro', :k, 'agent_node', "
                        "gen_random_uuid())"
                    ),
                    {"t": tenant_id, "d": tool_id, "k": "a" * 64},
                )
        finally:
            engine.dispose()

        with pytest.raises(Exception, match="fk_tool_execution_tool_definition"):
            command.downgrade(config, "0004_workflow_checkpoint")


#: The four governance constraints migration 0008 added NOT VALID and 0010 validates.
_GOVERNANCE_CONSTRAINTS = (
    ("knowledge_document", "ck_knowledge_document_versioned_source"),
    ("knowledge_chunk", "ck_knowledge_chunk_located_chunk"),
    ("memory_entry", "ck_memory_entry_governed_entry"),
    ("memory_promotion", "ck_memory_promotion_governed_promotion"),
)


def _convalidated(url: str, table: str, constraint: str) -> bool:
    engine = sa.create_engine(url)
    try:
        with engine.connect() as conn:
            return bool(
                conn.execute(
                    sa.text(
                        "SELECT convalidated FROM pg_constraint"
                        " WHERE conname = :name AND conrelid = CAST(:table AS regclass)"
                    ),
                    {"name": constraint, "table": table},
                ).scalar_one()
            )
    finally:
        engine.dispose()


def _make_tenant(conn: sa.Connection, slug: str) -> uuid.UUID:
    return conn.execute(
        sa.text(
            "INSERT INTO tenant (id, slug, display_name, status) "
            "VALUES (gen_random_uuid(), :slug, :slug, 'active') RETURNING id"
        ),
        {"slug": slug},
    ).scalar_one()


@requires_postgres
class TestP6CorrectionMigration:
    """P6-08: migration 0010 validates Phase 6's NOT VALID governance constraints -
    correctly, meaning it actually inspects retained rows rather than validating blind.
    """

    def test_clean_database_upgrades_to_head_with_every_constraint_validated(
        self, throwaway_database: str
    ) -> None:
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "head")
        for table, constraint in _GOVERNANCE_CONSTRAINTS:
            assert _convalidated(throwaway_database, table, constraint), (
                f"{table}.{constraint} was not validated on a clean upgrade to head"
            )

    def test_the_access_manage_permission_is_seeded_exactly_once(
        self, throwaway_database: str
    ) -> None:
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "head")
        engine = sa.create_engine(throwaway_database)
        try:
            with engine.connect() as conn:
                count = conn.execute(
                    sa.text(
                        "SELECT count(*) FROM permission"
                        " WHERE key = 'knowledge.source.access.manage'"
                    )
                ).scalar_one()
        finally:
            engine.dispose()
        assert count == 1

    def test_retained_rows_that_already_satisfy_the_constraint_upgrade_and_stay_valid(
        self, throwaway_database: str
    ) -> None:
        """A retained row already shaped like Phase 6 data (e.g. written by 0008-era
        code before 0010 shipped) upgrades cleanly and the constraint still validates."""
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "0009_phase5_cleanup")
        engine = sa.create_engine(throwaway_database)
        try:
            with engine.begin() as conn:
                tenant_id = _make_tenant(conn, "p6-08-valid-retained")
                conn.execute(
                    sa.text(
                        "WITH s AS (INSERT INTO knowledge_source (id, tenant_id, provider, "
                        "source_ref, document_type, trust_class, created_by_type) "
                        "VALUES (gen_random_uuid(), :t, 'git', 'runbooks/valid.md', "
                        "'runbook', 'official_runbook', 'system') RETURNING id) "
                        "INSERT INTO knowledge_document (id, tenant_id, source_uri, title, "
                        "document_type, trust_class, content_hash, source_id, "
                        "content_format, parser_version, chunker_version, "
                        "embedding_model_id, embedding_dimensions, byte_size, chunk_count) "
                        "SELECT gen_random_uuid(), :t, 'runbooks/valid.md', 'Valid', "
                        "'runbook', 'official_runbook', repeat('a', 64), s.id, 'markdown', "
                        "'p1', 'c1', 'm1', 1536, 10, 1 FROM s"
                    ),
                    {"t": tenant_id},
                )
        finally:
            engine.dispose()

        command.upgrade(config, "head")
        assert _convalidated(
            throwaway_database, "knowledge_document", "ck_knowledge_document_versioned_source"
        )
        # The retained row is still there - the migration did not need to touch it.
        engine = sa.create_engine(throwaway_database)
        try:
            with engine.connect() as conn:
                count = conn.execute(
                    sa.text("SELECT count(*) FROM knowledge_document WHERE tenant_id = :t"),
                    {"t": tenant_id},
                ).scalar_one()
        finally:
            engine.dispose()
        assert count == 1

    def test_a_genuinely_invalid_legacy_row_blocks_the_migration_rather_than_validating_blind(
        self, throwaway_database: str
    ) -> None:
        """A pre-Phase-6-shaped row (Phase 6 columns left NULL, as a real pre-Phase-6
        deployment would have) must refuse the migration, not validate over it silently.

        The row has to be written *before* migration 0008 adds the constraint: 0008 adds
        it ``NOT VALID``, which grandfathers rows that already exist but - as PostgreSQL
        always does - still enforces it against every row written from that point on. So
        this is the only way such a row can legitimately exist, and it is exactly the
        scenario 0008's own docstring describes ("none exist in any known database", but
        the schema does not forbid a database where one does).
        """
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "0007_phase5_hardening")
        engine = sa.create_engine(throwaway_database)
        try:
            with engine.begin() as conn:
                tenant_id = _make_tenant(conn, "p6-08-invalid-legacy")
                conn.execute(
                    sa.text(
                        "INSERT INTO knowledge_document (id, tenant_id, source_uri, title, "
                        "document_type, trust_class, content_hash) VALUES (gen_random_uuid(), "
                        ":t, 'runbooks/legacy.md', 'Legacy', 'runbook', 'official_runbook', "
                        "repeat('b', 64))"
                    ),
                    {"t": tenant_id},
                )
        finally:
            engine.dispose()

        with pytest.raises(Exception, match="ck_knowledge_document_versioned_source"):
            command.upgrade(config, "head")

        # The migration must not have partially applied: the permission seed from the
        # same revision must not be visible either, and the constraint must still be
        # exactly as 0008 left it - NOT VALID, not validated, not dropped.
        assert not _convalidated(
            throwaway_database, "knowledge_document", "ck_knowledge_document_versioned_source"
        )
        engine = sa.create_engine(throwaway_database)
        try:
            with engine.connect() as conn:
                count = conn.execute(
                    sa.text(
                        "SELECT count(*) FROM permission"
                        " WHERE key = 'knowledge.source.access.manage'"
                    )
                ).scalar_one()
        finally:
            engine.dispose()
        assert count == 0

        # Superseding the row in place is not valid remediation either: an UPDATE
        # re-checks the constraint against the resulting row the same as an INSERT would
        # (a NOT VALID constraint skips only the one-time historical scan, never ongoing
        # writes), and the row's Phase-6 columns are still NULL. Deleting it is the actual
        # remediation an operator has for a row Phase 6 tooling never produced.
        engine = sa.create_engine(throwaway_database)
        try:
            with (
                pytest.raises(Exception, match="ck_knowledge_document_versioned_source"),
                engine.begin() as conn,
            ):
                conn.execute(
                    sa.text(
                        "UPDATE knowledge_document SET lifecycle = 'superseded', "
                        "superseded_at = now() WHERE tenant_id = :t"
                    ),
                    {"t": tenant_id},
                )
        finally:
            engine.dispose()
        engine = sa.create_engine(throwaway_database)
        try:
            with engine.begin() as conn:
                conn.execute(
                    sa.text("DELETE FROM knowledge_document WHERE tenant_id = :t"), {"t": tenant_id}
                )
        finally:
            engine.dispose()
        command.upgrade(config, "head")
        assert _convalidated(
            throwaway_database, "knowledge_document", "ck_knowledge_document_versioned_source"
        )

    def test_downgrade_restores_the_not_valid_state_and_removes_the_permission(
        self, throwaway_database: str
    ) -> None:
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "head")
        for table, constraint in _GOVERNANCE_CONSTRAINTS:
            assert _convalidated(throwaway_database, table, constraint)
        command.downgrade(config, "0009_phase5_cleanup")
        for table, constraint in _GOVERNANCE_CONSTRAINTS:
            assert not _convalidated(throwaway_database, table, constraint)
        engine = sa.create_engine(throwaway_database)
        try:
            with engine.connect() as conn:
                count = conn.execute(
                    sa.text(
                        "SELECT count(*) FROM permission"
                        " WHERE key = 'knowledge.source.access.manage'"
                    )
                ).scalar_one()
        finally:
            engine.dispose()
        assert count == 0
        command.upgrade(config, "head")
        command.check(config)


def test_the_migrations_directory_is_where_the_tests_think_it_is() -> None:
    # Guards the path assumptions above: a moved directory would make every test here pass
    # vacuously by finding no migrations at all.
    assert VERSIONS.is_dir()
    assert len(_migration_files()) >= 5
    assert shutil.which("git") is not None or not (REPO / ".git").exists()
