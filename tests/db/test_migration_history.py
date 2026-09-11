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

    def test_phase_4_and_5_tenant_scoped_additions(
        self, phase_3_tables: dict[str, list[str]]
    ) -> None:
        # The corollary: everything 0003 no longer covers must be covered by a later
        # migration. Only `workflow_checkpoint` was added, and 0004 creates and protects it
        # in the same migration.
        added = tenant_scoped_tables() - set(phase_3_tables["tenant"])
        assert added == {"workflow_checkpoint", "signal_receipt", "investigation_dispatch"}

    def test_phase_4_and_5_append_only_additions(
        self, phase_3_tables: dict[str, list[str]]
    ) -> None:
        added = append_only_tables() - set(phase_3_tables["append_only"])
        assert added == {"workflow_checkpoint", "signal_receipt"}


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
        }

    def test_row_level_security_covers_every_tenant_scoped_table_after_upgrade(
        self, throwaway_database: str
    ) -> None:
        config = _alembic_config(throwaway_database)
        command.upgrade(config, "head")
        missing = tenant_scoped_tables() - _protected_tables(throwaway_database)
        assert missing == set(), f"unprotected after upgrade: {sorted(missing)}"

    def test_the_catalogue_is_seeded_and_entirely_read_only(self, throwaway_database: str) -> None:
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
        assert rows, "the catalogue seeding migration ran"
        assert {tier for _, tier in rows} == {"ro"}

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


def test_the_migrations_directory_is_where_the_tests_think_it_is() -> None:
    # Guards the path assumptions above: a moved directory would make every test here pass
    # vacuously by finding no migrations at all.
    assert VERSIONS.is_dir()
    assert len(_migration_files()) >= 5
    assert shutil.which("git") is not None or not (REPO / ".git").exists()
