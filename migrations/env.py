"""Alembic environment.

The connection string comes from the environment, never from ``alembic.ini``, so no
credential is ever committed. Migrations run as the *owner* role; the application connects
as a separate, less privileged role that is subject to row-level security.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Importing the models package is what populates the metadata Alembic compares against.
from asic.db.models import metadata_obj

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = metadata_obj

_URL_ENV_VARS = ("ASIC_MIGRATION_DATABASE_URL", "ASIC_DATABASE_URL")


def _database_url() -> str:
    for var in _URL_ENV_VARS:
        value = os.environ.get(var)
        if value:
            return value
    raise RuntimeError(
        "no database URL for migrations: set "
        + " or ".join(_URL_ENV_VARS)
        + " (it is deliberately absent from alembic.ini so credentials are never committed)"
    )


def include_object(obj, name, type_, reflected, compare_to):  # type: ignore[no-untyped-def]
    """Keep autogenerate focused on objects this project owns.

    The pgvector extension creates its own types; reflecting them into a migration would
    produce a diff that tries to drop them.
    """
    return not (type_ == "table" and name == "alembic_version")


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        include_object=include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _database_url()

    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            include_object=include_object,
            # Transactional DDL: a failed migration leaves no partial schema behind.
            transaction_per_migration=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
