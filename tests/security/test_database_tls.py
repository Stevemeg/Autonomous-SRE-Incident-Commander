"""NFR-SEC-07: production database connections are verified TLS or nothing (asic.db.tls).

The policy is evaluated before any connection is attempted, so none of these tests needs a
database. The alembic test runs the real migration entry point in a subprocess to prove the
schema-owner path is covered as well as the application engine.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from asic.db.session import create_app_engine
from asic.db.tls import (
    DatabaseTlsPolicyError,
    enforce_database_tls_policy,
    validate_database_tls,
)

pytestmark = pytest.mark.security

REPO = Path(__file__).resolve().parents[2]
MARKER = "never-log-this-marker-0417"
HOST = "db.internal.example"


@pytest.fixture
def ca_file(tmp_path: Path) -> str:
    path = tmp_path / "db-ca.crt"
    path.write_text("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n", "utf-8")
    return str(path)


def _url(query: str = "") -> str:
    base = f"postgresql+psycopg2://asic_app:{MARKER}@{HOST}:5432/asic"
    return f"{base}?{query}" if query else base


@pytest.fixture
def production(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASIC_DEPLOYMENT_ENVIRONMENT", "production")
    monkeypatch.delenv("PGSSLMODE", raising=False)
    monkeypatch.delenv("PGSSLROOTCERT", raising=False)


def _refused(url: str, environ: dict[str, str] | None = None) -> str:
    with pytest.raises(DatabaseTlsPolicyError) as caught:
        validate_database_tls(url, environ=environ or {})
    message = str(caught.value)
    assert MARKER not in message
    assert HOST not in message  # the URL is never echoed, not even its host
    return message


def test_plaintext_is_refused() -> None:
    assert "sslmode=verify-full" in _refused(_url())


@pytest.mark.parametrize("mode", ["disable", "allow", "prefer", "require", "verify-ca"])
def test_every_mode_weaker_than_verify_full_is_refused(mode: str, ca_file: str) -> None:
    message = _refused(_url(f"sslmode={mode}&sslrootcert={ca_file}"))
    assert repr(mode) in message


def test_verify_full_without_a_ca_is_refused() -> None:
    assert "sslrootcert" in _refused(_url("sslmode=verify-full"))


def test_a_ca_path_that_does_not_exist_is_refused(tmp_path: Path) -> None:
    missing = tmp_path / "absent.crt"
    assert "readable file" in _refused(_url(f"sslmode=verify-full&sslrootcert={missing}"))


def test_verified_tls_with_a_mounted_ca_is_accepted(ca_file: str) -> None:
    validate_database_tls(_url(f"sslmode=verify-full&sslrootcert={ca_file}"), environ={})


def test_verified_tls_against_the_system_trust_store_is_accepted() -> None:
    validate_database_tls(_url("sslmode=verify-full&sslrootcert=system"), environ={})


def test_libpq_environment_variables_are_honoured_as_libpq_would(ca_file: str) -> None:
    # Settings may come from PGSSLMODE/PGSSLROOTCERT instead of the URL ...
    validate_database_tls(_url(), environ={"PGSSLMODE": "verify-full", "PGSSLROOTCERT": ca_file})
    # ... but an environment variable cannot rescue a URL that says something weaker,
    # because libpq gives the URL precedence.
    _refused(_url("sslmode=require"), {"PGSSLMODE": "verify-full", "PGSSLROOTCERT": ca_file})


def test_a_unix_socket_is_refused_because_it_never_carries_tls(ca_file: str) -> None:
    socket_url = (
        f"postgresql+psycopg2://asic_app:{MARKER}@/asic"
        f"?host=/var/run/postgresql&sslmode=verify-full&sslrootcert={ca_file}"
    )
    assert "TCP host" in _refused(socket_url)


def test_a_host_list_is_refused(ca_file: str) -> None:
    listed = _url(f"host=a.example,b.example&sslmode=verify-full&sslrootcert={ca_file}")
    _refused(listed)


def test_a_repeated_parameter_is_refused(ca_file: str) -> None:
    repeated = _url(f"sslmode=disable&sslmode=verify-full&sslrootcert={ca_file}")
    assert "repeats" in _refused(repeated)


def test_a_malformed_url_fails_with_a_controlled_error() -> None:
    message = _refused(f"not a url :// {MARKER}")
    assert message == "database URL is malformed"


def test_a_non_postgresql_url_is_refused() -> None:
    _refused("sqlite:///asic.db")


def test_non_production_profiles_may_use_explicit_plaintext(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for profile in ("local", "development", "test", ""):
        monkeypatch.setenv("ASIC_DEPLOYMENT_ENVIRONMENT", profile)
        enforce_database_tls_policy(_url())  # no exception: the boundary is the profile


@pytest.mark.usefixtures("production")
def test_the_application_engine_refuses_plaintext_before_connecting(
    asic_log_records: list[logging.LogRecord],
) -> None:
    with pytest.raises(DatabaseTlsPolicyError) as caught:
        create_app_engine(_url())
    assert MARKER not in str(caught.value)
    assert not any(MARKER in record.getMessage() for record in asic_log_records)


@pytest.mark.usefixtures("production")
def test_the_application_engine_accepts_verified_tls(ca_file: str) -> None:
    engine = create_app_engine(_url(f"sslmode=verify-full&sslrootcert={ca_file}"))
    try:
        assert engine.url.query["sslmode"] == "verify-full"
    finally:
        engine.dispose()


def test_the_migration_entry_point_refuses_plaintext_in_production() -> None:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("PGSSL", "ASIC_DATABASE", "ASIC_MIGRATION"))
    }
    env.update(
        {
            "ASIC_DEPLOYMENT_ENVIRONMENT": "production",
            "ASIC_MIGRATION_DATABASE_URL": _url(),
            "PYTHONPATH": str(REPO / "src"),
        }
    )
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode != 0
    assert "DatabaseTlsPolicyError" in result.stderr
    assert MARKER not in result.stdout + result.stderr
