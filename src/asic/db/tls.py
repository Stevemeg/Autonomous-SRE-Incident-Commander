"""Transport security for database connections (NFR-SEC-07).

A production deployment must not reach PostgreSQL over plaintext, and must not accept a TLS
connection whose server it has not identified. The driver is psycopg2 over libpq, so the
policy is expressed in libpq's own terms rather than invented ones:

* ``sslmode=verify-full`` - encrypt, verify the server certificate chain against a trusted
  CA, and verify that the certificate names the host being connected to. ``require`` and
  ``verify-ca`` are refused: the first authenticates nobody, the second accepts any
  certificate the CA ever issued, for any host.
* ``sslrootcert`` - the CA bundle libpq verifies against, either a readable file (for
  example a mounted Kubernetes Secret) or libpq's ``system`` store. Without it libpq falls
  back to ``~/.postgresql/root.crt``, which does not exist in the read-only image; refusing
  here names the problem instead of surfacing a connection error on first use.
* a TCP host - libpq never negotiates TLS on a unix-domain socket, so a socket path would
  silently downgrade ``verify-full`` to plaintext.

Settings are read from the connection URL, falling back to the ``PGSSLMODE`` and
``PGSSLROOTCERT`` environment variables exactly as libpq itself would, so an environment
variable cannot quietly weaken what the URL appears to say.

Development, test and the local kind overlay may use plaintext: the boundary is the same
``ASIC_DEPLOYMENT_ENVIRONMENT`` marker that already keeps simulators and test credentials
out of production. Encryption *at rest* is a property of the database service, not of this
process, and is outside what the application can enforce (see the production gap register).

No message raised here contains the URL: it can carry a password.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from asic.integrations.credentials import is_production_deployment

#: The only sslmode accepted in production.
REQUIRED_SSLMODE: Final[str] = "verify-full"

#: libpq's value for "use the operating system's trust store" (libpq >= 16).
SYSTEM_TRUST_STORE: Final[str] = "system"

#: libpq's default when nothing sets sslmode: ``prefer`` silently falls back to plaintext.
LIBPQ_DEFAULT_SSLMODE: Final[str] = "prefer"


class DatabaseTlsPolicyError(RuntimeError):
    """The database connection settings do not meet the production transport policy."""


def _single(query: Mapping[str, object], key: str) -> str | None:
    value = query.get(key)
    if value is None:
        return None
    if isinstance(value, tuple):
        # A repeated parameter is ambiguous: which one libpq honours is not a policy input.
        raise DatabaseTlsPolicyError(f"database URL repeats the {key!r} parameter")
    return str(value)


def validate_database_tls(url: str, *, environ: Mapping[str, str] | None = None) -> None:
    """Refuse a connection URL that would not be verified TLS. Raises on any violation."""
    env = os.environ if environ is None else environ
    try:
        parsed = make_url(url)
    except (ArgumentError, ValueError) as exc:
        raise DatabaseTlsPolicyError("database URL is malformed") from exc
    if parsed.get_backend_name() != "postgresql":
        raise DatabaseTlsPolicyError("production requires a PostgreSQL database URL")

    query = parsed.query
    host = _single(query, "host") or parsed.host
    if not host:
        raise DatabaseTlsPolicyError(
            "production database URL names no TCP host; a unix socket cannot carry TLS"
        )
    if host.startswith("/") or "," in host:
        raise DatabaseTlsPolicyError(
            "production database URL must name exactly one TCP host (no socket path, "
            "no host list whose members could negotiate differently)"
        )

    sslmode = (_single(query, "sslmode") or env.get("PGSSLMODE") or LIBPQ_DEFAULT_SSLMODE).strip()
    if sslmode != REQUIRED_SSLMODE:
        raise DatabaseTlsPolicyError(
            f"production requires sslmode={REQUIRED_SSLMODE}; the effective mode is "
            f"{sslmode!r}, which does not verify the server's identity"
        )

    rootcert = (_single(query, "sslrootcert") or env.get("PGSSLROOTCERT") or "").strip()
    if not rootcert:
        raise DatabaseTlsPolicyError(
            "production requires sslrootcert: the CA bundle the server certificate is "
            f"verified against (a mounted file, or {SYSTEM_TRUST_STORE!r})"
        )
    if rootcert != SYSTEM_TRUST_STORE and not Path(rootcert).is_file():
        raise DatabaseTlsPolicyError(
            "sslrootcert does not name a readable file; the database CA must be mounted "
            "before the process starts"
        )


def enforce_database_tls_policy(url: str) -> None:
    """Apply :func:`validate_database_tls` when, and only when, the deployment is production."""
    if is_production_deployment():
        validate_database_tls(url)


__all__ = [
    "LIBPQ_DEFAULT_SSLMODE",
    "REQUIRED_SSLMODE",
    "SYSTEM_TRUST_STORE",
    "DatabaseTlsPolicyError",
    "enforce_database_tls_policy",
    "validate_database_tls",
]
