"""Connector credential resolution at the execution boundary.

A connector row stores a credential *reference* (``asic/read/prometheus``). The secret is
resolved only inside the adapter, immediately before the request that needs it, and only
ever held as a :class:`SecretValue` - a wrapper whose ``repr``, ``str`` and pickled form
never contain the secret. That is the mechanism behind "secrets never enter prompts,
execution arguments, traces, logs or API responses": the value that flows through those
paths is a reference or a redacted wrapper, never the secret itself.

Production resolution fails closed. :class:`EnvironmentCredentialProvider` raises
:class:`~asic.domain.errors.CredentialUnavailable` for a missing secret, and there is no
fallback to a test credential: :class:`StaticCredentialProvider` refuses to exist in a
deployment marked production, and live composition refuses any provider that declares
itself test infrastructure.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Final, NoReturn, Protocol, runtime_checkable

from asic.domain.errors import CredentialUnavailable
from asic.domain.safety import NeverRender

#: The only accepted shape of a reference. Mirrors the database check constraint.
CREDENTIAL_REF_PATTERN: Final[re.Pattern[str]] = re.compile(r"asic/[a-z0-9][a-z0-9/_.-]{0,200}")

#: Environment variable naming a directory of mounted secret files (e.g. a Kubernetes
#: secret volume). Checked before per-reference environment variables.
SECRETS_DIR_ENV: Final[str] = "ASIC_SECRETS_DIR"

DEPLOYMENT_ENV_VAR: Final[str] = "ASIC_DEPLOYMENT_ENVIRONMENT"
_PRODUCTION: Final[frozenset[str]] = frozenset({"production", "prod"})


def is_production_deployment() -> bool:
    return os.environ.get(DEPLOYMENT_ENV_VAR, "").strip().lower() in _PRODUCTION


def validate_reference(reference: str) -> str:
    if not isinstance(reference, str) or not CREDENTIAL_REF_PATTERN.fullmatch(reference):
        raise CredentialUnavailable("credential reference is malformed")
    if ".." in reference.split("/"):
        raise CredentialUnavailable("credential reference is malformed")
    return reference


class SecretValue(NeverRender):
    """A resolved secret that refuses to be printed, logged, compared or serialised."""

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        if not value:
            raise CredentialUnavailable("credential resolved to an empty value")
        self.__value = value

    def reveal(self) -> str:
        """Return the secret. Call only where the value enters an outbound request."""
        return self.__value

    def __repr__(self) -> str:
        return "SecretValue([redacted])"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:  # pragma: no cover - deliberately unusable
        return NotImplemented

    __hash__ = None  # type: ignore[assignment]

    def __reduce__(self) -> NoReturn:
        raise TypeError("a SecretValue cannot be serialised")


@runtime_checkable
class CredentialProvider(Protocol):
    """Resolves a credential reference into a secret, or fails closed."""

    @property
    def is_test_infrastructure(self) -> bool:
        """True for explicit test/local providers. Live composition refuses these."""

    def resolve(self, reference: str) -> SecretValue:
        """Raises :class:`CredentialUnavailable`; never returns a placeholder."""


class EnvironmentCredentialProvider:
    """Production resolution from mounted secret files or environment variables.

    ``asic/read/prometheus`` resolves from ``$ASIC_SECRETS_DIR/asic/read/prometheus`` when
    that directory is configured, otherwise from ``ASIC_SECRET_ASIC_READ_PROMETHEUS``.
    Resolution happens per call, so rotation takes effect without a restart.
    """

    __slots__ = ("_environ",)

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._environ = environ if environ is not None else os.environ

    @property
    def is_test_infrastructure(self) -> bool:
        return False

    def resolve(self, reference: str) -> SecretValue:
        validate_reference(reference)
        directory = self._environ.get(SECRETS_DIR_ENV)
        if directory:
            root = Path(directory).resolve()
            candidate = (root / reference).resolve()
            if root not in candidate.parents:
                raise CredentialUnavailable("credential reference escapes the secrets directory")
            if candidate.is_file():
                value = candidate.read_text(encoding="utf-8").strip()
                return SecretValue(value)
        variable = "ASIC_SECRET_" + re.sub(r"[^A-Z0-9]", "_", reference.upper())
        value = self._environ.get(variable, "").strip()
        if not value:
            # The reference is safe to name; the secret is not in the message.
            raise CredentialUnavailable(f"credential {reference!r} is not configured")
        return SecretValue(value)


class StaticCredentialProvider:
    """Explicit test infrastructure: a fixed mapping of references to fake secrets.

    Refuses construction in a production deployment, and declares itself test
    infrastructure so live composition refuses it everywhere else too.
    """

    __slots__ = ("_secrets",)

    def __init__(self, secrets: Mapping[str, str]) -> None:
        if is_production_deployment():
            raise CredentialUnavailable(
                "a static test credential provider cannot run in a production deployment"
            )
        self._secrets = {validate_reference(k): v for k, v in secrets.items()}

    @property
    def is_test_infrastructure(self) -> bool:
        return True

    def resolve(self, reference: str) -> SecretValue:
        validate_reference(reference)
        if reference not in self._secrets:
            raise CredentialUnavailable(f"credential {reference!r} is not configured")
        return SecretValue(self._secrets[reference])


__all__ = [
    "CREDENTIAL_REF_PATTERN",
    "SECRETS_DIR_ENV",
    "CredentialProvider",
    "EnvironmentCredentialProvider",
    "SecretValue",
    "StaticCredentialProvider",
    "is_production_deployment",
    "validate_reference",
]
