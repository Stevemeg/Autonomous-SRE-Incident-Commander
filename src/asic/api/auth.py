"""Bearer-token authentication and database-backed, environment-scoped authorization.

Authentication (who is this, for which tenant) is delegated to a :class:`TokenVerifier`
(:mod:`asic.api.tokens`). Authorization is never read from the token: every request reloads
the caller's grants from the database, so revocation applies to the very next request.
Phase 13 (ADR-0030) made the verifier explicit: production composes the OIDC/JWKS verifier
and can never fall back to the development shared-secret verifier.
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

import sqlalchemy as sa
from fastapi import Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy.orm import Session, sessionmaker

from asic.api.rate_limit import RateLimiter
from asic.api.tokens import (
    DEFAULT_ALGORITHMS,
    AuthMode,
    Hs256DevelopmentVerifier,
    JwksClient,
    OidcJwksVerifier,
    TokenRejected,
    TokenVerifier,
)
from asic.db.models import Permission, RolePermission, User, UserRoleAssignment
from asic.db.session import apply_statement_timeouts, bind_tenant
from asic.domain.enums import UserStatus
from asic.integrations.credentials import is_production_deployment
from asic.observability.logging import log_event

_security_log = logging.getLogger("asic.security")


@dataclass(frozen=True, slots=True)
class ApiSettings:
    #: Development/test signing secret. Ignored (and never required) in OIDC mode.
    jwt_secret: str = ""
    jwt_issuer: str = "asic-idp"
    jwt_audience: str = "asic-api"
    rate_limit_per_minute: int = 120
    #: Serve this process's Prometheus exposition at ``/metrics``. Off unless enabled: the
    #: endpoint is unauthenticated and belongs on an internal scrape network. Metric labels
    #: carry no tenant or incident identifiers (``asic.observability.catalogue``).
    metrics_enabled: bool = False
    #: How bearer tokens are verified. The development verifier is a shared secret and is
    #: refused by :func:`build_token_verifier` in a production deployment.
    auth_mode: AuthMode = AuthMode.DEVELOPMENT_HS256
    oidc_jwks_url: str | None = None
    oidc_algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS
    #: Permit plain HTTP to a loopback JWKS server. For local test servers only; refused
    #: by :func:`build_token_verifier` in a production deployment.
    oidc_allow_loopback_http: bool = False

    @classmethod
    def from_environment(cls) -> ApiSettings:
        production = is_production_deployment()
        raw_mode = os.environ.get("ASIC_AUTH_MODE", "").strip().lower()
        if not raw_mode:
            raw_mode = AuthMode.OIDC_JWKS.value if production else AuthMode.DEVELOPMENT_HS256.value
        try:
            mode = AuthMode(raw_mode)
        except ValueError:
            raise RuntimeError(
                "ASIC_AUTH_MODE must be 'oidc_jwks' or 'development_hs256'"
            ) from None
        metrics = os.environ.get("ASIC_METRICS_ENABLED", "").strip().lower() in (
            "1",
            "true",
            "yes",
        )
        if mode is AuthMode.OIDC_JWKS:
            issuer = os.environ.get("ASIC_JWT_ISSUER", "").strip()
            audience = os.environ.get("ASIC_JWT_AUDIENCE", "").strip()
            url = os.environ.get("ASIC_OIDC_JWKS_URL", "").strip()
            if not (issuer and audience and url):
                raise RuntimeError(
                    "OIDC mode requires ASIC_JWT_ISSUER, ASIC_JWT_AUDIENCE and ASIC_OIDC_JWKS_URL"
                )
            algorithms = tuple(
                a.strip()
                for a in os.environ.get("ASIC_OIDC_ALGORITHMS", "").split(",")
                if a.strip()
            )
            return cls(
                jwt_issuer=issuer,
                jwt_audience=audience,
                metrics_enabled=metrics,
                auth_mode=mode,
                oidc_jwks_url=url,
                oidc_algorithms=algorithms or DEFAULT_ALGORITHMS,
            )
        secret = os.environ.get("ASIC_JWT_SECRET")
        if not secret or len(secret) < 32:
            raise RuntimeError("ASIC_JWT_SECRET must contain at least 32 characters")
        return cls(
            jwt_secret=secret,
            jwt_issuer=os.environ.get("ASIC_JWT_ISSUER", "asic-idp"),
            jwt_audience=os.environ.get("ASIC_JWT_AUDIENCE", "asic-api"),
            metrics_enabled=metrics,
        )


def build_token_verifier(settings: ApiSettings) -> TokenVerifier:
    """Compose the verifier for these settings, refusing an unsafe production composition.

    A production deployment (``ASIC_DEPLOYMENT_ENVIRONMENT=production``) can only run the
    OIDC/JWKS verifier over HTTPS. There is no fallback: a misconfiguration is a startup
    failure, never a quiet downgrade to a shared secret.
    """
    production = is_production_deployment()
    if settings.auth_mode is AuthMode.DEVELOPMENT_HS256:
        if production:
            raise RuntimeError("development JWT authentication cannot run in production")
        return Hs256DevelopmentVerifier(
            secret=settings.jwt_secret, issuer=settings.jwt_issuer, audience=settings.jwt_audience
        )
    if not settings.oidc_jwks_url:
        raise RuntimeError("OIDC mode requires a JWKS URL")
    if production and settings.oidc_allow_loopback_http:
        raise RuntimeError("plain-HTTP JWKS is not permitted in production")
    return OidcJwksVerifier(
        keys=JwksClient(
            settings.oidc_jwks_url,
            allow_loopback_http=settings.oidc_allow_loopback_http,
            allowed_algorithms=settings.oidc_algorithms,
        ),
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        algorithms=settings.oidc_algorithms,
    )


class Claims(BaseModel):
    # Identity providers commonly add informational claims. They are accepted as data and
    # never become authority; grants are always reloaded from the database below.
    model_config = ConfigDict(extra="ignore")
    sub: str = Field(min_length=1, max_length=255)
    tenant_id: uuid.UUID
    iss: str
    aud: str | list[str]
    exp: int
    nbf: int | None = None
    iat: int | None = None
    connector_id: str | None = Field(default=None, min_length=1, max_length=255)
    source: str | None = Field(default=None, min_length=1, max_length=64)
    service_id: uuid.UUID | None = None
    environment_id: uuid.UUID | None = None


@dataclass(frozen=True, slots=True)
class Grant:
    permission: str
    environment_id: uuid.UUID | None


@dataclass(frozen=True, slots=True)
class Principal:
    tenant_id: uuid.UUID
    user_id: uuid.UUID
    subject: str
    grants: tuple[Grant, ...]
    connector_id: str | None = None
    source: str | None = None
    service_id: uuid.UUID | None = None
    environment_id: uuid.UUID | None = None

    def allows_environment(self, permission: str, environment_id: uuid.UUID) -> bool:
        return any(
            grant.permission == permission and grant.environment_id in (None, environment_id)
            for grant in self.grants
        )

    def allows_tenant_wide(self, permission: str) -> bool:
        return any(
            grant.permission == permission and grant.environment_id is None for grant in self.grants
        )

    def allows_any_environment(self, permission: str) -> bool:
        return any(grant.permission == permission for grant in self.grants)

    def visible_environments(self, permission: str) -> frozenset[uuid.UUID] | None:
        matching = [grant.environment_id for grant in self.grants if grant.permission == permission]
        if None in matching:
            return None
        return frozenset(item for item in matching if item is not None)


def _unauthorized(code: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": code, "message": "authentication failed"},
        headers={"WWW-Authenticate": "Bearer"},
    )


def _rejected(reason: str) -> HTTPException:
    # The reason is a closed code for operators; the response never says why (an oracle).
    log_event(_security_log, "auth.rejected", level=logging.INFO, reason=reason)
    return _unauthorized("invalid_token")


def decode_claims(token: str, verifier: TokenVerifier) -> Claims:
    """Verify a bearer token and parse its claims. Raises 401 with a closed reason code."""
    try:
        return Claims.model_validate(verifier.verify(token))
    except TokenRejected as exc:
        raise _rejected(exc.reason.value) from None
    except (ValidationError, ValueError):
        raise _rejected("claims_invalid") from None


def authenticate(factory: sessionmaker[Session], claims: Claims) -> Principal:
    now = datetime.now(UTC)
    with factory() as session:
        bind_tenant(session, claims.tenant_id)
        apply_statement_timeouts(session)
        user = session.scalar(
            sa.select(User).where(
                User.tenant_id == claims.tenant_id,
                User.external_idp_subject == claims.sub,
                User.status == UserStatus.ACTIVE,
            )
        )
        if user is None:
            raise _unauthorized("unknown_principal")
        rows = session.execute(
            sa.select(Permission.key, UserRoleAssignment.environment_id)
            .select_from(UserRoleAssignment)
            .join(RolePermission, RolePermission.role_id == UserRoleAssignment.role_id)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(
                UserRoleAssignment.tenant_id == claims.tenant_id,
                UserRoleAssignment.user_id == user.id,
                sa.or_(
                    UserRoleAssignment.expires_at.is_(None),
                    UserRoleAssignment.expires_at > now,
                ),
            )
        )
        grants = tuple(Grant(key, environment_id) for key, environment_id in rows)
        principal = Principal(
            claims.tenant_id,
            user.id,
            claims.sub,
            grants,
            claims.connector_id,
            claims.source,
            claims.service_id,
            claims.environment_id,
        )
        session.commit()
        return principal


def _too_many() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail={"code": "rate_limited", "message": "request rate exceeded"},
        headers={"Retry-After": "60"},
    )


def principal_dependency(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> Principal:
    client = request.client.host if request.client else "unknown"
    failures: RateLimiter = request.app.state.auth_failure_limiter
    # Unauthenticated abuse is bounded per peer address. Only *failures* are counted, so a
    # legitimate caller is never throttled by its own successful traffic.
    if not authorization or not authorization.startswith("Bearer "):
        if not failures.admit(client):
            raise _too_many()
        raise _unauthorized("missing_token")
    verifier: TokenVerifier = request.app.state.token_verifier
    factory: sessionmaker[Session] = request.app.state.session_factory
    try:
        claims = decode_claims(authorization[7:], verifier)
    except HTTPException:
        if not failures.admit(client):
            raise _too_many() from None
        raise
    # The key is verified-signature material (tenant + subject): an attacker cannot mint new
    # keys, so cardinality is bounded by the identity provider's users. It is limited
    # *before* the database lookup so an over-limit caller costs no query.
    limiter: RateLimiter = request.app.state.rate_limiter
    if not limiter.admit(f"{claims.tenant_id}:{claims.sub}"):
        raise _too_many()
    return authenticate(factory, claims)


CurrentPrincipal = Annotated[Principal, Depends(principal_dependency)]


class PermissionDenied(HTTPException):
    """A 403 that remembers who was denied which permission, so it can be audited.

    The response body is the fixed ``forbidden`` shape and never names the permission or the
    reason: an oracle for which permissions exist or which environment a resource is in.
    """

    def __init__(self, principal: Principal, permission: str) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "forbidden", "message": "principal lacks required authority"},
        )
        self.principal = principal
        self.permission = permission


def require_environment(principal: Principal, permission: str, environment_id: uuid.UUID) -> None:
    if not principal.allows_environment(permission, environment_id):
        raise PermissionDenied(principal, permission)


def require_tenant_wide(principal: Principal, permission: str) -> None:
    if not principal.allows_tenant_wide(permission):
        raise PermissionDenied(principal, permission)


def require_any_environment(principal: Principal, permission: str) -> None:
    if not principal.allows_any_environment(permission):
        raise PermissionDenied(principal, permission)


__all__ = [
    "ApiSettings",
    "AuthMode",
    "CurrentPrincipal",
    "Grant",
    "PermissionDenied",
    "Principal",
    "authenticate",
    "build_token_verifier",
    "decode_claims",
    "require_any_environment",
    "require_environment",
    "require_tenant_wide",
]
