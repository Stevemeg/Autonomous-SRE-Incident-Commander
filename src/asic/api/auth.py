"""JWT authentication and database-backed, environment-scoped authorization."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any

import jwt
import sqlalchemy as sa
from fastapi import Depends, Header, HTTPException, Request, status
from jwt import InvalidTokenError
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy.orm import Session, sessionmaker

from asic.api.rate_limit import RateLimiter
from asic.db.models import Permission, RolePermission, User, UserRoleAssignment
from asic.db.session import apply_statement_timeouts, bind_tenant
from asic.domain.enums import UserStatus


@dataclass(frozen=True, slots=True)
class ApiSettings:
    jwt_secret: str
    jwt_issuer: str = "asic-idp"
    jwt_audience: str = "asic-api"
    rate_limit_per_minute: int = 120

    @classmethod
    def from_environment(cls) -> ApiSettings:
        secret = os.environ.get("ASIC_JWT_SECRET")
        if not secret or len(secret) < 32:
            raise RuntimeError("ASIC_JWT_SECRET must contain at least 32 characters")
        return cls(
            jwt_secret=secret,
            jwt_issuer=os.environ.get("ASIC_JWT_ISSUER", "asic-idp"),
            jwt_audience=os.environ.get("ASIC_JWT_AUDIENCE", "asic-api"),
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

    def allows(self, permission: str, environment_id: uuid.UUID | None = None) -> bool:
        return any(
            grant.permission == permission
            and (environment_id is None or grant.environment_id in (None, environment_id))
            for grant in self.grants
        )

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


def decode_claims(token: str, settings: ApiSettings) -> Claims:
    try:
        raw: dict[str, Any] = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=["HS256"],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["sub", "tenant_id", "iss", "aud", "exp"]},
        )
        return Claims.model_validate(raw)
    except (InvalidTokenError, ValidationError, ValueError) as exc:
        raise _unauthorized("invalid_token") from exc


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


def principal_dependency(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> Principal:
    if not authorization or not authorization.startswith("Bearer "):
        raise _unauthorized("missing_token")
    settings: ApiSettings = request.app.state.api_settings
    factory: sessionmaker[Session] = request.app.state.session_factory
    principal = authenticate(factory, decode_claims(authorization[7:], settings))
    limiter: RateLimiter = request.app.state.rate_limiter
    if not limiter.admit(f"{principal.tenant_id}:{principal.user_id}"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"code": "rate_limited", "message": "request rate exceeded"},
            headers={"Retry-After": "60"},
        )
    return principal


CurrentPrincipal = Annotated[Principal, Depends(principal_dependency)]


def require(principal: Principal, permission: str, environment_id: uuid.UUID | None = None) -> None:
    if not principal.allows(permission, environment_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "forbidden", "message": "principal lacks required authority"},
        )


__all__ = ["ApiSettings", "CurrentPrincipal", "Grant", "Principal", "authenticate", "require"]
