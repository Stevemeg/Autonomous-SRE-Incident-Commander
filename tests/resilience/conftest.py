"""Shared fixtures for the Phase 15 resilience suites.

These suites run the real application (ASGI app, SQLAlchemy engine, PostgreSQL under the
unprivileged application role) and inject faults at the network or provider seam. Nothing
here mocks away the system under test: the fault proxy is a real TCP hop and the providers
are the real simulator/broker stack with a failing transport or model.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass

import pytest
from sqlalchemy import Engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from asic.db.session import create_app_engine
from tests.api.test_auth import SETTINGS as _API_SETTINGS
from tests.api.test_auth import _principal, _token
from tests.integrations.conftest import runtime  # noqa: F401 - shared adapter fixture
from tests.kernel_fixtures import Fixture, build_fixture
from tests.resilience.fault_proxy import FaultProxy

pytestmark = pytest.mark.postgres

#: The Phase 9 test settings with the per-principal limiter out of the way: these suites
#: measure database behaviour, and the limiter is exercised by its own campaign.
SETTINGS = dataclasses.replace(_API_SETTINGS, rate_limit_per_minute=1_000_000)


@pytest.fixture
def app_url(_ensure_test_app_role: str) -> str:
    return _ensure_test_app_role


@pytest.fixture
def db_proxy(app_url: str) -> Iterator[FaultProxy]:
    url = make_url(app_url)
    with FaultProxy(url.host or "127.0.0.1", url.port or 5432) as proxy:
        yield proxy


def proxied_url(app_url: str, proxy: FaultProxy) -> str:
    return (
        make_url(app_url)
        .set(host="127.0.0.1", port=proxy.port)
        .render_as_string(hide_password=False)
    )


@pytest.fixture
def proxied_engine(app_url: str, db_proxy: FaultProxy) -> Iterator[Engine]:
    """The application's own engine factory (deadlines, pre-ping), through the proxy."""
    engine = create_app_engine(proxied_url(app_url, db_proxy), pool_size=4, max_overflow=0)
    yield engine
    engine.dispose()


@dataclass
class ApiWorld:
    fixture: Fixture
    other: Fixture
    headers: dict[str, str]
    other_headers: dict[str, str]


@pytest.fixture
def api_world(owner_engine: Engine) -> ApiWorld:
    """Two tenants, each with a responder, committed so a separate engine can see them."""
    with Session(bind=owner_engine, expire_on_commit=False, autoflush=False) as session:
        first = build_fixture(session, slug=f"res-a-{uuid.uuid4().hex[:8]}")
        second = build_fixture(session, slug=f"res-b-{uuid.uuid4().hex[:8]}")
        session.commit()
        subject_a, subject_b = f"resp-a-{uuid.uuid4().hex[:6]}", f"resp-b-{uuid.uuid4().hex[:6]}"
        _principal(session, first, "responder", subject_a)
        _principal(session, second, "responder", subject_b)
    return ApiWorld(
        first,
        second,
        {"Authorization": f"Bearer {_token(first.tenant_id, subject_a)}"},
        {"Authorization": f"Bearer {_token(second.tenant_id, subject_b)}"},
    )


def factory_for(engine: Engine) -> Callable[[], Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


__all__ = ["SETTINGS", "ApiWorld", "factory_for", "proxied_url"]
