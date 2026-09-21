"""Phase 13 review of every registered capability's authorization semantics.

A mechanical inventory rather than a reading exercise: each rule below is asserted for every
descriptor in every catalogue, so a new tool that is effectful but classed as a read, that has
no scope, or that is created dynamically fails a test instead of relying on review.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from asic.domain.enums import RiskTier, ToolEffectClass
from asic.domain.errors import UnregisteredCapability
from asic.domain.safety import check_field_names
from asic.tools.capability import CapabilityResolver
from asic.tools.catalogue import READ_ONLY_CATALOGUE
from asic.tools.descriptor import ToolDescriptor
from asic.tools.integration_catalogue import INTEGRATION_CATALOGUE
from asic.tools.registry import ToolRegistry
from asic.tools.remediation_catalogue import NODE_SCOPED_CAPABILITIES, WRITE_CATALOGUE

pytestmark = pytest.mark.security

ALL: tuple[ToolDescriptor, ...] = (*READ_ONLY_CATALOGUE, *WRITE_CATALOGUE, *INTEGRATION_CATALOGUE)
IDS = [d.name for d in ALL]
SRC = Path(__file__).resolve().parents[2] / "src" / "asic"


def test_inventory_is_not_empty_and_names_are_unique() -> None:
    assert len(ALL) == 16
    assert len({d.name for d in ALL}) == len(ALL), "duplicate or ambiguous tool name"


def test_capabilities_are_one_to_one_except_the_documented_node_pair() -> None:
    by_capability: dict[str, list[str]] = {}
    for descriptor in ALL:
        by_capability.setdefault(descriptor.capability, []).append(descriptor.name)
    shared = {cap: names for cap, names in by_capability.items() if len(names) > 1}
    # Cordon and uncordon are one capability by design: they are each other's rollback and
    # are authorised identically (F-08). Nothing else may share a capability.
    assert shared == {"mutate.k8s_node": ["k8s.node.cordon", "k8s.node.uncordon"]}
    assert set(shared) == set(NODE_SCOPED_CAPABILITIES)


@pytest.mark.parametrize("descriptor", ALL, ids=IDS)
class TestEveryDescriptor:
    def test_it_declares_an_explicit_capability_namespace(self, descriptor: ToolDescriptor) -> None:
        prefix = descriptor.capability.split(".", 1)[0]
        assert prefix in {"read", "mutate", "write", "notify"}, descriptor.capability

    def test_effect_class_risk_and_capability_namespace_agree(
        self, descriptor: ToolDescriptor
    ) -> None:
        prefix = descriptor.capability.split(".", 1)[0]
        if prefix == "read":
            assert descriptor.effect_class is ToolEffectClass.READ
            assert descriptor.risk_tier is RiskTier.RO
        else:
            # An effectful capability is never classed as a read, and never as RO.
            assert descriptor.effect_class is not ToolEffectClass.READ
            assert descriptor.risk_tier in {RiskTier.R1, RiskTier.R2}
        if prefix == "mutate":
            assert descriptor.effect_class is ToolEffectClass.INFRASTRUCTURE_MUTATION
        if prefix in {"write", "notify"}:
            assert descriptor.effect_class is ToolEffectClass.EXTERNAL_RECORD
        assert descriptor.risk_tier is not RiskTier.R3

    def test_tenant_and_environment_scope_are_resolved_never_supplied(
        self, descriptor: ToolDescriptor
    ) -> None:
        resolved = {a.name for a in descriptor.arguments if a.scope_resolved}
        assert {"tenant_id", "environment"} <= resolved

    def test_no_argument_can_carry_a_command_or_a_secret(self, descriptor: ToolDescriptor) -> None:
        assert check_field_names([a.name for a in descriptor.arguments]) == []

    def test_effectful_capabilities_are_audited_bounded_and_idempotent(
        self, descriptor: ToolDescriptor
    ) -> None:
        if descriptor.effect_class is ToolEffectClass.READ:
            return
        assert descriptor.audit_events, "an effectful tool must declare its audit events"
        assert descriptor.is_idempotent and descriptor.idempotency_key_fields
        assert "tenant_id" in descriptor.idempotency_key_fields
        assert descriptor.max_attempts == 1, "effectful calls are never blindly retried"
        assert descriptor.timeout_seconds <= 300

    def test_mutations_declare_their_rollback_and_preconditions(
        self, descriptor: ToolDescriptor
    ) -> None:
        if descriptor.effect_class is not ToolEffectClass.INFRASTRUCTURE_MUTATION:
            return
        assert descriptor.rollback_tool_name in {d.name for d in ALL}
        assert descriptor.preconditions
        assert descriptor.risk_tier in {RiskTier.R1, RiskTier.R2}


#: The complete, reviewed set of free-text arguments and their length ceilings. Each is
#: bounded, and each is *data*: a search topic and a literal log substring are escaped into
#: typed queries (there is no query language argument), and each ``summary`` is rendered by
#: the adapter as inert display text (control characters removed, destination-escaped). None
#: reaches an authorization decision. A new free-text argument must be added here on purpose.
REVIEWED_FREE_TEXT: dict[str, int] = {
    "knowledge.search.topic": 200,
    "logs.query.contains": 120,
    "grafana.annotation.create.summary": 300,
    "jira.issue.comment.summary": 300,
    "jira.issue.create.summary": 300,
    "pagerduty.event.summary": 300,
    "slack.post.summary": 300,
    "teams.post.summary": 300,
}


def test_free_text_arguments_are_exactly_the_reviewed_bounded_set() -> None:
    found = {
        f"{d.name}.{a.name}": a.max_length
        for d in ALL
        for a in d.arguments
        if not a.scope_resolved
        and a.kind.value == "bounded_string"
        and not (a.pattern or a.allowed_values)
    }
    assert found == REVIEWED_FREE_TEXT


def test_node_capabilities_are_r2_and_service_free_by_design() -> None:
    for descriptor in ALL:
        if descriptor.capability in NODE_SCOPED_CAPABILITIES:
            assert descriptor.risk_tier is RiskTier.R2
            assert "service" not in {a.name for a in descriptor.arguments}


def test_investigation_registry_cannot_see_any_effectful_tool() -> None:
    registry = ToolRegistry.read_only()
    assert {d.effect_class for d in registry.descriptors()} == {ToolEffectClass.READ}
    assert CapabilityResolver(registry).max_risk_tier is RiskTier.RO


def test_a_model_generated_tool_name_cannot_create_a_capability() -> None:
    registry = ToolRegistry.remediation_full()
    for invented in ("kubectl.exec", "shell.run", "k8s.node.drain", "mutate.k8s_secret", ""):
        with pytest.raises(UnregisteredCapability):
            registry.by_name(invented)
    assert not [
        name for name in ("register", "add", "extend", "append") if hasattr(registry, name)
    ], "the registry exposes a mutator"


def test_registries_are_constructed_only_from_the_static_catalogues() -> None:
    """No hidden dynamic capability creation: ``ToolDescriptor(...)`` is only ever called in
    the catalogue modules, and ``ToolRegistry(...)`` only inside the registry itself."""
    catalogue_modules = {"catalogue.py", "remediation_catalogue.py", "integration_catalogue.py"}
    offenders: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name == "ToolDescriptor" and path.name not in catalogue_modules | {"descriptor.py"}:
                offenders.append(f"{path.relative_to(SRC)}: ToolDescriptor(...)")
            if name == "ToolRegistry" and path.name != "registry.py":
                offenders.append(f"{path.relative_to(SRC)}: ToolRegistry(...)")
    assert offenders == [], offenders


def test_no_source_module_bypasses_the_broker_by_invoking_a_provider() -> None:
    """A provider's ``invoke`` is called from the broker only (the single egress point).

    Precise, not textual: a call is an offender only when the receiver of ``.invoke`` is
    named like a provider, in any module other than the broker itself.
    """
    offenders: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "broker.py" and path.parent.name == "tools":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "invoke"
            ):
                receiver = node.func.value
                label = (
                    receiver.id if isinstance(receiver, ast.Name) else getattr(receiver, "attr", "")
                )
                if "provider" in label.lower():
                    offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert offenders == [], offenders
