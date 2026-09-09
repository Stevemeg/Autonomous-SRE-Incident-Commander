"""Tool descriptors: the typed shape of every capability the system can exercise.

This is the in-process form of a ``tool_definition`` row. The database owns the catalogue
and the risk tier; this module owns validation, and it enforces two structural properties
that master specification sections 6 and 7 require.

**There is no free-form command argument type.** An argument is one of a small closed set
of kinds - a bounded string with a pattern, a number in a range, a member of an enumeration
- and every descriptor's field names are checked against
:data:`asic.domain.safety.FORBIDDEN_EXECUTION_FIELDS`. A ``command``, ``script``,
``manifest`` or ``raw_query`` argument cannot be declared, so no code path exists that
could carry one.

**Scope arguments are resolved, never supplied.** An argument marked
:attr:`ArgumentSpec.scope_resolved` is filled by the broker from the incident's tenant,
environment and service ownership. Supplying one is a rejected request, not a merge. This
is what stops a caller - a model included - from widening its own reach by naming a
different namespace, cluster or tenant.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import StrEnum, unique
from typing import Any, Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from asic.domain.enums import RiskTier, ToolProviderKind
from asic.domain.errors import SchemaViolation
from asic.domain.safety import check_field_names


@unique
class ArgumentKind(StrEnum):
    """The complete set of argument shapes a tool may declare.

    Closed on purpose. Adding a kind is a deliberate act reviewed alongside the safety
    guarantees, rather than something that happens by writing a new tool.
    """

    BOUNDED_STRING = "bounded_string"
    ENUM = "enum"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    TIMESTAMP = "timestamp"
    DURATION_SECONDS = "duration_seconds"
    UUID = "uuid"
    STRING_LIST = "string_list"


#: Default ceiling for a bounded string. Generous enough for a service or namespace name,
#: far too small to smuggle a script.
DEFAULT_STRING_MAX_LENGTH: Final[int] = 253


class ArgumentSpec(BaseModel):
    """One typed argument of one tool."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    kind: ArgumentKind
    description: str
    required: bool = True
    #: Filled by the broker from resolved incident scope. A caller supplying it is
    #: rejected outright.
    scope_resolved: bool = False
    pattern: str | None = None
    max_length: int = DEFAULT_STRING_MAX_LENGTH
    allowed_values: tuple[str, ...] = ()
    min_value: float | None = None
    max_value: float | None = None
    max_items: int = 32

    @field_validator("name")
    @classmethod
    def _name_is_safe(cls, value: str) -> str:
        offenders = check_field_names([value])
        if offenders:
            raise ValueError(
                f"argument {value!r} is forbidden: {offenders[0]}. Tools expose typed "
                "operations; there is no argument type capable of carrying a command."
            )
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value):
            raise ValueError(f"argument name {value!r} must be lower_snake_case")
        return value

    @model_validator(mode="after")
    def _kind_constraints_are_coherent(self) -> ArgumentSpec:
        if self.kind is ArgumentKind.ENUM and not self.allowed_values:
            raise ValueError(f"enum argument {self.name!r} declares no allowed values")
        if self.kind is not ArgumentKind.ENUM and self.allowed_values:
            raise ValueError(f"argument {self.name!r} declares allowed values but is not an enum")
        if self.kind is ArgumentKind.BOUNDED_STRING and self.max_length > 1024:
            raise ValueError(
                f"argument {self.name!r} allows {self.max_length} characters; a bounded "
                "string long enough to hold a script is not bounded"
            )
        if self.pattern is not None:
            re.compile(self.pattern)
        return self

    def coerce(self, value: object) -> Any:
        """Validate and normalise one supplied value.

        Raises:
            SchemaViolation: with a message naming the argument and the rule it broke.
        """
        try:
            return self._coerce(value)
        except SchemaViolation:
            raise
        except (TypeError, ValueError) as exc:
            raise SchemaViolation(f"argument {self.name!r}: {exc}") from exc

    def _coerce(self, value: object) -> Any:
        kind = self.kind
        if kind in (ArgumentKind.BOUNDED_STRING, ArgumentKind.ENUM):
            if not isinstance(value, str):
                raise SchemaViolation(f"argument {self.name!r} must be a string")
            if len(value) > self.max_length:
                raise SchemaViolation(
                    f"argument {self.name!r} is {len(value)} characters, over the declared "
                    f"maximum of {self.max_length}"
                )
            if kind is ArgumentKind.ENUM and value not in self.allowed_values:
                raise SchemaViolation(
                    f"argument {self.name!r} must be one of {list(self.allowed_values)}, "
                    f"got {value!r}"
                )
            if self.pattern is not None and not re.fullmatch(self.pattern, value):
                raise SchemaViolation(
                    f"argument {self.name!r} does not match the declared pattern {self.pattern!r}"
                )
            return value
        if kind is ArgumentKind.BOOLEAN:
            if not isinstance(value, bool):
                raise SchemaViolation(f"argument {self.name!r} must be a boolean")
            return value
        if kind in (ArgumentKind.INTEGER, ArgumentKind.DURATION_SECONDS):
            if isinstance(value, bool) or not isinstance(value, int):
                raise SchemaViolation(f"argument {self.name!r} must be an integer")
            return self._check_range(value)
        if kind is ArgumentKind.NUMBER:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise SchemaViolation(f"argument {self.name!r} must be a number")
            return self._check_range(float(value))
        if kind is ArgumentKind.TIMESTAMP:
            parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
            if parsed.tzinfo is None:
                raise SchemaViolation(
                    f"argument {self.name!r} must be timezone-aware; a naive timestamp "
                    "means a different window in every process"
                )
            return parsed
        if kind is ArgumentKind.UUID:
            return value if isinstance(value, UUID) else UUID(str(value))
        if not isinstance(value, (list, tuple)):
            raise SchemaViolation(f"argument {self.name!r} must be a list of strings")
        items = list(value)
        if len(items) > self.max_items:
            raise SchemaViolation(
                f"argument {self.name!r} has {len(items)} items, over the declared "
                f"maximum of {self.max_items}"
            )
        for item in items:
            if not isinstance(item, str) or len(item) > self.max_length:
                raise SchemaViolation(f"argument {self.name!r} contains an invalid entry")
        return items

    def _check_range(self, value: float) -> float | int:
        if self.min_value is not None and value < self.min_value:
            raise SchemaViolation(f"argument {self.name!r} is below the minimum {self.min_value}")
        if self.max_value is not None and value > self.max_value:
            raise SchemaViolation(f"argument {self.name!r} is above the maximum {self.max_value}")
        return value

    def to_json_schema(self) -> dict[str, Any]:
        """The form persisted in ``tool_definition.input_schema``."""
        payload: dict[str, Any] = {
            "kind": self.kind.value,
            "description": self.description,
            "required": self.required,
            "scope_resolved": self.scope_resolved,
        }
        if self.pattern:
            payload["pattern"] = self.pattern
        if self.allowed_values:
            payload["allowed_values"] = list(self.allowed_values)
        if self.min_value is not None:
            payload["min_value"] = self.min_value
        if self.max_value is not None:
            payload["max_value"] = self.max_value
        if self.kind in (ArgumentKind.BOUNDED_STRING, ArgumentKind.ENUM, ArgumentKind.STRING_LIST):
            payload["max_length"] = self.max_length
        return payload


class ResultField(BaseModel):
    """One required field of a tool's result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    kind: ArgumentKind
    required: bool = True


class ToolDescriptor(BaseModel):
    """A registered capability, with everything section 7 requires it to declare."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    version: str
    capability: str
    description: str
    risk_tier: RiskTier
    provider_kind: ToolProviderKind

    arguments: tuple[ArgumentSpec, ...]
    result_fields: tuple[ResultField, ...]

    timeout_seconds: int = Field(ge=1, le=3600)
    settling_seconds: int = Field(default=0, ge=0)
    is_idempotent: bool = True
    #: Argument names composing the idempotency key for this tool's effect.
    idempotency_key_fields: tuple[str, ...] = ()
    max_attempts: int = Field(default=1, ge=1, le=5)
    retry_backoff_seconds: float = Field(default=0.0, ge=0.0)
    preconditions: tuple[str, ...] = ()
    rollback_tool_name: str | None = None
    #: Audit event types this tool's invocation must produce.
    audit_events: tuple[str, ...] = ()
    #: Result size ceiling. An unbounded result is a budget and a prompt-size problem.
    max_result_items: int = Field(default=200, ge=1)
    is_enabled: bool = True

    @field_validator("name", "capability")
    @classmethod
    def _dotted_lowercase(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+", value):
            raise ValueError(f"{value!r} must be dotted lower_snake_case, e.g. 'read.metrics'")
        return value

    @field_validator("version")
    @classmethod
    def _semver(cls, value: str) -> str:
        if not re.fullmatch(r"\d+\.\d+\.\d+", value):
            raise ValueError(f"version {value!r} must be semver MAJOR.MINOR.PATCH")
        return value

    @model_validator(mode="after")
    def _safety_invariants(self) -> ToolDescriptor:
        # SI-5: a destructive capability is not expressible, so it cannot be registered.
        if self.risk_tier is RiskTier.R3:
            raise ValueError(
                f"{self.name} declares risk tier R3; destructive and irreversible actions "
                "are not registered as agent-invocable tools at all (SI-5)"
            )
        if self.risk_tier is RiskTier.RO:
            if self.rollback_tool_name is not None or self.settling_seconds:
                raise ValueError(
                    f"{self.name} is read-only but declares effect metadata; a read tool "
                    "changes nothing, so it has nothing to roll back or settle"
                )
        elif self.rollback_tool_name is None:
            raise ValueError(
                f"{self.name} is a write tool with no declared rollback; the way back is "
                "declared before the action can ever be proposed"
            )
        if not self.is_idempotent and self.max_attempts > 1:
            raise ValueError(
                f"{self.name} is not idempotent but declares retries; repetition would "
                "change the result, so the recovery is reconciliation, not retry"
            )
        names = [a.name for a in self.arguments]
        if len(set(names)) != len(names):
            raise ValueError(f"{self.name} declares a duplicate argument name")
        unknown_key_fields = set(self.idempotency_key_fields) - set(names)
        if unknown_key_fields:
            raise ValueError(
                f"{self.name} composes its idempotency key from undeclared argument(s) "
                f"{sorted(unknown_key_fields)}"
            )
        offenders = check_field_names([f.name for f in self.result_fields])
        if offenders:
            raise ValueError(f"{self.name} declares an unsafe result field: {offenders[0]}")
        return self

    @property
    def major_version(self) -> int:
        return int(self.version.split(".")[0])

    @property
    def scope_argument_names(self) -> frozenset[str]:
        return frozenset(a.name for a in self.arguments if a.scope_resolved)

    def argument(self, name: str) -> ArgumentSpec | None:
        return next((a for a in self.arguments if a.name == name), None)

    def bind_arguments(
        self,
        supplied: Mapping[str, Any],
        resolved_scope: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Produce the final argument set, or reject the request.

        The order matters and is the point of the method:

        1. an unknown argument is rejected, never dropped, because silently ignoring an
           argument means executing something other than what was requested;
        2. a caller-supplied scope argument is rejected, never overwritten, because
           overwriting would hide an attempt to widen scope instead of surfacing it;
        3. scope is then taken from ``resolved_scope`` alone;
        4. everything is type-checked against its declared kind.

        Raises:
            SchemaViolation: on any of the above.
        """
        declared = {a.name: a for a in self.arguments}
        unknown = sorted(set(supplied) - set(declared))
        if unknown:
            raise SchemaViolation(
                f"{self.name} received undeclared argument(s) {unknown}; the tool's "
                "surface is fixed by its descriptor"
            )
        trespass = sorted(set(supplied) & self.scope_argument_names)
        if trespass:
            raise SchemaViolation(
                f"{self.name} received caller-supplied scope argument(s) {trespass}; scope "
                "is resolved from the incident's tenant, environment and service ownership "
                "and can never be widened by a caller"
            )

        bound: dict[str, Any] = {}
        for name, spec in declared.items():
            if spec.scope_resolved:
                if name not in resolved_scope:
                    raise SchemaViolation(
                        f"{self.name} requires resolved scope argument {name!r}, which the "
                        "broker did not supply; refusing rather than guessing"
                    )
                bound[name] = spec.coerce(resolved_scope[name])
                continue
            if name in supplied:
                bound[name] = spec.coerce(supplied[name])
            elif spec.required:
                raise SchemaViolation(f"{self.name} is missing required argument {name!r}")
        return bound

    def validate_result(self, result: object) -> Mapping[str, Any]:
        """Check a tool result against the declared output shape.

        A malformed result is a typed failure. It is never coerced and never replaced with
        a plausible-looking default: fabricated data presented as a tool result is the
        single worst thing this layer could do.

        Result checking is deliberately separate from argument checking. Arguments are
        constrained tightly because they determine what we *ask for*; results carry
        operational content whose length we do not control, so applying the argument
        bounds here would reject a legitimately long log line as malformed.
        """
        if not isinstance(result, Mapping):
            raise SchemaViolation(
                f"{self.name} returned {type(result).__name__}, expected a mapping"
            )
        for field in self.result_fields:
            if field.name not in result:
                if field.required:
                    raise SchemaViolation(
                        f"{self.name} result is missing required field {field.name!r}"
                    )
                continue
            self._check_result_field(field, result[field.name])
        return result

    def _check_result_field(self, field: ResultField, value: object) -> None:
        kind = field.kind
        if kind is ArgumentKind.STRING_LIST:
            if not isinstance(value, (list, tuple)):
                raise SchemaViolation(
                    f"{self.name} result field {field.name!r} must be a list, got "
                    f"{type(value).__name__}"
                )
            if len(value) > self.max_result_items:
                raise SchemaViolation(
                    f"{self.name} returned {len(value)} items in {field.name!r}, over the "
                    f"declared ceiling of {self.max_result_items}; an unbounded result is a "
                    "budget and a prompt-size problem, so it is refused rather than trimmed"
                )
            return
        expected: type | tuple[type, ...]
        if kind is ArgumentKind.BOOLEAN:
            expected = bool
        elif kind in (ArgumentKind.INTEGER, ArgumentKind.DURATION_SECONDS):
            expected = int
        elif kind is ArgumentKind.NUMBER:
            expected = (int, float)
        else:
            expected = str
        if isinstance(value, bool) and expected is not bool:
            raise SchemaViolation(
                f"{self.name} result field {field.name!r} is a boolean, expected {kind.value}"
            )
        if not isinstance(value, expected):
            raise SchemaViolation(
                f"{self.name} result field {field.name!r} is {type(value).__name__}, "
                f"expected {kind.value}"
            )

    def to_input_schema(self) -> dict[str, Any]:
        return {a.name: a.to_json_schema() for a in self.arguments}

    def to_output_schema(self) -> dict[str, Any]:
        return {f.name: {"kind": f.kind.value, "required": f.required} for f in self.result_fields}


def assert_no_write_capability(descriptors: Sequence[ToolDescriptor]) -> None:
    """Assert a catalogue is entirely read-only.

    The read-only orchestration kernel calls this on the catalogue it loads, so a write
    tool arriving in the registry fails at start-up rather than at the moment something
    tries to use it.
    """
    offenders = [d.name for d in descriptors if d.risk_tier is not RiskTier.RO]
    if offenders:
        raise ValueError(
            f"catalogue contains non read-only tool(s) {sorted(offenders)}; the "
            "orchestration kernel is read-only and refuses to load a catalogue that "
            "could mutate anything"
        )


__all__ = [
    "DEFAULT_STRING_MAX_LENGTH",
    "ArgumentKind",
    "ArgumentSpec",
    "ResultField",
    "ToolDescriptor",
    "assert_no_write_capability",
]
