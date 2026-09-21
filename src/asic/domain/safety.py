"""Structural guards that keep unsafe shapes out of the schema.

Master specification section 6 forbids executing arbitrary model-generated production
commands, and the approved architecture makes that a *structural* property rather than a
rule someone must remember: there is no column, and no tool input field, capable of
carrying a free-form command.

This module names the forbidden shapes so the test suite can assert their absence against
the real schema and against every registered tool definition. It is a guard, not a
sanitiser: the answer to a forbidden field is to reject it, never to clean it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Final, cast

#: Column and tool-input field names that would create an arbitrary-execution channel.
#: Matching is on the whole name, case-insensitively, after normalising separators.
FORBIDDEN_EXECUTION_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "command",
        "commands",
        "cmd",
        "shell",
        "shell_command",
        "script",
        "script_body",
        "bash",
        "sh",
        "exec",
        "execute",
        "eval",
        "kubectl",
        "kubectl_command",
        "raw_command",
        "raw_query",
        "manifest",
        "manifest_yaml",
        "patch_body",
        "raw_patch",
        "sql",
        "raw_sql",
        "code",
        "payload_script",
    }
)

#: Column names that would put secret material in the database. The tool registry stores
#: a *reference* to a secret (``credential_ref``), never the secret itself.
FORBIDDEN_SECRET_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "secret_value",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "token",
        "auth_token",
        "bearer_token",
        "client_secret",
        "credentials",
        "credential",
        "connection_string",
        "dsn",
        "session_cookie",
    }
)

_NORMALISE = re.compile(r"[^a-z0-9]+")


def normalise_field_name(name: str) -> str:
    return _NORMALISE.sub("_", name.strip().lower()).strip("_")


def is_forbidden_execution_field(name: str) -> bool:
    return normalise_field_name(name) in FORBIDDEN_EXECUTION_FIELDS


def is_forbidden_secret_field(name: str) -> bool:
    return normalise_field_name(name) in FORBIDDEN_SECRET_FIELDS


def check_field_names(names: object) -> list[str]:
    """Return the offending names among ``names``, empty when the set is safe.

    Accepts any iterable of strings. Used by schema tests and by tool-definition
    validation so both apply exactly the same rule.
    """
    if isinstance(names, str) or not isinstance(names, Iterable):
        raise TypeError("check_field_names expects an iterable of field names")

    offenders: list[str] = []
    for raw in cast("Iterable[object]", names):
        name = str(raw)
        if is_forbidden_execution_field(name):
            offenders.append(f"{name} (arbitrary-execution channel)")
        elif is_forbidden_secret_field(name):
            offenders.append(f"{name} (secret material in the database)")
    return offenders


#: Columns that legitimately contain the *name* of a credential in the secret manager
#: rather than a credential. Allow-listed so the secret-field guard does not fire on them.
SECRET_REFERENCE_COLUMNS: Final[frozenset[str]] = frozenset(
    {
        "credential_ref",
        "secret_ref",
        "secret_manager_path",
    }
)


def is_secret_reference(name: str) -> bool:
    return normalise_field_name(name) in SECRET_REFERENCE_COLUMNS


class NeverRender:
    """Marker base for values that must not reach a log, span, prompt, audit row or response.

    :class:`asic.integrations.credentials.SecretValue` derives from it. Redaction treats any
    instance as fully redacted *by type*, which does not depend on the value's shape or on
    the name of the field it travelled in - the property name- and pattern-based rules
    cannot give (Phase 13, F-16).
    """

    __slots__ = ()
