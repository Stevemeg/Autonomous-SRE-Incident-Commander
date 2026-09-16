"""Native external-system adapters behind the tool broker (Phase 10, ADR-0026).

Nothing in this package is reachable from a graph node. Adapters are composed into a
:class:`~asic.integrations.provider.NativeIntegrationProvider`, which the broker selects
after authorization, connector-scope resolution and argument binding. Every request an
adapter sends is built from typed, validated arguments and server-side connector
configuration; there is no argument through which a caller can supply a URL, a method, a
header or a query language.
"""
