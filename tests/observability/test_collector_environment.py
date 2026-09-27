"""UNIT: the reference collector stamps its environment on every pipeline (Phase 15, F-17).

Application log lines carry service, level and event but not the deployment environment, and
Loki promotes ``deployment.environment.name`` to a stream label. Without a collector-side value,
local, staging and production log streams were indistinguishable. Resolution of the
``${env:...:-unspecified}`` default is checked with ``otelcol-contrib print-config`` in the
validation gate (LOCAL SERVICE); this test pins the structure.
"""

from __future__ import annotations

from pathlib import Path

import yaml

COLLECTOR = (
    Path(__file__).resolve().parents[2] / "configs/observability/otel-collector/collector.yaml"
)


def test_every_pipeline_inserts_the_collector_environment() -> None:
    config = yaml.safe_load(COLLECTOR.read_text("utf-8"))
    processor = config["processors"]["resource/environment"]
    (attribute,) = processor["attributes"]
    assert attribute == {
        "key": "deployment.environment.name",
        "value": "${env:ASIC_DEPLOYMENT_ENVIRONMENT:-unspecified}",
        # insert: a traced process's own (normalised) value is never overwritten
        "action": "insert",
    }
    for name, pipeline in config["service"]["pipelines"].items():
        processors = pipeline["processors"]
        assert "resource/environment" in processors, name
        # memory_limiter first, batch last: the collector's documented ordering
        assert processors[0] == "memory_limiter" and processors[-1] == "batch", name


def test_no_identifier_is_promoted_to_a_resource_attribute() -> None:
    config = yaml.safe_load(COLLECTOR.read_text("utf-8"))
    keys = {
        attribute["key"]
        for name, processor in config["processors"].items()
        if name.startswith("resource")
        for attribute in processor.get("attributes", [])
    }
    assert keys == {"deployment.environment.name"}
