#!/usr/bin/env bash
set -Eeuo pipefail
# Pin the validated tool images, not mutable tags. Run from repository root.
prometheus=prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0
collector=otel/opentelemetry-collector-contrib@sha256:fd328de2552466ad78385e1b1289c3f2402b1c45f265b252aab1955b42845ac1
docker run --rm --entrypoint /bin/promtool -v "$PWD/configs/observability/prometheus:/work:ro" -w /work "$prometheus" check config prometheus.yml
docker run --rm --entrypoint /bin/promtool -v "$PWD/configs/observability/prometheus:/work:ro" -w /work "$prometheus" check rules rules/asic-alerts.rules.yml rules/asic-recording.rules.yml
docker run --rm --entrypoint /bin/promtool -v "$PWD/configs/observability/prometheus:/work:ro" -w /work "$prometheus" test rules tests/asic-alerts.test.yml
docker run --rm -v "$PWD/configs/observability/otel-collector:/work:ro" "$collector" validate --config=/work/collector.yaml
