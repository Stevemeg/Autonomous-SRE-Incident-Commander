"""Kubernetes: typed reads and the four approved remediation operations.

No ``kubectl``, no shell, no caller-supplied resource path, no caller-supplied patch body.
Every request path is composed here from a fixed API group/version and pattern-validated
names; every mutation body is built here from values the API server itself returned (a
prior ReplicaSet's pod template) or from bounded integers.

Scope is enforced twice for **service-scoped** mutations (deployment rollback, HPA
adjustment). The broker only reaches this adapter for a namespace resolved from the
service's registered ownership; and before the mutation the adapter reads the target and
refuses (``scope_denied``, effect not applied) unless it carries the configured service
label with the incident's service as its value. A deployment that merely happens to share a
namespace with the service is not a target.

**Node cordon/uncordon are deliberately not service-scoped** (Phase 13, F-08): a node is
shared infrastructure and has no service label. Their authority is the frozen tenant and
environment, the node identity bound into the approved action hash, tier R2, and a current
human approval on every dispatch (``asic.remediation.authorization``,
``docs/security/AUTHORIZATION.md``). This adapter performs no service check for them.

Reads use the connector's read credential; mutations use its separate write credential.
A read credential is therefore never capable of a write at the API server (SI-4).

Mutations use optimistic concurrency: a rollback is a JSON Patch whose first operation
tests the ``resourceVersion`` read a moment earlier, so a concurrent change fails with a
conflict instead of being overwritten.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Final

from asic.domain.enums import IntegrationFailureClass, IntegrationKind
from asic.domain.errors import IntegrationError
from asic.integrations.base import (
    AdapterRuntime,
    authorization,
    base_headers,
    display_text,
    endpoint_for,
    json_body,
    mapping,
    require_connector,
    resolve_secret,
    send_json,
    sequence,
    setting,
    ssl_context_for,
)
from asic.integrations.transport import HttpMethod, HttpRequest, malformed, path
from asic.tools.provider import ConnectorGrant, InvocationContext

SOURCE: Final[str] = "kubernetes"
REVISION_ANNOTATION: Final[str] = "deployment.kubernetes.io/revision"
REVISION_HISTORY_ANNOTATION: Final[str] = "deployment.kubernetes.io/revision-history"
_LABEL_KEY_PATTERN: Final[str] = (
    r"([a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?/)?[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?"
)
_TOKEN_UNSAFE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9._:/@-]")
MAX_NODES: Final[int] = 100
MAX_EVENTS: Final[int] = 50


def _token(value: object) -> str:
    """A value safe to embed in a space-separated ``key=value`` observation line."""
    return _TOKEN_UNSAFE.sub("_", str(value))[:128] or "-"


def _int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return default


class KubernetesAdapter:
    kind = IntegrationKind.KUBERNETES

    def __init__(self, runtime: AdapterRuntime) -> None:
        self._runtime = runtime

    # ------------------------------------------------------------------ plumbing

    def _request(
        self,
        connector: ConnectorGrant,
        context: InvocationContext,
        *,
        write: bool,
        method: HttpMethod,
        request_path: str,
        query: tuple[tuple[str, str], ...] = (),
        body: bytes | None = None,
        content_type: str | None = None,
        effectful: bool = False,
    ) -> Any:
        reference = connector.write_credential_ref if write else connector.credential_ref
        secret = resolve_secret(self._runtime, reference, purpose="write" if write else "read")
        headers = base_headers(context)
        headers.append(authorization(secret, "bearer"))
        if content_type is not None:
            headers.append(("Content-Type", content_type))
        request = HttpRequest(
            method=method,
            endpoint=endpoint_for(self._runtime, connector),
            path=request_path,
            query=query,
            headers=tuple(headers),
            body=body,
            effectful=effectful,
        )
        return send_json(
            self._runtime,
            request,
            context,
            ssl_context=ssl_context_for(self._runtime, connector),
        )

    @staticmethod
    def _service_label(connector: ConnectorGrant) -> str:
        return setting(
            connector, "service_label", pattern=_LABEL_KEY_PATTERN, default="app.kubernetes.io/name"
        )

    def _items(self, payload: Any, what: str) -> list[Mapping[str, Any]]:
        return [mapping(item, what) for item in sequence(mapping(payload, what).get("items"), what)]

    def _replica_sets(
        self,
        connector: ConnectorGrant,
        context: InvocationContext,
        namespace: str,
        service: str,
        *,
        write: bool,
    ) -> list[Mapping[str, Any]]:
        return self._items(
            self._request(
                connector,
                context,
                write=write,
                method="GET",
                request_path=path("apis", "apps", "v1", "namespaces", namespace, "replicasets"),
                query=(
                    ("labelSelector", f"{self._service_label(connector)}={service}"),
                    ("limit", "100"),
                ),
            ),
            "replicaset list",
        )

    def _require_service_label(
        self, connector: ConnectorGrant, resource: Mapping[str, Any], service: str, what: str
    ) -> None:
        labels = mapping(mapping(resource.get("metadata"), what).get("labels") or {}, what)
        if labels.get(self._service_label(connector)) != service:
            raise IntegrationError(
                f"{what} does not carry the incident service label; refusing to mutate it",
                failure_class=IntegrationFailureClass.SCOPE_DENIED,
                effect_not_applied=True,
            )

    # --------------------------------------------------------------------- reads

    def workload_read(
        self, arguments: Mapping[str, Any], context: InvocationContext
    ) -> Mapping[str, Any]:
        connector = require_connector(context, self.kind)
        namespace = str(arguments["namespace"])
        service = str(arguments["service"])
        selector = f"{self._service_label(connector)}={service}"
        deployments = self._items(
            self._request(
                connector,
                context,
                write=False,
                method="GET",
                request_path=path("apis", "apps", "v1", "namespaces", namespace, "deployments"),
                query=(("labelSelector", selector), ("limit", "20")),
            ),
            "deployment list",
        )
        replica_sets = self._replica_sets(connector, context, namespace, service, write=False)
        workloads: list[str] = []
        for deployment in deployments:
            workloads.append(self._deployment_line(deployment, replica_sets))
        hpas = self._items(
            self._request(
                connector,
                context,
                write=False,
                method="GET",
                request_path=path(
                    "apis", "autoscaling", "v2", "namespaces", namespace, "horizontalpodautoscalers"
                ),
                query=(("labelSelector", selector), ("limit", "20")),
            ),
            "hpa list",
        )
        for hpa in hpas:
            meta = mapping(hpa.get("metadata"), "hpa metadata")
            spec = mapping(hpa.get("spec"), "hpa spec")
            status = mapping(hpa.get("status") or {}, "hpa status")
            workloads.append(
                f"HorizontalPodAutoscaler/{_token(meta.get('name'))} "
                f"current={_int(status.get('currentReplicas'))} "
                f"min={_int(spec.get('minReplicas'), 1)} max={_int(spec.get('maxReplicas'))}"
            )
        nodes = self._items(
            self._request(
                connector,
                context,
                write=False,
                method="GET",
                request_path=path("api", "v1", "nodes"),
                query=(("limit", str(MAX_NODES)),),
            ),
            "node list",
        )
        for node in nodes[:MAX_NODES]:
            meta = mapping(node.get("metadata"), "node metadata")
            spec = mapping(node.get("spec") or {}, "node spec")
            schedulable = "false" if spec.get("unschedulable") is True else "true"
            workloads.append(f"Node/{_token(meta.get('name'))} schedulable={schedulable}")

        events: list[str] = []
        if arguments.get("include_events"):
            raw_events = self._items(
                self._request(
                    connector,
                    context,
                    write=False,
                    method="GET",
                    request_path=path("api", "v1", "namespaces", namespace, "events"),
                    query=(("limit", str(MAX_EVENTS)),),
                ),
                "event list",
            )
            rows: list[tuple[str, str]] = []
            for event in raw_events:
                involved = mapping(event.get("involvedObject") or {}, "event object")
                name = str(involved.get("name", ""))
                if not name.startswith(service):
                    continue
                stamp = str(event.get("lastTimestamp") or event.get("eventTime") or "")
                rows.append(
                    (
                        stamp,
                        f"{_token(stamp)} {_token(event.get('type'))} "
                        f"{_token(event.get('reason'))} {_token(name)} "
                        f"{display_text(event.get('message', ''), limit=300)}",
                    )
                )
            events = [line for _stamp, line in sorted(rows)]
        return {
            "workloads": workloads,
            "events": events,
            "source": SOURCE,
            "schema_version": 1,
            "environment": str(arguments["environment"]),
            "service": service,
            "namespace": namespace,
        }

    def _deployment_line(
        self, deployment: Mapping[str, Any], replica_sets: list[Mapping[str, Any]]
    ) -> str:
        meta = mapping(deployment.get("metadata"), "deployment metadata")
        spec = mapping(deployment.get("spec"), "deployment spec")
        status = mapping(deployment.get("status") or {}, "deployment status")
        annotations = mapping(meta.get("annotations") or {}, "deployment annotations")
        desired = _int(spec.get("replicas"), 1)
        revision = _int(annotations.get(REVISION_ANNOTATION))
        idle = (
            _int(status.get("observedGeneration")) >= _int(meta.get("generation"))
            and _int(status.get("updatedReplicas")) == desired
            and _int(status.get("availableReplicas")) == desired
            and _int(status.get("unavailableReplicas")) == 0
        )
        containers = sequence(
            mapping(mapping(spec.get("template"), "template").get("spec"), "pod spec").get(
                "containers"
            ),
            "containers",
        )
        image = str(mapping(containers[0], "container").get("image", "")) if containers else ""
        history = ""
        uid = meta.get("uid")
        for replica_set in replica_sets:
            rs_meta = mapping(replica_set.get("metadata"), "replicaset metadata")
            owners = sequence(rs_meta.get("ownerReferences") or [], "owners")
            rs_annotations = mapping(rs_meta.get("annotations") or {}, "annotations")
            owned = any(mapping(o, "owner").get("uid") == uid for o in owners)
            if owned and _int(rs_annotations.get(REVISION_ANNOTATION)) == revision:
                history = str(rs_annotations.get(REVISION_HISTORY_ANNOTATION, ""))
        line = (
            f"Deployment/{_token(meta.get('name'))} "
            f"replicas={_int(status.get('readyReplicas'))}/{desired} revision={revision} "
            f"image={_token(image.rsplit(':', 1)[-1] if ':' in image else image)} "
            f"rollout={'idle' if idle else 'progressing'}"
        )
        if history and re.fullmatch(r"\d+(,\d+)*", history):
            line += f" revision_history={history}"
        return line

    def deploy_list(
        self, arguments: Mapping[str, Any], context: InvocationContext
    ) -> Mapping[str, Any]:
        connector = require_connector(context, self.kind)
        service = str(arguments["service"])
        # deploy.list declares no namespace argument; the namespace is the service's first
        # registered namespace, exactly as the broker resolves it for namespaced tools.
        if not connector.namespaces:
            raise IntegrationError(
                "service has no registered namespace",
                failure_class=IntegrationFailureClass.SCOPE_DENIED,
                effect_not_applied=True,
            )
        namespace = connector.namespaces[0]
        start = arguments.get("window_start")
        end = arguments.get("window_end")
        rows: list[tuple[int, str]] = []
        for replica_set in self._replica_sets(connector, context, namespace, service, write=False):
            meta = mapping(replica_set.get("metadata"), "replicaset metadata")
            annotations = mapping(meta.get("annotations") or {}, "annotations")
            revision = _int(annotations.get(REVISION_ANNOTATION), -1)
            if revision < 0:
                continue
            created_text = str(meta.get("creationTimestamp", ""))
            try:
                created = datetime.fromisoformat(created_text.replace("Z", "+00:00"))
            except ValueError as exc:
                raise malformed("replicaset creationTimestamp is invalid") from exc
            in_window = (
                isinstance(start, datetime) and isinstance(end, datetime) and start <= created < end
            )
            spec = mapping(replica_set.get("spec"), "replicaset spec")
            status = mapping(replica_set.get("status") or {}, "replicaset status")
            containers = sequence(
                mapping(mapping(spec.get("template"), "template").get("spec"), "pod spec").get(
                    "containers"
                ),
                "containers",
            )
            image = str(mapping(containers[0], "container").get("image", "")) if containers else ""
            active = "active" if _int(status.get("replicas")) > 0 else "inactive"
            rows.append(
                (
                    revision,
                    f"revision={revision} at={created.isoformat()} service={service} "
                    f"change=image:{_token(image)} status={active} "
                    f"replicaset={_token(meta.get('name'))} in_window={str(in_window).lower()}",
                )
            )
        rows.sort(key=lambda row: row[0], reverse=True)
        return {
            "deployments": [line for _revision, line in rows[:50]],
            "source": SOURCE,
            "schema_version": 1,
            "environment": str(arguments["environment"]),
            "service": service,
        }

    # ------------------------------------------------------------------- writes

    def deployment_rollback(
        self, arguments: Mapping[str, Any], context: InvocationContext
    ) -> Mapping[str, Any]:
        connector = require_connector(context, self.kind)
        namespace = str(arguments["namespace"])
        service = str(arguments["service"])
        name = str(arguments["deployment"])
        target_revision = int(arguments["to_revision"])
        deployment_path = path("apis", "apps", "v1", "namespaces", namespace, "deployments", name)
        deployment = mapping(
            self._request(
                connector, context, write=True, method="GET", request_path=deployment_path
            ),
            "deployment",
        )
        self._require_service_label(connector, deployment, service, "deployment")
        meta = mapping(deployment.get("metadata"), "deployment metadata")
        annotations = mapping(meta.get("annotations") or {}, "deployment annotations")
        current = _int(annotations.get(REVISION_ANNOTATION), -1)
        resource_version = meta.get("resourceVersion")
        if current < 0 or not isinstance(resource_version, str):
            raise malformed("deployment has no revision or resourceVersion")

        target: Mapping[str, Any] | None = None
        current_rs: Mapping[str, Any] | None = None
        for replica_set in self._replica_sets(connector, context, namespace, service, write=True):
            rs_meta = mapping(replica_set.get("metadata"), "replicaset metadata")
            owners = sequence(rs_meta.get("ownerReferences") or [], "owners")
            if not any(mapping(o, "owner").get("uid") == meta.get("uid") for o in owners):
                continue
            rs_annotations = mapping(rs_meta.get("annotations") or {}, "annotations")
            revision = _int(rs_annotations.get(REVISION_ANNOTATION), -1)
            history = str(rs_annotations.get(REVISION_HISTORY_ANNOTATION, "")).split(",")
            if revision == current:
                current_rs = replica_set
            if revision == target_revision or str(target_revision) in history:
                target = replica_set
        if target is None:
            raise IntegrationError(
                f"revision {target_revision} is not available for this deployment",
                failure_class=IntegrationFailureClass.NOT_FOUND,
                effect_not_applied=True,
            )
        if target is current_rs:
            # Already serving the target template: the effect is present, nothing to send.
            return {
                "previous_revision": current,
                "new_revision": target_revision,
                "source": SOURCE,
                "schema_version": 1,
            }
        template = copy.deepcopy(
            dict(
                mapping(mapping(target.get("spec"), "replicaset spec").get("template"), "template")
            )
        )
        template_meta = dict(mapping(template.get("metadata") or {}, "template metadata"))
        labels = dict(mapping(template_meta.get("labels") or {}, "template labels"))
        labels.pop("pod-template-hash", None)
        template_meta["labels"] = labels
        template["metadata"] = template_meta
        patch = [
            {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
            {"op": "replace", "path": "/spec/template", "value": template},
        ]
        mapping(
            self._request(
                connector,
                context,
                write=True,
                method="PATCH",
                request_path=deployment_path,
                body=json_body(patch),
                content_type="application/json-patch+json",
                effectful=True,
            ),
            "patched deployment",
            effectful=True,
        )
        return {
            "previous_revision": current,
            "new_revision": target_revision,
            "source": SOURCE,
            "schema_version": 1,
        }

    def hpa_adjust(
        self, arguments: Mapping[str, Any], context: InvocationContext
    ) -> Mapping[str, Any]:
        connector = require_connector(context, self.kind)
        namespace = str(arguments["namespace"])
        service = str(arguments["service"])
        low, high = int(arguments["min_replicas"]), int(arguments["max_replicas"])
        if low > high:
            raise IntegrationError(
                "min_replicas exceeds max_replicas",
                failure_class=IntegrationFailureClass.INVALID_REQUEST,
                effect_not_applied=True,
            )
        hpa_path = path(
            "apis",
            "autoscaling",
            "v2",
            "namespaces",
            namespace,
            "horizontalpodautoscalers",
            str(arguments["hpa_name"]),
        )
        hpa = mapping(
            self._request(connector, context, write=True, method="GET", request_path=hpa_path),
            "hpa",
        )
        self._require_service_label(connector, hpa, service, "horizontalpodautoscaler")
        spec = mapping(hpa.get("spec"), "hpa spec")
        previous_min, previous_max = _int(spec.get("minReplicas"), 1), _int(spec.get("maxReplicas"))
        if (previous_min, previous_max) != (low, high):
            self._request(
                connector,
                context,
                write=True,
                method="PATCH",
                request_path=hpa_path,
                body=json_body({"spec": {"minReplicas": low, "maxReplicas": high}}),
                content_type="application/merge-patch+json",
                effectful=True,
            )
        return {
            "previous_min": previous_min,
            "previous_max": previous_max,
            "source": SOURCE,
            "schema_version": 1,
        }

    def node_schedulability(
        self, arguments: Mapping[str, Any], context: InvocationContext, *, schedulable: bool
    ) -> Mapping[str, Any]:
        connector = require_connector(context, self.kind)
        node_path = path("api", "v1", "nodes", str(arguments["node"]))
        node = mapping(
            self._request(connector, context, write=True, method="GET", request_path=node_path),
            "node",
        )
        was_schedulable = (
            mapping(node.get("spec") or {}, "node spec").get("unschedulable") is not True
        )
        if was_schedulable != schedulable:
            self._request(
                connector,
                context,
                write=True,
                method="PATCH",
                request_path=node_path,
                body=json_body({"spec": {"unschedulable": not schedulable}}),
                content_type="application/merge-patch+json",
                effectful=True,
            )
        return {"was_schedulable": was_schedulable, "source": SOURCE, "schema_version": 1}


__all__ = ["SOURCE", "KubernetesAdapter"]
