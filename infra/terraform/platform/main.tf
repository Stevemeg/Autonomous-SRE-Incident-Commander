provider "kubernetes" {
  config_path    = pathexpand(var.kubeconfig_path)
  config_context = var.kube_context
}

locals {
  labels = merge(
    {
      "app.kubernetes.io/part-of"    = "asic"
      "app.kubernetes.io/managed-by" = "terraform"
    },
    var.labels,
  )

  # Pod Security Admission: every workload in the namespace must satisfy "restricted".
  # Merged last so caller-supplied labels cannot weaken it.
  pod_security_labels = {
    "pod-security.kubernetes.io/enforce"         = "restricted"
    "pod-security.kubernetes.io/enforce-version" = var.pod_security_version
    "pod-security.kubernetes.io/audit"           = "restricted"
    "pod-security.kubernetes.io/audit-version"   = var.pod_security_version
    "pod-security.kubernetes.io/warn"            = "restricted"
    "pod-security.kubernetes.io/warn-version"    = var.pod_security_version
  }

  service_accounts = toset([
    "asic-api",
    "asic-frontend",
    "asic-migration",
  ])
}

resource "kubernetes_namespace_v1" "asic" {
  metadata {
    name   = var.namespace
    labels = merge(local.labels, local.pod_security_labels)
  }
}

resource "kubernetes_service_account_v1" "workload" {
  for_each = local.service_accounts

  metadata {
    name      = each.value
    namespace = kubernetes_namespace_v1.asic.metadata[0].name
    labels    = local.labels
  }

  automount_service_account_token = false
}
