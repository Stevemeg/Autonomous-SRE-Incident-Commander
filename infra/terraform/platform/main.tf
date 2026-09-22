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

  service_accounts = toset([
    "asic-api",
    "asic-frontend",
    "asic-migration",
  ])
}

resource "kubernetes_namespace_v1" "asic" {
  metadata {
    name   = var.namespace
    labels = local.labels
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
