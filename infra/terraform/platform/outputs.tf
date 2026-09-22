output "namespace" {
  description = "Namespace in which Kustomize installs ASIC workloads."
  value       = kubernetes_namespace_v1.asic.metadata[0].name
}

output "service_accounts" {
  description = "Unprivileged workload service accounts. No RBAC roles are bound by this module."
  value       = sort([for account in kubernetes_service_account_v1.workload : account.metadata[0].name])
}
