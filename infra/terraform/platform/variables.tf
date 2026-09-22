variable "kubeconfig_path" {
  description = "Path to a short-lived or operator-managed kubeconfig. Never store its contents in Terraform state."
  type        = string
  default     = "~/.kube/config"

  validation {
    condition     = length(trimspace(var.kubeconfig_path)) > 0
    error_message = "kubeconfig_path must not be empty."
  }
}

variable "kube_context" {
  description = "Explicit Kubernetes context; prevents accidental use of the current context."
  type        = string

  validation {
    condition     = length(trimspace(var.kube_context)) > 0
    error_message = "kube_context must be explicit."
  }
}

variable "namespace" {
  description = "Dedicated namespace owned by Terraform; Kustomize owns namespaced workloads."
  type        = string
  default     = "asic-system"

  validation {
    condition = (
      length(var.namespace) <= 63 &&
      can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace)) &&
      !contains(["default", "kube-system", "kube-public", "kube-node-lease"], var.namespace)
    )
    error_message = "namespace must be a dedicated non-system DNS label of at most 63 characters."
  }
}

variable "labels" {
  description = "Additional non-secret platform labels."
  type        = map(string)
  default     = {}
}
