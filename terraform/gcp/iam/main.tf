# GCP IAM Security Configuration
# Identity and Access Management best practices

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

# Variables
variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "environment" {
  type        = string
  description = "Environment name"
  default     = "production"
}

variable "org_id" {
  type        = string
  description = "GCP Organization ID"
  default     = ""
}

variable "security_admin_members" {
  type        = list(string)
  description = "Members for security admin role"
  default     = []
}

variable "security_viewer_members" {
  type        = list(string)
  description = "Members for security viewer role"
  default     = []
}

# Custom Security Admin Role
resource "google_project_iam_custom_role" "security_admin" {
  project     = var.project_id
  role_id     = "${var.environment}_security_admin"
  title       = "${var.environment} Security Administrator"
  description = "Custom security administrator role with elevated security permissions"

  permissions = [
    "securitycenter.findings.list",
    "securitycenter.findings.update",
    "securitycenter.sources.list",
    "securitycenter.assets.list",
    "logging.logEntries.list",
    "logging.logs.list",
    "logging.logMetrics.list",
    "logging.sinks.list",
    "monitoring.alertPolicies.list",
    "monitoring.alertPolicies.update",
    "monitoring.dashboards.list",
    "iam.roles.list",
    "iam.serviceAccounts.list",
    "iam.serviceAccountKeys.list",
    "resourcemanager.projects.getIamPolicy",
    "compute.firewalls.list",
    "compute.networks.list",
    "compute.securityPolicies.list",
    "cloudasset.assets.searchAllResources",
    "cloudasset.assets.searchAllIamPolicies"
  ]
}

# Custom Security Viewer Role
resource "google_project_iam_custom_role" "security_viewer" {
  project     = var.project_id
  role_id     = "${var.environment}_security_viewer"
  title       = "${var.environment} Security Viewer"
  description = "Read-only security role for security team members"

  permissions = [
    "securitycenter.findings.list",
    "securitycenter.sources.list",
    "securitycenter.assets.list",
    "logging.logEntries.list",
    "logging.logs.list",
    "monitoring.alertPolicies.list",
    "monitoring.dashboards.list",
    "iam.roles.list",
    "iam.serviceAccounts.list",
    "resourcemanager.projects.getIamPolicy",
    "compute.firewalls.list",
    "compute.networks.list"
  ]
}

# Security Admin Service Account
resource "google_service_account" "security_automation" {
  project      = var.project_id
  account_id   = "${var.environment}-security-automation"
  display_name = "${var.environment} Security Automation Service Account"
  description  = "Service account for security automation tasks"
}

# Security Admin Role Binding
resource "google_project_iam_member" "security_admin" {
  for_each = toset(var.security_admin_members)
  project  = var.project_id
  role     = google_project_iam_custom_role.security_admin.id
  member   = each.value
}

# Security Viewer Role Binding
resource "google_project_iam_member" "security_viewer" {
  for_each = toset(var.security_viewer_members)
  project  = var.project_id
  role     = google_project_iam_custom_role.security_viewer.id
  member   = each.value
}

# Workload Identity Pool for External Authentication
resource "google_iam_workload_identity_pool" "security" {
  project                   = var.project_id
  workload_identity_pool_id = "${var.environment}-security-pool"
  display_name              = "${var.environment} Security Identity Pool"
  description               = "Identity pool for external security tools"
}

# Organization Policy - Domain Restricted Sharing
resource "google_org_policy_policy" "domain_restricted_sharing" {
  count  = var.org_id != "" ? 1 : 0
  name   = "organizations/${var.org_id}/policies/iam.allowedPolicyMemberDomains"
  parent = "organizations/${var.org_id}"

  spec {
    rules {
      values {
        allowed_values = ["is:${var.org_id}"]
      }
    }
  }
}

# Organization Policy - Disable Service Account Key Creation
resource "google_org_policy_policy" "disable_sa_key_creation" {
  count  = var.org_id != "" ? 1 : 0
  name   = "organizations/${var.org_id}/policies/iam.disableServiceAccountKeyCreation"
  parent = "organizations/${var.org_id}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# Organization Policy - Require OS Login
resource "google_org_policy_policy" "require_os_login" {
  count  = var.org_id != "" ? 1 : 0
  name   = "organizations/${var.org_id}/policies/compute.requireOsLogin"
  parent = "organizations/${var.org_id}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# IAM Audit Config
resource "google_project_iam_audit_config" "all_services" {
  project = var.project_id
  service = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# Outputs
output "security_admin_role" {
  description = "Security admin custom role ID"
  value       = google_project_iam_custom_role.security_admin.id
}

output "security_viewer_role" {
  description = "Security viewer custom role ID"
  value       = google_project_iam_custom_role.security_viewer.id
}

output "security_automation_sa_email" {
  description = "Security automation service account email"
  value       = google_service_account.security_automation.email
}

output "workload_identity_pool_id" {
  description = "Workload identity pool ID"
  value       = google_iam_workload_identity_pool.security.workload_identity_pool_id
}
