# GCP Security Command Center Configuration
# Centralized security and risk management

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

variable "org_id" {
  type        = string
  description = "GCP Organization ID"
}

variable "environment" {
  type        = string
  description = "Environment name"
  default     = "production"
}

variable "notification_email" {
  type        = string
  description = "Email for security notifications"
  default     = "security@example.com"
}

variable "pubsub_topic_name" {
  type        = string
  description = "Pub/Sub topic for SCC findings"
  default     = "scc-findings"
}

# Enable Security Command Center API
resource "google_project_service" "scc" {
  project = var.project_id
  service = "securitycenter.googleapis.com"

  disable_on_destroy = false
}

# Pub/Sub Topic for SCC Findings
resource "google_pubsub_topic" "scc_findings" {
  project = var.project_id
  name    = "${var.environment}-${var.pubsub_topic_name}"

  labels = {
    environment = var.environment
    purpose     = "security-findings"
  }
}

# Pub/Sub Subscription
resource "google_pubsub_subscription" "scc_findings" {
  project = var.project_id
  name    = "${var.environment}-${var.pubsub_topic_name}-sub"
  topic   = google_pubsub_topic.scc_findings.name

  ack_deadline_seconds       = 20
  message_retention_duration = "604800s"  # 7 days
  retain_acked_messages      = false

  expiration_policy {
    ttl = ""  # Never expires
  }
}

# SCC Notification Config - Critical Findings
resource "google_scc_notification_config" "critical_findings" {
  config_id    = "${var.environment}-critical-findings"
  organization = var.org_id
  description  = "Notifications for critical security findings"
  pubsub_topic = google_pubsub_topic.scc_findings.id

  streaming_config {
    filter = "severity=\"CRITICAL\" OR severity=\"HIGH\""
  }

  depends_on = [google_project_service.scc]
}

# SCC Notification Config - All Findings
resource "google_scc_notification_config" "all_findings" {
  config_id    = "${var.environment}-all-findings"
  organization = var.org_id
  description  = "Notifications for all security findings"
  pubsub_topic = google_pubsub_topic.scc_findings.id

  streaming_config {
    filter = "state=\"ACTIVE\""
  }

  depends_on = [google_project_service.scc]
}

# BigQuery Dataset for SCC Export
resource "google_bigquery_dataset" "scc_export" {
  project    = var.project_id
  dataset_id = "${var.environment}_scc_findings"
  location   = "US"

  default_table_expiration_ms = 31536000000  # 365 days

  access {
    role          = "OWNER"
    special_group = "projectOwners"
  }

  labels = {
    environment = var.environment
    purpose     = "scc-analytics"
  }
}

# SCC BigQuery Export
resource "google_scc_organization_custom_module" "export_findings" {
  organization   = var.org_id
  display_name   = "${var.environment}-finding-export"
  enablement_state = "ENABLED"

  custom_config {
    predicate {
      expression = "resource.project_display_name.contains(\"${var.environment}\")"
    }

    custom_output {
      properties {
        name = "environment"
        value_expression {
          expression = "\"${var.environment}\""
        }
      }
    }

    resource_selector {
      resource_types = [
        "compute.googleapis.com/Instance",
        "storage.googleapis.com/Bucket",
        "iam.googleapis.com/ServiceAccount",
        "container.googleapis.com/Cluster"
      ]
    }

    severity     = "HIGH"
    description  = "Custom module for ${var.environment} environment"
    recommendation = "Review and remediate the finding according to security policy"
  }

  depends_on = [google_project_service.scc]
}

# Cloud Function for Auto-Remediation (optional)
resource "google_storage_bucket" "functions" {
  project  = var.project_id
  name     = "${var.project_id}-${var.environment}-scc-functions"
  location = "US"

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }
}

# Service Account for Cloud Function
resource "google_service_account" "scc_remediation" {
  project      = var.project_id
  account_id   = "${var.environment}-scc-remediation"
  display_name = "${var.environment} SCC Auto-Remediation"
  description  = "Service account for automated security remediation"
}

# Grant necessary permissions
resource "google_project_iam_member" "scc_remediation_viewer" {
  project = var.project_id
  role    = "roles/securitycenter.findingsViewer"
  member  = "serviceAccount:${google_service_account.scc_remediation.email}"
}

resource "google_project_iam_member" "scc_remediation_editor" {
  project = var.project_id
  role    = "roles/securitycenter.findingsEditor"
  member  = "serviceAccount:${google_service_account.scc_remediation.email}"
}

# Mute Config for Known False Positives
resource "google_scc_mute_config" "false_positives" {
  mute_config_id = "${var.environment}-false-positives"
  parent         = "organizations/${var.org_id}"
  description    = "Mute known false positive findings"
  filter         = "category=\"PUBLIC_IP_ADDRESS\" AND resource.project_display_name=\"${var.environment}-public-facing\""

  depends_on = [google_project_service.scc]
}

# Organization Security Health Analytics Settings
resource "google_scc_source_iam_binding" "security_team" {
  organization = var.org_id
  source       = "organizations/${var.org_id}/sources/-"
  role         = "roles/securitycenter.findingsViewer"
  members = [
    "group:security-team@example.com"
  ]

  depends_on = [google_project_service.scc]
}

# Cloud Monitoring Dashboard for SCC
resource "google_monitoring_dashboard" "scc_dashboard" {
  project        = var.project_id
  dashboard_json = jsonencode({
    displayName = "${var.environment} Security Command Center"
    mosaicLayout = {
      columns = 12
      tiles = [
        {
          width  = 6
          height = 4
          widget = {
            title = "Critical Findings"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"securitycenter.googleapis.com/finding_count\" AND metric.labels.severity=\"CRITICAL\""
                }
              }
              thresholds = [
                {
                  value = 1
                  color = "RED"
                }
              ]
            }
          }
        },
        {
          xPos   = 6
          width  = 6
          height = 4
          widget = {
            title = "High Severity Findings"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"securitycenter.googleapis.com/finding_count\" AND metric.labels.severity=\"HIGH\""
                }
              }
              thresholds = [
                {
                  value = 5
                  color = "YELLOW"
                }
              ]
            }
          }
        },
        {
          yPos   = 4
          width  = 12
          height = 4
          widget = {
            title = "Findings by Category"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"securitycenter.googleapis.com/finding_count\""
                    }
                  }
                }
              ]
            }
          }
        }
      ]
    }
  })
}

# Outputs
output "scc_pubsub_topic" {
  description = "Pub/Sub topic for SCC findings"
  value       = google_pubsub_topic.scc_findings.id
}

output "scc_subscription" {
  description = "Pub/Sub subscription for SCC findings"
  value       = google_pubsub_subscription.scc_findings.id
}

output "scc_bigquery_dataset" {
  description = "BigQuery dataset for SCC export"
  value       = google_bigquery_dataset.scc_export.dataset_id
}

output "remediation_sa_email" {
  description = "Service account for auto-remediation"
  value       = google_service_account.scc_remediation.email
}

output "dashboard_id" {
  description = "SCC monitoring dashboard ID"
  value       = google_monitoring_dashboard.scc_dashboard.id
}
