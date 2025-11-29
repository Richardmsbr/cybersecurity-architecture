# GCP Cloud Logging and Monitoring Configuration
# Centralized logging, metrics, and alerting

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

variable "region" {
  type        = string
  description = "GCP Region"
  default     = "us-central1"
}

variable "log_retention_days" {
  type        = number
  description = "Log retention in days"
  default     = 365
}

variable "notification_email" {
  type        = string
  description = "Email for security alerts"
  default     = "security@example.com"
}

# Log Bucket for Long-term Storage
resource "google_logging_project_bucket_config" "security_logs" {
  project        = var.project_id
  location       = var.region
  retention_days = var.log_retention_days
  bucket_id      = "${var.environment}-security-logs"
  description    = "Security logs bucket for ${var.environment}"

  index_configs {
    field_path = "jsonPayload.severity"
    type       = "INDEX_TYPE_STRING"
  }

  index_configs {
    field_path = "jsonPayload.resource.type"
    type       = "INDEX_TYPE_STRING"
  }
}

# Log Sink - Security Events to Bucket
resource "google_logging_project_sink" "security_events" {
  project     = var.project_id
  name        = "${var.environment}-security-events-sink"
  destination = "logging.googleapis.com/projects/${var.project_id}/locations/${var.region}/buckets/${google_logging_project_bucket_config.security_logs.bucket_id}"

  filter = <<-EOT
    protoPayload.methodName=~"SetIamPolicy" OR
    protoPayload.methodName=~"CreateServiceAccount" OR
    protoPayload.methodName=~"DeleteServiceAccount" OR
    protoPayload.methodName=~"CreateServiceAccountKey" OR
    protoPayload.methodName=~"DeleteServiceAccountKey" OR
    protoPayload.methodName=~"SetFirewall" OR
    protoPayload.methodName=~"DeleteFirewall" OR
    protoPayload.serviceName="login.googleapis.com" OR
    resource.type="gce_firewall_rule" OR
    resource.type="iam_role" OR
    resource.type="service_account"
  EOT

  unique_writer_identity = true
}

# Log Sink - Export to BigQuery for Analysis
resource "google_bigquery_dataset" "security_logs" {
  project    = var.project_id
  dataset_id = "${var.environment}_security_logs"
  location   = var.region

  default_table_expiration_ms = var.log_retention_days * 24 * 60 * 60 * 1000

  access {
    role          = "OWNER"
    special_group = "projectOwners"
  }

  access {
    role          = "READER"
    special_group = "projectReaders"
  }

  labels = {
    environment = var.environment
    purpose     = "security-analytics"
  }
}

resource "google_logging_project_sink" "bigquery_sink" {
  project     = var.project_id
  name        = "${var.environment}-bigquery-sink"
  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.security_logs.dataset_id}"

  filter = <<-EOT
    protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog" OR
    resource.type="gce_instance" OR
    resource.type="k8s_cluster" OR
    resource.type="cloud_function"
  EOT

  unique_writer_identity = true
  bigquery_options {
    use_partitioned_tables = true
  }
}

# Grant BigQuery permissions to sink
resource "google_bigquery_dataset_iam_member" "sink_writer" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.security_logs.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.bigquery_sink.writer_identity
}

# Log-based Metrics

# Failed Login Attempts
resource "google_logging_metric" "failed_logins" {
  project     = var.project_id
  name        = "${var.environment}_failed_logins"
  description = "Count of failed login attempts"
  filter      = <<-EOT
    protoPayload.serviceName="login.googleapis.com" AND
    protoPayload.status.code!=0
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User attempting login"
    }
  }

  label_extractors = {
    "user" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# IAM Policy Changes
resource "google_logging_metric" "iam_changes" {
  project     = var.project_id
  name        = "${var.environment}_iam_policy_changes"
  description = "Count of IAM policy modifications"
  filter      = <<-EOT
    protoPayload.methodName=~"SetIamPolicy" OR
    protoPayload.methodName=~"CreateRole" OR
    protoPayload.methodName=~"DeleteRole" OR
    protoPayload.methodName=~"UpdateRole"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Firewall Rule Changes
resource "google_logging_metric" "firewall_changes" {
  project     = var.project_id
  name        = "${var.environment}_firewall_changes"
  description = "Count of firewall rule modifications"
  filter      = <<-EOT
    resource.type="gce_firewall_rule" AND
    (protoPayload.methodName=~"insert" OR
     protoPayload.methodName=~"delete" OR
     protoPayload.methodName=~"patch" OR
     protoPayload.methodName=~"update")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Service Account Key Creation
resource "google_logging_metric" "sa_key_creation" {
  project     = var.project_id
  name        = "${var.environment}_sa_key_creation"
  description = "Count of service account key creations"
  filter      = <<-EOT
    protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Notification Channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "${var.environment} Security Alerts"
  type         = "email"

  labels = {
    email_address = var.notification_email
  }
}

# Alert Policies

# Failed Login Alert
resource "google_monitoring_alert_policy" "failed_logins" {
  project      = var.project_id
  display_name = "${var.environment} - Excessive Failed Logins"
  combiner     = "OR"

  conditions {
    display_name = "Failed login threshold"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.failed_logins.name}\" AND resource.type=\"global\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "Multiple failed login attempts detected. Investigate potential brute force attack."
    mime_type = "text/markdown"
  }
}

# IAM Changes Alert
resource "google_monitoring_alert_policy" "iam_changes" {
  project      = var.project_id
  display_name = "${var.environment} - IAM Policy Changes"
  combiner     = "OR"

  conditions {
    display_name = "IAM policy change detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.iam_changes.name}\" AND resource.type=\"global\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "IAM policy change detected. Review the change for compliance."
    mime_type = "text/markdown"
  }
}

# SA Key Creation Alert
resource "google_monitoring_alert_policy" "sa_key_creation" {
  project      = var.project_id
  display_name = "${var.environment} - Service Account Key Created"
  combiner     = "OR"

  conditions {
    display_name = "SA key creation detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_key_creation.name}\" AND resource.type=\"global\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "Service account key was created. This is a security-sensitive operation that should be reviewed."
    mime_type = "text/markdown"
  }
}

# Outputs
output "security_logs_bucket" {
  description = "Security logs bucket ID"
  value       = google_logging_project_bucket_config.security_logs.bucket_id
}

output "bigquery_dataset" {
  description = "BigQuery dataset for security analytics"
  value       = google_bigquery_dataset.security_logs.dataset_id
}

output "notification_channel_id" {
  description = "Notification channel ID"
  value       = google_monitoring_notification_channel.email.id
}

output "failed_logins_metric" {
  description = "Failed logins metric name"
  value       = google_logging_metric.failed_logins.name
}
