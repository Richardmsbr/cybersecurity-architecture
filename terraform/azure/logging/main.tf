# Azure Logging and Monitoring Configuration
# Log Analytics, Activity Logs, and Diagnostic Settings

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

# Variables
variable "environment" {
  type        = string
  description = "Environment name"
  default     = "production"
}

variable "location" {
  type        = string
  description = "Azure region"
  default     = "eastus"
}

variable "resource_group_name" {
  type        = string
  description = "Resource group name"
}

variable "log_retention_days" {
  type        = number
  description = "Log retention in days"
  default     = 90
}

variable "archive_retention_days" {
  type        = number
  description = "Archive retention in days"
  default     = 365
}

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.environment}-log-analytics"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days

  internet_ingestion_enabled = true
  internet_query_enabled     = true

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Storage Account for Long-term Archive
resource "azurerm_storage_account" "logs" {
  name                     = "${var.environment}logsarchive"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  min_tls_version          = "TLS1_2"

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 30
    }

    container_delete_retention_policy {
      days = 30
    }
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Storage Container for Activity Logs
resource "azurerm_storage_container" "activity_logs" {
  name                  = "activity-logs"
  storage_account_name  = azurerm_storage_account.logs.name
  container_access_type = "private"
}

# Storage Container for Resource Logs
resource "azurerm_storage_container" "resource_logs" {
  name                  = "resource-logs"
  storage_account_name  = azurerm_storage_account.logs.name
  container_access_type = "private"
}

# Storage Management Policy for Tiering
resource "azurerm_storage_management_policy" "logs" {
  storage_account_id = azurerm_storage_account.logs.id

  rule {
    name    = "log-lifecycle"
    enabled = true

    filters {
      blob_types = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = 30
        tier_to_archive_after_days_since_modification_greater_than = 90
        delete_after_days_since_modification_greater_than          = var.archive_retention_days
      }

      snapshot {
        delete_after_days_since_creation_greater_than = 30
      }
    }
  }
}

# Data Source for Subscription
data "azurerm_subscription" "current" {}

# Activity Log Diagnostic Setting (Subscription Level)
resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "${var.environment}-activity-log"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  storage_account_id         = azurerm_storage_account.logs.id

  enabled_log {
    category = "Administrative"
  }

  enabled_log {
    category = "Security"
  }

  enabled_log {
    category = "ServiceHealth"
  }

  enabled_log {
    category = "Alert"
  }

  enabled_log {
    category = "Recommendation"
  }

  enabled_log {
    category = "Policy"
  }

  enabled_log {
    category = "Autoscale"
  }

  enabled_log {
    category = "ResourceHealth"
  }
}

# Log Analytics Solutions
resource "azurerm_log_analytics_solution" "security" {
  solution_name         = "Security"
  location              = var.location
  resource_group_name   = var.resource_group_name
  workspace_resource_id = azurerm_log_analytics_workspace.main.id
  workspace_name        = azurerm_log_analytics_workspace.main.name

  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/Security"
  }
}

resource "azurerm_log_analytics_solution" "security_center" {
  solution_name         = "SecurityCenterFree"
  location              = var.location
  resource_group_name   = var.resource_group_name
  workspace_resource_id = azurerm_log_analytics_workspace.main.id
  workspace_name        = azurerm_log_analytics_workspace.main.name

  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/SecurityCenterFree"
  }
}

resource "azurerm_log_analytics_solution" "updates" {
  solution_name         = "Updates"
  location              = var.location
  resource_group_name   = var.resource_group_name
  workspace_resource_id = azurerm_log_analytics_workspace.main.id
  workspace_name        = azurerm_log_analytics_workspace.main.name

  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/Updates"
  }
}

resource "azurerm_log_analytics_solution" "change_tracking" {
  solution_name         = "ChangeTracking"
  location              = var.location
  resource_group_name   = var.resource_group_name
  workspace_resource_id = azurerm_log_analytics_workspace.main.id
  workspace_name        = azurerm_log_analytics_workspace.main.name

  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/ChangeTracking"
  }
}

# Log Analytics Saved Searches
resource "azurerm_log_analytics_saved_search" "failed_logins" {
  name                       = "FailedLogins"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Security"
  display_name               = "Failed Login Attempts"
  query                      = <<QUERY
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, ResultType
| where FailedAttempts > 5
| order by FailedAttempts desc
QUERY
}

resource "azurerm_log_analytics_saved_search" "privilege_escalation" {
  name                       = "PrivilegeEscalation"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Security"
  display_name               = "Privilege Escalation Events"
  query                      = <<QUERY
AuditLogs
| where OperationName has_any ("Add member to role", "Add eligible member to role")
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = tostring(TargetResources[0].displayName)
| project TimeGenerated, InitiatedBy, TargetUser, RoleName, Result
QUERY
}

resource "azurerm_log_analytics_saved_search" "security_group_changes" {
  name                       = "SecurityGroupChanges"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Security"
  display_name               = "Network Security Group Changes"
  query                      = <<QUERY
AzureActivity
| where OperationNameValue has_any ("NetworkSecurityGroups/write", "securityRules/write")
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup, _ResourceId, Properties
QUERY
}

# Action Group for Alerts
resource "azurerm_monitor_action_group" "security" {
  name                = "${var.environment}-security-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name                    = "SecurityTeam"
    email_address           = "security@example.com"
    use_common_alert_schema = true
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Alert Rules
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "failed_logins" {
  name                = "${var.environment}-failed-logins-alert"
  location            = var.location
  resource_group_name = var.resource_group_name
  scopes              = [azurerm_log_analytics_workspace.main.id]
  description         = "Alert on excessive failed login attempts"
  severity            = 2

  criteria {
    query                   = <<QUERY
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
QUERY
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"
  }

  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  action {
    action_groups = [azurerm_monitor_action_group.security.id]
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "admin_role_changes" {
  name                = "${var.environment}-admin-role-changes-alert"
  location            = var.location
  resource_group_name = var.resource_group_name
  scopes              = [azurerm_log_analytics_workspace.main.id]
  description         = "Alert on administrative role changes"
  severity            = 1

  criteria {
    query                   = <<QUERY
AuditLogs
| where OperationName has_any ("Add member to role", "Add eligible member to role")
| where TargetResources has_any ("Global Administrator", "Privileged Role Administrator")
QUERY
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"
  }

  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  action {
    action_groups = [azurerm_monitor_action_group.security.id]
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Data Collection Rule for VMs
resource "azurerm_monitor_data_collection_rule" "vm_logs" {
  name                = "${var.environment}-vm-dcr"
  location            = var.location
  resource_group_name = var.resource_group_name

  destinations {
    log_analytics {
      workspace_resource_id = azurerm_log_analytics_workspace.main.id
      name                  = "log-analytics"
    }
  }

  data_flow {
    streams      = ["Microsoft-SecurityEvent", "Microsoft-Syslog"]
    destinations = ["log-analytics"]
  }

  data_sources {
    windows_event_log {
      streams = ["Microsoft-SecurityEvent"]
      name    = "windows-security"
      x_path_queries = [
        "Security!*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4648 or EventID=4672 or EventID=4688 or EventID=4697 or EventID=4720 or EventID=4722 or EventID=4723 or EventID=4724 or EventID=4725 or EventID=4726 or EventID=4728 or EventID=4732 or EventID=4738 or EventID=4740 or EventID=4756 or EventID=4767 or EventID=4768 or EventID=4769 or EventID=4771 or EventID=4776)]]"
      ]
    }

    syslog {
      facility_names = ["auth", "authpriv", "daemon", "kern"]
      log_levels     = ["Alert", "Critical", "Emergency", "Error", "Warning"]
      name           = "linux-syslog"
      streams        = ["Microsoft-Syslog"]
    }
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Outputs
output "log_analytics_workspace_id" {
  description = "Log Analytics Workspace ID"
  value       = azurerm_log_analytics_workspace.main.id
}

output "log_analytics_workspace_name" {
  description = "Log Analytics Workspace name"
  value       = azurerm_log_analytics_workspace.main.name
}

output "log_analytics_primary_key" {
  description = "Log Analytics primary key"
  value       = azurerm_log_analytics_workspace.main.primary_shared_key
  sensitive   = true
}

output "storage_account_id" {
  description = "Storage Account ID"
  value       = azurerm_storage_account.logs.id
}

output "action_group_id" {
  description = "Action Group ID"
  value       = azurerm_monitor_action_group.security.id
}

output "data_collection_rule_id" {
  description = "Data Collection Rule ID"
  value       = azurerm_monitor_data_collection_rule.vm_logs.id
}
