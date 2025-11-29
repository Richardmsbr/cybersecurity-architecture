# Azure SIEM Configuration
# Log Analytics-based SIEM with advanced analytics

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

variable "enable_threat_intelligence" {
  type        = bool
  description = "Enable threat intelligence feeds"
  default     = true
}

# Log Analytics Workspace for SIEM
resource "azurerm_log_analytics_workspace" "siem" {
  name                = "${var.environment}-siem-workspace"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days

  internet_ingestion_enabled = true
  internet_query_enabled     = true

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
    Purpose     = "SIEM"
  }
}

# Log Analytics Cluster for dedicated capacity (optional for large deployments)
# resource "azurerm_log_analytics_cluster" "siem" {
#   name                = "${var.environment}-siem-cluster"
#   location            = var.location
#   resource_group_name = var.resource_group_name
#   identity {
#     type = "SystemAssigned"
#   }
# }

# Custom Log Table for Security Events
resource "azurerm_log_analytics_query_pack" "security" {
  name                = "${var.environment}-security-queries"
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Security Detection Queries
resource "azurerm_log_analytics_query_pack_query" "brute_force" {
  query_pack_id = azurerm_log_analytics_query_pack.security.id
  display_name  = "Brute Force Detection"
  description   = "Detects brute force attacks based on failed login attempts"
  body          = <<QUERY
SigninLogs
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    UniqueUsers = dcount(UserPrincipalName),
    TargetUsers = make_set(UserPrincipalName)
    by IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| extend ThreatIndicator = "BruteForce"
| project TimeGenerated, IPAddress, FailedAttempts, UniqueUsers, TargetUsers, ThreatIndicator
QUERY

  categories    = ["Security", "Authentication"]
  solutions     = ["SecurityInsights"]
}

resource "azurerm_log_analytics_query_pack_query" "lateral_movement" {
  query_pack_id = azurerm_log_analytics_query_pack.security.id
  display_name  = "Lateral Movement Detection"
  description   = "Detects potential lateral movement patterns"
  body          = <<QUERY
SecurityEvent
| where EventID in (4624, 4625)
| where LogonType in (3, 10)
| summarize
    LoginCount = count(),
    UniqueTargets = dcount(Computer),
    Targets = make_set(Computer)
    by Account, IpAddress, bin(TimeGenerated, 1h)
| where UniqueTargets > 3
| extend ThreatIndicator = "LateralMovement"
QUERY

  categories    = ["Security", "ThreatHunting"]
  solutions     = ["SecurityInsights"]
}

resource "azurerm_log_analytics_query_pack_query" "data_exfiltration" {
  query_pack_id = azurerm_log_analytics_query_pack.security.id
  display_name  = "Data Exfiltration Detection"
  description   = "Detects unusual outbound data transfer patterns"
  body          = <<QUERY
AzureNetworkAnalytics_CL
| where FlowDirection_s == "O"
| summarize
    TotalBytes = sum(BytesSentToDestination_d),
    UniqueDestinations = dcount(DestIP_s)
    by SrcIP_s, bin(TimeGenerated, 1h)
| where TotalBytes > 1000000000 or UniqueDestinations > 50
| extend ThreatIndicator = "DataExfiltration"
QUERY

  categories    = ["Security", "DataProtection"]
  solutions     = ["SecurityInsights"]
}

resource "azurerm_log_analytics_query_pack_query" "privilege_escalation" {
  query_pack_id = azurerm_log_analytics_query_pack.security.id
  display_name  = "Privilege Escalation Detection"
  description   = "Detects privilege escalation attempts"
  body          = <<QUERY
AuditLogs
| where OperationName has_any ("Add member to role", "Add eligible member to role", "Add owner")
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = tostring(TargetResources[0].displayName)
| where RoleName has_any ("Administrator", "Owner", "Contributor")
| project TimeGenerated, InitiatedByUser, TargetUser, RoleName, OperationName, Result
| extend ThreatIndicator = "PrivilegeEscalation"
QUERY

  categories    = ["Security", "Identity"]
  solutions     = ["SecurityInsights"]
}

resource "azurerm_log_analytics_query_pack_query" "malware_indicators" {
  query_pack_id = azurerm_log_analytics_query_pack.security.id
  display_name  = "Malware Indicators"
  description   = "Detects known malware indicators"
  body          = <<QUERY
SecurityEvent
| where EventID == 4688
| where CommandLine has_any (
    "powershell -enc",
    "Invoke-Expression",
    "IEX",
    "DownloadString",
    "certutil -decode",
    "bitsadmin /transfer"
)
| extend ThreatIndicator = "MalwareIndicator"
| project TimeGenerated, Computer, Account, CommandLine, ThreatIndicator
QUERY

  categories    = ["Security", "Malware"]
  solutions     = ["SecurityInsights"]
}

# Action Group for SIEM Alerts
resource "azurerm_monitor_action_group" "siem" {
  name                = "${var.environment}-siem-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SIEMAlert"

  email_receiver {
    name                    = "SecurityTeam"
    email_address           = "security@example.com"
    use_common_alert_schema = true
  }

  email_receiver {
    name                    = "SOC"
    email_address           = "soc@example.com"
    use_common_alert_schema = true
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Alert Rules
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "brute_force_alert" {
  name                = "${var.environment}-brute-force-alert"
  location            = var.location
  resource_group_name = var.resource_group_name
  scopes              = [azurerm_log_analytics_workspace.siem.id]
  description         = "Alert on brute force attack detection"
  severity            = 2

  criteria {
    query                   = <<QUERY
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
QUERY
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"
  }

  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  action {
    action_groups = [azurerm_monitor_action_group.siem.id]
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "privilege_escalation_alert" {
  name                = "${var.environment}-privilege-escalation-alert"
  location            = var.location
  resource_group_name = var.resource_group_name
  scopes              = [azurerm_log_analytics_workspace.siem.id]
  description         = "Alert on privilege escalation"
  severity            = 1

  criteria {
    query                   = <<QUERY
AuditLogs
| where OperationName has_any ("Add member to role", "Add eligible member to role")
| where TargetResources has_any ("Global Administrator", "Privileged Role Administrator", "Security Administrator")
QUERY
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"
  }

  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  action {
    action_groups = [azurerm_monitor_action_group.siem.id]
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "malware_alert" {
  name                = "${var.environment}-malware-alert"
  location            = var.location
  resource_group_name = var.resource_group_name
  scopes              = [azurerm_log_analytics_workspace.siem.id]
  description         = "Alert on malware indicators"
  severity            = 1

  criteria {
    query                   = <<QUERY
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("powershell -enc", "Invoke-Expression", "IEX", "DownloadString")
QUERY
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"
  }

  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  action {
    action_groups = [azurerm_monitor_action_group.siem.id]
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Threat Intelligence Feed Integration
resource "azurerm_log_analytics_linked_storage_account" "threat_intel" {
  count               = var.enable_threat_intelligence ? 1 : 0
  data_source_type    = "CustomLogs"
  resource_group_name = var.resource_group_name
  workspace_resource_id = azurerm_log_analytics_workspace.siem.id
  storage_account_ids = [azurerm_storage_account.threat_intel[0].id]
}

resource "azurerm_storage_account" "threat_intel" {
  count                    = var.enable_threat_intelligence ? 1 : 0
  name                     = "${var.environment}threatintel"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
    Purpose     = "ThreatIntelligence"
  }
}

# Workbook for SIEM Dashboard
resource "azurerm_application_insights_workbook" "siem_dashboard" {
  name                = "siem-dashboard-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  display_name        = "${var.environment} SIEM Dashboard"

  data_json = jsonencode({
    version = "Notebook/1.0"
    items = [
      {
        type = 1
        content = {
          json = "# Security Operations Dashboard\n\nReal-time security monitoring and threat detection."
        }
        name = "header"
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query   = "SigninLogs | summarize count() by ResultType | render piechart"
          size    = 1
          title   = "Login Results"
        }
        name = "login-results"
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query   = "SecurityEvent | where EventID in (4624, 4625) | summarize count() by bin(TimeGenerated, 1h) | render timechart"
          size    = 1
          title   = "Authentication Events Over Time"
        }
        name = "auth-timeline"
      }
    ]
  })

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Outputs
output "siem_workspace_id" {
  description = "SIEM Log Analytics Workspace ID"
  value       = azurerm_log_analytics_workspace.siem.id
}

output "siem_workspace_name" {
  description = "SIEM Log Analytics Workspace name"
  value       = azurerm_log_analytics_workspace.siem.name
}

output "query_pack_id" {
  description = "Security Query Pack ID"
  value       = azurerm_log_analytics_query_pack.security.id
}

output "action_group_id" {
  description = "SIEM Action Group ID"
  value       = azurerm_monitor_action_group.siem.id
}

output "workbook_id" {
  description = "SIEM Dashboard Workbook ID"
  value       = azurerm_application_insights_workbook.siem_dashboard.id
}
