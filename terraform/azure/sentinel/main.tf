# Azure Sentinel Configuration
# Cloud-native SIEM and SOAR

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
  description = "Log Analytics retention in days"
  default     = 90
}

variable "enable_ueba" {
  type        = bool
  description = "Enable User and Entity Behavior Analytics"
  default     = true
}

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "sentinel" {
  name                = "${var.environment}-sentinel-workspace"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Sentinel Solution
resource "azurerm_log_analytics_solution" "sentinel" {
  solution_name         = "SecurityInsights"
  location              = var.location
  resource_group_name   = var.resource_group_name
  workspace_resource_id = azurerm_log_analytics_workspace.sentinel.id
  workspace_name        = azurerm_log_analytics_workspace.sentinel.name

  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/SecurityInsights"
  }
}

# Sentinel Onboarding
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "main" {
  workspace_id                 = azurerm_log_analytics_workspace.sentinel.id
  customer_managed_key_enabled = false
}

# Azure Active Directory Data Connector
resource "azurerm_sentinel_data_connector_azure_active_directory" "main" {
  name                       = "azure-ad-connector"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
}

# Microsoft Defender for Cloud Data Connector
resource "azurerm_sentinel_data_connector_microsoft_defender_advanced_threat_protection" "main" {
  name                       = "defender-atp-connector"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
}

# Office 365 Data Connector
resource "azurerm_sentinel_data_connector_office_365" "main" {
  name                       = "office365-connector"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  exchange_enabled           = true
  sharepoint_enabled         = true
  teams_enabled              = true
}

# Azure Activity Data Connector
resource "azurerm_sentinel_data_connector_azure_security_center" "main" {
  name                       = "azure-security-center-connector"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
}

# Threat Intelligence Data Connector
resource "azurerm_sentinel_data_connector_threat_intelligence" "main" {
  name                       = "threat-intel-connector"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
}

# UEBA Settings
resource "azurerm_sentinel_alert_rule_machine_learning_behavior_analytics" "ueba" {
  count                      = var.enable_ueba ? 1 : 0
  name                       = "ueba-analytics"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  alert_rule_template_guid   = "fa118b98-de46-4e94-87f9-8e6d5c157b7c"
}

# Analytics Rules - Brute Force Attack
resource "azurerm_sentinel_alert_rule_scheduled" "brute_force" {
  name                       = "brute-force-detection"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  display_name               = "Brute Force Attack Detection"
  severity                   = "High"
  query                      = <<QUERY
SigninLogs
| where ResultType == "50126"
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
QUERY

  query_frequency = "PT5M"
  query_period    = "PT5M"
  trigger_operator = "GreaterThan"
  trigger_threshold = 0

  tactics = ["CredentialAccess"]
  techniques = ["T1110"]
}

# Analytics Rules - Impossible Travel
resource "azurerm_sentinel_alert_rule_scheduled" "impossible_travel" {
  name                       = "impossible-travel"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  display_name               = "Impossible Travel Activity"
  severity                   = "Medium"
  query                      = <<QUERY
SigninLogs
| where ResultType == 0
| summarize Locations = make_set(Location), LoginTimes = make_list(TimeGenerated) by UserPrincipalName
| where array_length(Locations) > 1
QUERY

  query_frequency = "PT1H"
  query_period    = "PT24H"
  trigger_operator = "GreaterThan"
  trigger_threshold = 0

  tactics = ["InitialAccess"]
  techniques = ["T1078"]
}

# Analytics Rules - Suspicious PowerShell
resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_powershell" {
  name                       = "suspicious-powershell"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  display_name               = "Suspicious PowerShell Command"
  severity                   = "High"
  query                      = <<QUERY
SecurityEvent
| where EventID == 4688
| where Process has "powershell.exe"
| where CommandLine has_any ("Invoke-Expression", "IEX", "DownloadString", "EncodedCommand", "-enc")
QUERY

  query_frequency = "PT5M"
  query_period    = "PT5M"
  trigger_operator = "GreaterThan"
  trigger_threshold = 0

  tactics = ["Execution"]
  techniques = ["T1059"]
}

# Analytics Rules - Privilege Escalation
resource "azurerm_sentinel_alert_rule_scheduled" "privilege_escalation" {
  name                       = "privilege-escalation"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  display_name               = "Privilege Escalation Attempt"
  severity                   = "High"
  query                      = <<QUERY
AuditLogs
| where OperationName has_any ("Add member to role", "Add eligible member to role")
| where Result == "success"
| extend RoleName = tostring(TargetResources[0].displayName)
| where RoleName has_any ("Global Administrator", "Privileged Role Administrator", "Security Administrator")
QUERY

  query_frequency = "PT5M"
  query_period    = "PT5M"
  trigger_operator = "GreaterThan"
  trigger_threshold = 0

  tactics = ["PrivilegeEscalation"]
  techniques = ["T1078"]
}

# Watchlist for High Value Assets
resource "azurerm_sentinel_watchlist" "high_value_assets" {
  name                       = "high-value-assets"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  display_name               = "High Value Assets"
  item_search_key            = "AssetName"
}

# Watchlist for VIP Users
resource "azurerm_sentinel_watchlist" "vip_users" {
  name                       = "vip-users"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  display_name               = "VIP Users"
  item_search_key            = "UserPrincipalName"
}

# Automation Rule for High Severity Incidents
resource "azurerm_sentinel_automation_rule" "high_severity" {
  name                       = "auto-high-severity"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.main.workspace_id
  display_name               = "Auto-assign High Severity Incidents"
  order                      = 1
  enabled                    = true

  condition_json = jsonencode({
    conditions = [
      {
        conditionType = "Property"
        conditionProperties = {
          propertyName  = "IncidentSeverity"
          operator      = "Equals"
          propertyValues = ["High"]
        }
      }
    ]
  })

  action_incident {
    order  = 1
    status = "Active"
  }
}

# Outputs
output "workspace_id" {
  description = "Log Analytics Workspace ID"
  value       = azurerm_log_analytics_workspace.sentinel.id
}

output "workspace_name" {
  description = "Log Analytics Workspace name"
  value       = azurerm_log_analytics_workspace.sentinel.name
}

output "sentinel_onboarding_id" {
  description = "Sentinel onboarding ID"
  value       = azurerm_sentinel_log_analytics_workspace_onboarding.main.id
}
