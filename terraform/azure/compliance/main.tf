# Azure Policy and Compliance Configuration
# Azure Policy, Regulatory Compliance, and Defender for Cloud

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

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics Workspace ID"
}

variable "enable_defender" {
  type        = bool
  description = "Enable Microsoft Defender for Cloud"
  default     = true
}

# Data Source for Subscription
data "azurerm_subscription" "current" {}

# Microsoft Defender for Cloud
resource "azurerm_security_center_subscription_pricing" "servers" {
  count         = var.enable_defender ? 1 : 0
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "storage" {
  count         = var.enable_defender ? 1 : 0
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "sql" {
  count         = var.enable_defender ? 1 : 0
  tier          = "Standard"
  resource_type = "SqlServers"
}

resource "azurerm_security_center_subscription_pricing" "app_services" {
  count         = var.enable_defender ? 1 : 0
  tier          = "Standard"
  resource_type = "AppServices"
}

resource "azurerm_security_center_subscription_pricing" "keyvaults" {
  count         = var.enable_defender ? 1 : 0
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "kubernetes" {
  count         = var.enable_defender ? 1 : 0
  tier          = "Standard"
  resource_type = "KubernetesService"
}

resource "azurerm_security_center_subscription_pricing" "containers" {
  count         = var.enable_defender ? 1 : 0
  tier          = "Standard"
  resource_type = "ContainerRegistry"
}

resource "azurerm_security_center_subscription_pricing" "arm" {
  count         = var.enable_defender ? 1 : 0
  tier          = "Standard"
  resource_type = "Arm"
}

resource "azurerm_security_center_subscription_pricing" "dns" {
  count         = var.enable_defender ? 1 : 0
  tier          = "Standard"
  resource_type = "Dns"
}

# Security Center Workspace
resource "azurerm_security_center_workspace" "main" {
  count        = var.enable_defender ? 1 : 0
  scope        = data.azurerm_subscription.current.id
  workspace_id = var.log_analytics_workspace_id
}

# Security Center Auto Provisioning
resource "azurerm_security_center_auto_provisioning" "main" {
  count          = var.enable_defender ? 1 : 0
  auto_provision = "On"
}

# Security Center Contact
resource "azurerm_security_center_contact" "main" {
  count               = var.enable_defender ? 1 : 0
  name                = "security-contact"
  email               = "security@example.com"
  phone               = "+1-555-0100"
  alert_notifications = true
  alerts_to_admins    = true
}

# Policy Definition - Require Encryption at Rest
resource "azurerm_policy_definition" "require_encryption" {
  name         = "${var.environment}-require-encryption"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Require encryption at rest"
  description  = "Ensures all storage resources have encryption enabled"

  metadata = jsonencode({
    category = "Security"
    version  = "1.0.0"
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field    = "Microsoft.Storage/storageAccounts/encryption.services.blob.enabled"
          notEquals = "true"
        }
      ]
    }
    then = {
      effect = "deny"
    }
  })
}

# Policy Definition - Require HTTPS
resource "azurerm_policy_definition" "require_https" {
  name         = "${var.environment}-require-https"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Require HTTPS for Storage Accounts"
  description  = "Ensures all storage accounts require HTTPS"

  metadata = jsonencode({
    category = "Security"
    version  = "1.0.0"
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field    = "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly"
          notEquals = "true"
        }
      ]
    }
    then = {
      effect = "deny"
    }
  })
}

# Policy Definition - Require TLS 1.2
resource "azurerm_policy_definition" "require_tls12" {
  name         = "${var.environment}-require-tls12"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Require TLS 1.2 minimum"
  description  = "Ensures all storage accounts use TLS 1.2 minimum"

  metadata = jsonencode({
    category = "Security"
    version  = "1.0.0"
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field    = "Microsoft.Storage/storageAccounts/minimumTlsVersion"
          notEquals = "TLS1_2"
        }
      ]
    }
    then = {
      effect = "deny"
    }
  })
}

# Policy Initiative (Policy Set)
resource "azurerm_policy_set_definition" "security_baseline" {
  name         = "${var.environment}-security-baseline"
  policy_type  = "Custom"
  display_name = "${var.environment} Security Baseline"
  description  = "Security baseline policies for ${var.environment} environment"

  metadata = jsonencode({
    category = "Security"
    version  = "1.0.0"
  })

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.require_encryption.id
    parameter_values     = "{}"
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.require_https.id
    parameter_values     = "{}"
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.require_tls12.id
    parameter_values     = "{}"
  }

  # Built-in: Audit VMs without disaster recovery
  policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/0015ea4d-51ff-4ce3-8d8c-f3f8f0179a56"
    parameter_values     = "{}"
  }

  # Built-in: Require tag on resources
  policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/871b6d14-10aa-478d-b590-94f262ecfa99"
    parameter_values = jsonencode({
      tagName = {
        value = "Environment"
      }
    })
  }
}

# Policy Assignment
resource "azurerm_subscription_policy_assignment" "security_baseline" {
  name                 = "${var.environment}-security-baseline"
  policy_definition_id = azurerm_policy_set_definition.security_baseline.id
  subscription_id      = data.azurerm_subscription.current.id
  display_name         = "${var.environment} Security Baseline Assignment"
  description          = "Assigns the security baseline policy initiative"
  enforce              = true

  non_compliance_message {
    content = "This resource is not compliant with the ${var.environment} security baseline."
  }
}

# Built-in Policy Assignments

# CIS Microsoft Azure Foundations Benchmark
resource "azurerm_subscription_policy_assignment" "cis_benchmark" {
  name                 = "${var.environment}-cis-benchmark"
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/1a5bb27d-173f-493e-9568-eb56638dde4d"
  subscription_id      = data.azurerm_subscription.current.id
  display_name         = "CIS Microsoft Azure Foundations Benchmark"
  description          = "CIS Microsoft Azure Foundations Benchmark compliance"

  non_compliance_message {
    content = "This resource does not meet CIS benchmark requirements."
  }
}

# Azure Security Benchmark
resource "azurerm_subscription_policy_assignment" "azure_security_benchmark" {
  name                 = "${var.environment}-asb"
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8"
  subscription_id      = data.azurerm_subscription.current.id
  display_name         = "Azure Security Benchmark"
  description          = "Azure Security Benchmark compliance"

  non_compliance_message {
    content = "This resource does not meet Azure Security Benchmark requirements."
  }
}

# Regulatory Compliance Assessment (requires Defender for Cloud)
resource "azurerm_security_center_assessment_policy" "custom_assessment" {
  count        = var.enable_defender ? 1 : 0
  display_name = "${var.environment} Custom Security Assessment"
  description  = "Custom security assessment for ${var.environment}"
  severity     = "Medium"
}

# Resource Graph Query for Compliance Status
locals {
  compliance_query = <<QUERY
policyresources
| where type == 'microsoft.policyinsights/policystates'
| where properties.complianceState == 'NonCompliant'
| summarize count() by tostring(properties.policyDefinitionName)
| order by count_ desc
QUERY
}

# Outputs
output "policy_initiative_id" {
  description = "Security baseline policy initiative ID"
  value       = azurerm_policy_set_definition.security_baseline.id
}

output "policy_assignment_id" {
  description = "Security baseline policy assignment ID"
  value       = azurerm_subscription_policy_assignment.security_baseline.id
}

output "cis_benchmark_assignment_id" {
  description = "CIS benchmark policy assignment ID"
  value       = azurerm_subscription_policy_assignment.cis_benchmark.id
}

output "azure_security_benchmark_assignment_id" {
  description = "Azure Security Benchmark policy assignment ID"
  value       = azurerm_subscription_policy_assignment.azure_security_benchmark.id
}

output "compliance_query" {
  description = "Resource Graph query for compliance status"
  value       = local.compliance_query
}
