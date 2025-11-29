# Azure Identity and Access Management Configuration
# Azure AD, RBAC, and Conditional Access

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.0"
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

variable "admin_group_name" {
  type        = string
  description = "Name of the admin group"
  default     = "Security-Administrators"
}

variable "security_group_name" {
  type        = string
  description = "Name of the security team group"
  default     = "Security-Team"
}

# Data Sources
data "azuread_client_config" "current" {}
data "azurerm_subscription" "current" {}

# Security Administrators Group
resource "azuread_group" "security_admins" {
  display_name     = var.admin_group_name
  security_enabled = true
  description      = "Security administrators with elevated privileges"

  owners = [data.azuread_client_config.current.object_id]
}

# Security Team Group
resource "azuread_group" "security_team" {
  display_name     = var.security_group_name
  security_enabled = true
  description      = "Security team members"

  owners = [data.azuread_client_config.current.object_id]
}

# Break Glass Account
resource "azuread_user" "break_glass" {
  user_principal_name = "break-glass@${data.azuread_client_config.current.tenant_id}.onmicrosoft.com"
  display_name        = "Break Glass Account"
  password            = random_password.break_glass.result

  account_enabled = true
  show_in_address_list = false
}

resource "random_password" "break_glass" {
  length           = 32
  special          = true
  override_special = "!@#$%^&*"
}

# Custom Security Reader Role
resource "azurerm_role_definition" "security_reader" {
  name        = "${var.environment}-security-reader"
  scope       = data.azurerm_subscription.current.id
  description = "Security reader with access to security-related resources"

  permissions {
    actions = [
      "Microsoft.Security/*/read",
      "Microsoft.Authorization/*/read",
      "Microsoft.Insights/alertRules/read",
      "Microsoft.Insights/diagnosticSettings/read",
      "Microsoft.OperationalInsights/workspaces/read",
      "Microsoft.OperationalInsights/workspaces/query/read",
      "Microsoft.Resources/subscriptions/resourceGroups/read",
      "Microsoft.Network/networkSecurityGroups/read",
      "Microsoft.Network/applicationSecurityGroups/read",
      "Microsoft.KeyVault/vaults/read"
    ]
    not_actions = []
  }

  assignable_scopes = [
    data.azurerm_subscription.current.id
  ]
}

# Custom Security Analyst Role
resource "azurerm_role_definition" "security_analyst" {
  name        = "${var.environment}-security-analyst"
  scope       = data.azurerm_subscription.current.id
  description = "Security analyst with investigation capabilities"

  permissions {
    actions = [
      "Microsoft.Security/*/read",
      "Microsoft.Security/securityStatuses/read",
      "Microsoft.Security/alerts/read",
      "Microsoft.Authorization/*/read",
      "Microsoft.Insights/alertRules/*",
      "Microsoft.Insights/diagnosticSettings/*",
      "Microsoft.OperationalInsights/workspaces/*",
      "Microsoft.Sentinel/*",
      "Microsoft.Resources/subscriptions/resourceGroups/read",
      "Microsoft.Network/networkSecurityGroups/read",
      "Microsoft.Network/networkWatchers/*",
      "Microsoft.KeyVault/vaults/read"
    ]
    not_actions = []
  }

  assignable_scopes = [
    data.azurerm_subscription.current.id
  ]
}

# Role Assignment - Security Team
resource "azurerm_role_assignment" "security_team_reader" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Security Reader"
  principal_id         = azuread_group.security_team.object_id
}

resource "azurerm_role_assignment" "security_team_analyst" {
  scope                = data.azurerm_subscription.current.id
  role_definition_id   = azurerm_role_definition.security_analyst.role_definition_resource_id
  principal_id         = azuread_group.security_team.object_id
}

# Role Assignment - Security Admins
resource "azurerm_role_assignment" "security_admins" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Security Admin"
  principal_id         = azuread_group.security_admins.object_id
}

# Conditional Access Policy - Require MFA for Admins
resource "azuread_conditional_access_policy" "require_mfa_admins" {
  display_name = "${var.environment}-require-mfa-admins"
  state        = "enabled"

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_groups = [azuread_group.security_admins.object_id]
    }

    locations {
      included_locations = ["All"]
    }
  }

  grant_controls {
    operator                          = "OR"
    built_in_controls                 = ["mfa"]
  }
}

# Conditional Access Policy - Block Legacy Authentication
resource "azuread_conditional_access_policy" "block_legacy_auth" {
  display_name = "${var.environment}-block-legacy-auth"
  state        = "enabled"

  conditions {
    client_app_types = ["exchangeActiveSync", "other"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = [azuread_user.break_glass.object_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# Conditional Access Policy - Require Compliant Device
resource "azuread_conditional_access_policy" "require_compliant_device" {
  display_name = "${var.environment}-require-compliant-device"
  state        = "enabled"

  conditions {
    client_app_types = ["browser", "mobileAppsAndDesktopClients"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = [azuread_user.break_glass.object_id]
    }

    platforms {
      included_platforms = ["windows", "macOS", "iOS", "android"]
    }
  }

  grant_controls {
    operator                          = "OR"
    built_in_controls                 = ["compliantDevice", "domainJoinedDevice"]
  }
}

# Conditional Access Policy - Block Risky Sign-ins
resource "azuread_conditional_access_policy" "block_risky_signin" {
  display_name = "${var.environment}-block-risky-signin"
  state        = "enabled"

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = [azuread_user.break_glass.object_id]
    }

    sign_in_risk_levels = ["high"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# Conditional Access Policy - Require MFA for Risky Sign-ins
resource "azuread_conditional_access_policy" "mfa_risky_signin" {
  display_name = "${var.environment}-mfa-risky-signin"
  state        = "enabled"

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = [azuread_user.break_glass.object_id]
    }

    sign_in_risk_levels = ["medium"]
  }

  grant_controls {
    operator                          = "OR"
    built_in_controls                 = ["mfa"]
  }
}

# Named Location - Corporate Network
resource "azuread_named_location" "corporate" {
  display_name = "${var.environment}-corporate-network"

  ip {
    ip_ranges = ["203.0.113.0/24"]  # Replace with actual corporate IP ranges
    trusted   = true
  }
}

# Directory Role - Global Reader Assignment
resource "azuread_directory_role" "global_reader" {
  display_name = "Global Reader"
}

resource "azuread_directory_role_assignment" "security_team_global_reader" {
  role_id             = azuread_directory_role.global_reader.template_id
  principal_object_id = azuread_group.security_team.object_id
}

# Privileged Identity Management Settings
resource "azuread_group_role_management_policy" "security_admin_policy" {
  group_id = azuread_group.security_admins.id
  role_id  = "member"

  activation_rules {
    maximum_duration = "PT8H"
    require_approval = true
    require_justification = true
    require_multifactor_authentication = true
  }

  notification_rules {
    eligible_assignments {
      admin_notifications {
        notification_level    = "All"
        default_recipients    = true
      }
    }
    active_assignments {
      admin_notifications {
        notification_level    = "All"
        default_recipients    = true
      }
    }
  }
}

# Outputs
output "security_admins_group_id" {
  description = "Security Administrators group object ID"
  value       = azuread_group.security_admins.object_id
}

output "security_team_group_id" {
  description = "Security Team group object ID"
  value       = azuread_group.security_team.object_id
}

output "break_glass_user_id" {
  description = "Break Glass account object ID"
  value       = azuread_user.break_glass.object_id
  sensitive   = true
}

output "security_reader_role_id" {
  description = "Security Reader custom role ID"
  value       = azurerm_role_definition.security_reader.role_definition_id
}

output "security_analyst_role_id" {
  description = "Security Analyst custom role ID"
  value       = azurerm_role_definition.security_analyst.role_definition_id
}
