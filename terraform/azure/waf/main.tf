# Azure Web Application Firewall Configuration
# Application Gateway with WAF and Front Door WAF

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

variable "subnet_id" {
  type        = string
  description = "Subnet ID for Application Gateway"
}

variable "waf_mode" {
  type        = string
  description = "WAF mode (Detection or Prevention)"
  default     = "Prevention"
}

variable "backend_fqdns" {
  type        = list(string)
  description = "Backend FQDNs for the application"
  default     = []
}

# Public IP for Application Gateway
resource "azurerm_public_ip" "appgw" {
  name                = "${var.environment}-appgw-pip"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# WAF Policy
resource "azurerm_web_application_firewall_policy" "main" {
  name                = "${var.environment}-waf-policy"
  location            = var.location
  resource_group_name = var.resource_group_name

  policy_settings {
    enabled                     = true
    mode                        = var.waf_mode
    request_body_check          = true
    file_upload_limit_in_mb     = 100
    max_request_body_size_in_kb = 128
  }

  managed_rules {
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
    }

    managed_rule_set {
      type    = "Microsoft_BotManagerRuleSet"
      version = "1.0"
    }
  }

  custom_rules {
    name      = "BlockHighRiskCountries"
    priority  = 1
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "RemoteAddr"
      }
      operator           = "GeoMatch"
      negation_condition = false
      match_values       = ["CN", "RU", "KP", "IR"]
    }
  }

  custom_rules {
    name      = "RateLimitRule"
    priority  = 2
    rule_type = "RateLimitRule"
    action    = "Block"

    rate_limit_duration_in_minutes = 1
    rate_limit_threshold           = 100

    match_conditions {
      match_variables {
        variable_name = "RemoteAddr"
      }
      operator           = "IPMatch"
      negation_condition = true
      match_values       = ["10.0.0.0/8"]
    }
  }

  custom_rules {
    name      = "BlockSQLInjection"
    priority  = 3
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "QueryString"
      }
      operator           = "Contains"
      negation_condition = false
      match_values       = ["SELECT", "UNION", "DROP", "INSERT", "DELETE", "UPDATE", "--", "/*"]
      transforms         = ["UrlDecode", "Lowercase"]
    }
  }

  custom_rules {
    name      = "BlockXSS"
    priority  = 4
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "QueryString"
      }
      operator           = "Contains"
      negation_condition = false
      match_values       = ["<script>", "javascript:", "onerror=", "onload="]
      transforms         = ["UrlDecode", "Lowercase"]
    }
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Application Gateway with WAF
resource "azurerm_application_gateway" "main" {
  name                = "${var.environment}-appgw"
  location            = var.location
  resource_group_name = var.resource_group_name
  firewall_policy_id  = azurerm_web_application_firewall_policy.main.id

  sku {
    name     = "WAF_v2"
    tier     = "WAF_v2"
    capacity = 2
  }

  gateway_ip_configuration {
    name      = "gateway-ip-config"
    subnet_id = var.subnet_id
  }

  frontend_port {
    name = "https-port"
    port = 443
  }

  frontend_port {
    name = "http-port"
    port = 80
  }

  frontend_ip_configuration {
    name                 = "frontend-ip"
    public_ip_address_id = azurerm_public_ip.appgw.id
  }

  backend_address_pool {
    name  = "backend-pool"
    fqdns = var.backend_fqdns
  }

  backend_http_settings {
    name                  = "http-settings"
    cookie_based_affinity = "Disabled"
    port                  = 443
    protocol              = "Https"
    request_timeout       = 60
    probe_name            = "health-probe"

    pick_host_name_from_backend_address = true
  }

  probe {
    name                                      = "health-probe"
    protocol                                  = "Https"
    path                                      = "/health"
    interval                                  = 30
    timeout                                   = 30
    unhealthy_threshold                       = 3
    pick_host_name_from_backend_http_settings = true
  }

  http_listener {
    name                           = "https-listener"
    frontend_ip_configuration_name = "frontend-ip"
    frontend_port_name             = "https-port"
    protocol                       = "Https"
    ssl_certificate_name           = "ssl-cert"
  }

  http_listener {
    name                           = "http-listener"
    frontend_ip_configuration_name = "frontend-ip"
    frontend_port_name             = "http-port"
    protocol                       = "Http"
  }

  ssl_certificate {
    name     = "ssl-cert"
    data     = filebase64("${path.module}/cert.pfx")
    password = var.ssl_cert_password
  }

  request_routing_rule {
    name                       = "https-rule"
    priority                   = 100
    rule_type                  = "Basic"
    http_listener_name         = "https-listener"
    backend_address_pool_name  = "backend-pool"
    backend_http_settings_name = "http-settings"
  }

  redirect_configuration {
    name                 = "http-to-https"
    redirect_type        = "Permanent"
    target_listener_name = "https-listener"
    include_path         = true
    include_query_string = true
  }

  request_routing_rule {
    name                        = "http-redirect-rule"
    priority                    = 200
    rule_type                   = "Basic"
    http_listener_name          = "http-listener"
    redirect_configuration_name = "http-to-https"
  }

  ssl_policy {
    policy_type = "Predefined"
    policy_name = "AppGwSslPolicy20220101S"
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

variable "ssl_cert_password" {
  type        = string
  description = "SSL certificate password"
  sensitive   = true
  default     = ""
}

# Diagnostic Settings
resource "azurerm_monitor_diagnostic_setting" "appgw" {
  name                       = "${var.environment}-appgw-diagnostics"
  target_resource_id         = azurerm_application_gateway.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "ApplicationGatewayAccessLog"
  }

  enabled_log {
    category = "ApplicationGatewayPerformanceLog"
  }

  enabled_log {
    category = "ApplicationGatewayFirewallLog"
  }

  metric {
    category = "AllMetrics"
  }
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics Workspace ID"
  default     = ""
}

# Outputs
output "application_gateway_id" {
  description = "Application Gateway ID"
  value       = azurerm_application_gateway.main.id
}

output "public_ip_address" {
  description = "Application Gateway public IP"
  value       = azurerm_public_ip.appgw.ip_address
}

output "waf_policy_id" {
  description = "WAF Policy ID"
  value       = azurerm_web_application_firewall_policy.main.id
}
