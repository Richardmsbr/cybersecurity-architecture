# GCP Cloud Armor Configuration
# Web Application Firewall and DDoS Protection

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

variable "rate_limit_threshold" {
  type        = number
  description = "Rate limit threshold per minute"
  default     = 1000
}

variable "blocked_countries" {
  type        = list(string)
  description = "List of country codes to block"
  default     = []
}

variable "whitelisted_ips" {
  type        = list(string)
  description = "List of IPs to whitelist"
  default     = []
}

# Cloud Armor Security Policy
resource "google_compute_security_policy" "main" {
  project     = var.project_id
  name        = "${var.environment}-security-policy"
  description = "Cloud Armor security policy for ${var.environment}"

  # Adaptive Protection
  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable          = true
      rule_visibility = "STANDARD"
    }
  }

  # Default Rule - Allow
  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default rule - allow all"
  }

  # Whitelist Rule
  dynamic "rule" {
    for_each = length(var.whitelisted_ips) > 0 ? [1] : []
    content {
      action   = "allow"
      priority = "100"
      match {
        versioned_expr = "SRC_IPS_V1"
        config {
          src_ip_ranges = var.whitelisted_ips
        }
      }
      description = "Whitelist trusted IPs"
    }
  }

  # Block Countries Rule
  dynamic "rule" {
    for_each = length(var.blocked_countries) > 0 ? [1] : []
    content {
      action   = "deny(403)"
      priority = "200"
      match {
        expr {
          expression = "origin.region_code in [${join(",", [for c in var.blocked_countries : "'${c}'"])}]"
        }
      }
      description = "Block traffic from restricted countries"
    }
  }

  # OWASP Top 10 - SQL Injection
  rule {
    action   = "deny(403)"
    priority = "1000"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
      }
    }
    description = "SQL Injection protection (OWASP)"
  }

  # OWASP Top 10 - XSS
  rule {
    action   = "deny(403)"
    priority = "1001"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
      }
    }
    description = "Cross-site scripting protection (OWASP)"
  }

  # OWASP Top 10 - Local File Inclusion
  rule {
    action   = "deny(403)"
    priority = "1002"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('lfi-v33-stable')"
      }
    }
    description = "Local file inclusion protection (OWASP)"
  }

  # OWASP Top 10 - Remote File Inclusion
  rule {
    action   = "deny(403)"
    priority = "1003"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rfi-v33-stable')"
      }
    }
    description = "Remote file inclusion protection (OWASP)"
  }

  # OWASP Top 10 - Remote Code Execution
  rule {
    action   = "deny(403)"
    priority = "1004"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rce-v33-stable')"
      }
    }
    description = "Remote code execution protection (OWASP)"
  }

  # OWASP Top 10 - Method Enforcement
  rule {
    action   = "deny(403)"
    priority = "1005"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('methodenforcement-v33-stable')"
      }
    }
    description = "Method enforcement protection (OWASP)"
  }

  # OWASP Top 10 - Scanner Detection
  rule {
    action   = "deny(403)"
    priority = "1006"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('scannerdetection-v33-stable')"
      }
    }
    description = "Scanner detection protection (OWASP)"
  }

  # OWASP Top 10 - Protocol Attack
  rule {
    action   = "deny(403)"
    priority = "1007"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('protocolattack-v33-stable')"
      }
    }
    description = "Protocol attack protection (OWASP)"
  }

  # OWASP Top 10 - Session Fixation
  rule {
    action   = "deny(403)"
    priority = "1008"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sessionfixation-v33-stable')"
      }
    }
    description = "Session fixation protection (OWASP)"
  }

  # Log4j CVE-2021-44228
  rule {
    action   = "deny(403)"
    priority = "1010"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('cve-canary')"
      }
    }
    description = "CVE protection (Log4j and others)"
  }

  # Rate Limiting Rule
  rule {
    action   = "rate_based_ban"
    priority = "2000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = var.rate_limit_threshold
        interval_sec = 60
      }
      ban_duration_sec = 300
    }
    description = "Rate limiting - ${var.rate_limit_threshold} requests per minute"
  }

  # Bot Management - Known Bots
  rule {
    action   = "deny(403)"
    priority = "3000"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rce-v33-stable') && !has(request.headers['user-agent'])"
      }
    }
    description = "Block requests without User-Agent"
  }
}

# Edge Security Policy (for CDN)
resource "google_compute_security_policy" "edge" {
  project     = var.project_id
  name        = "${var.environment}-edge-security-policy"
  description = "Edge security policy for CDN"
  type        = "CLOUD_ARMOR_EDGE"

  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default rule"
  }

  # Rate limiting for edge
  rule {
    action   = "throttle"
    priority = "1000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = 10000
        interval_sec = 60
      }
    }
    description = "Edge rate limiting"
  }
}

# reCAPTCHA Enterprise Integration (if needed)
# resource "google_recaptcha_enterprise_key" "primary" {
#   project      = var.project_id
#   display_name = "${var.environment}-recaptcha-key"
#   web_settings {
#     integration_type  = "SCORE"
#     allow_all_domains = false
#     allowed_domains   = ["example.com"]
#   }
# }

# Outputs
output "security_policy_id" {
  description = "Cloud Armor security policy ID"
  value       = google_compute_security_policy.main.id
}

output "security_policy_name" {
  description = "Cloud Armor security policy name"
  value       = google_compute_security_policy.main.name
}

output "security_policy_self_link" {
  description = "Cloud Armor security policy self link"
  value       = google_compute_security_policy.main.self_link
}

output "edge_security_policy_id" {
  description = "Edge security policy ID"
  value       = google_compute_security_policy.edge.id
}
