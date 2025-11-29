# AWS Security Hub Configuration
# Centralized security posture management

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Variables
variable "environment" {
  type        = string
  description = "Environment name"
  default     = "production"
}

variable "enabled_standards" {
  type        = list(string)
  description = "List of security standards to enable"
  default = [
    "aws-foundational-security-best-practices",
    "cis-aws-foundations-benchmark"
  ]
}

variable "aggregation_region" {
  type        = string
  description = "Region for cross-region aggregation"
  default     = ""
}

# Enable Security Hub
resource "aws_securityhub_account" "main" {}

# AWS Foundational Security Best Practices
resource "aws_securityhub_standards_subscription" "aws_foundational" {
  count         = contains(var.enabled_standards, "aws-foundational-security-best-practices") ? 1 : 0
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

# CIS AWS Foundations Benchmark
resource "aws_securityhub_standards_subscription" "cis" {
  count         = contains(var.enabled_standards, "cis-aws-foundations-benchmark") ? 1 : 0
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/cis-aws-foundations-benchmark/v/1.4.0"
}

# PCI DSS
resource "aws_securityhub_standards_subscription" "pci_dss" {
  count         = contains(var.enabled_standards, "pci-dss") ? 1 : 0
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/pci-dss/v/3.2.1"
}

# NIST 800-53
resource "aws_securityhub_standards_subscription" "nist" {
  count         = contains(var.enabled_standards, "nist-800-53") ? 1 : 0
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/nist-800-53/v/5.0.0"
}

# Cross-Region Aggregation
resource "aws_securityhub_finding_aggregator" "main" {
  count        = var.aggregation_region != "" ? 1 : 0
  depends_on   = [aws_securityhub_account.main]
  linking_mode = "ALL_REGIONS"
}

# Custom Action for Automated Response
resource "aws_securityhub_action_target" "quarantine" {
  depends_on  = [aws_securityhub_account.main]
  name        = "Quarantine"
  identifier  = "Quarantine"
  description = "Quarantine compromised resources"
}

resource "aws_securityhub_action_target" "notify" {
  depends_on  = [aws_securityhub_account.main]
  name        = "NotifySecurityTeam"
  identifier  = "NotifySecurityTeam"
  description = "Send notification to security team"
}

# SNS Topic for Security Hub Findings
resource "aws_sns_topic" "security_hub_findings" {
  name = "${var.environment}-security-hub-findings"

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# SNS Topic Policy
resource "aws_sns_topic_policy" "security_hub_findings" {
  arn = aws_sns_topic.security_hub_findings.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSecurityHubPublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_hub_findings.arn
      }
    ]
  })
}

# EventBridge Rule for Critical Findings
resource "aws_cloudwatch_event_rule" "critical_findings" {
  name        = "${var.environment}-security-hub-critical"
  description = "Capture critical Security Hub findings"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL", "HIGH"]
        }
        Workflow = {
          Status = ["NEW"]
        }
      }
    }
  })

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# EventBridge Target
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.critical_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_hub_findings.arn
}

# Data Sources
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Outputs
output "security_hub_arn" {
  description = "ARN of Security Hub"
  value       = aws_securityhub_account.main.id
}

output "sns_topic_arn" {
  description = "ARN of SNS topic for findings"
  value       = aws_sns_topic.security_hub_findings.arn
}

output "quarantine_action_arn" {
  description = "ARN of quarantine action"
  value       = aws_securityhub_action_target.quarantine.arn
}
