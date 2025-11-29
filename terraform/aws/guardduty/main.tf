# AWS GuardDuty Terraform Module
# Threat Detection and Continuous Security Monitoring

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "project_name" {
  type        = string
  description = "Project name for resource naming"
}

variable "environment" {
  type        = string
  description = "Environment (dev, staging, prod)"
}

variable "enable_s3_protection" {
  type        = bool
  default     = true
  description = "Enable S3 Protection feature"
}

variable "enable_kubernetes_audit" {
  type        = bool
  default     = true
  description = "Enable EKS Audit Log Monitoring"
}

variable "enable_malware_protection" {
  type        = bool
  default     = true
  description = "Enable Malware Protection for EC2"
}

variable "enable_rds_protection" {
  type        = bool
  default     = true
  description = "Enable RDS Protection"
}

variable "enable_lambda_protection" {
  type        = bool
  default     = true
  description = "Enable Lambda Network Activity Monitoring"
}

variable "finding_publishing_frequency" {
  type        = string
  default     = "FIFTEEN_MINUTES"
  description = "Frequency of publishing findings (FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS)"
}

variable "threat_intel_set_urls" {
  type        = list(string)
  default     = []
  description = "List of URLs containing threat intelligence IP sets"
}

variable "trusted_ip_list_urls" {
  type        = list(string)
  default     = []
  description = "List of URLs containing trusted IP addresses"
}

variable "sns_topic_arn" {
  type        = string
  default     = ""
  description = "SNS topic ARN for GuardDuty alerts"
}

locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Service     = "guardduty"
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# GuardDuty Detector
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = var.finding_publishing_frequency

  datasources {
    s3_logs {
      enable = var.enable_s3_protection
    }

    kubernetes {
      audit_logs {
        enable = var.enable_kubernetes_audit
      }
    }

    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.enable_malware_protection
        }
      }
    }
  }

  tags = local.common_tags
}

# Enable RDS Protection (separate resource in newer provider)
resource "aws_guardduty_detector_feature" "rds_login_events" {
  count = var.enable_rds_protection ? 1 : 0

  detector_id = aws_guardduty_detector.main.id
  name        = "RDS_LOGIN_EVENTS"
  status      = "ENABLED"
}

# Enable Lambda Network Activity Monitoring
resource "aws_guardduty_detector_feature" "lambda_network_logs" {
  count = var.enable_lambda_protection ? 1 : 0

  detector_id = aws_guardduty_detector.main.id
  name        = "LAMBDA_NETWORK_LOGS"
  status      = "ENABLED"
}

# Enable Runtime Monitoring for ECS/EKS
resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "ENABLED"
  }

  additional_configuration {
    name   = "ECS_FARGATE_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
}

# S3 Bucket for GuardDuty Findings Export
resource "aws_s3_bucket" "findings" {
  bucket = "${var.project_name}-guardduty-findings-${var.environment}-${data.aws_caller_identity.current.account_id}"
  tags   = local.common_tags
}

resource "aws_s3_bucket_versioning" "findings" {
  bucket = aws_s3_bucket.findings.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "findings" {
  bucket = aws_s3_bucket.findings.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.guardduty.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "findings" {
  bucket = aws_s3_bucket.findings.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "findings" {
  bucket = aws_s3_bucket.findings.id

  rule {
    id     = "archive-findings"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

# KMS Key for GuardDuty
resource "aws_kms_key" "guardduty" {
  description             = "KMS key for GuardDuty findings encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow GuardDuty to use the key"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Encrypt"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_alias" "guardduty" {
  name          = "alias/${var.project_name}-guardduty-${var.environment}"
  target_key_id = aws_kms_key.guardduty.key_id
}

# S3 Bucket Policy for GuardDuty
resource "aws_s3_bucket_policy" "findings" {
  bucket = aws_s3_bucket.findings.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGuardDutyGetBucketLocation"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "s3:GetBucketLocation"
        Resource = aws_s3_bucket.findings.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowGuardDutyPutObject"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.findings.arn}/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid       = "DenyUnencryptedTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.findings.arn,
          "${aws_s3_bucket.findings.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# GuardDuty Publishing Destination
resource "aws_guardduty_publishing_destination" "s3" {
  detector_id     = aws_guardduty_detector.main.id
  destination_arn = aws_s3_bucket.findings.arn
  kms_key_arn     = aws_kms_key.guardduty.arn

  depends_on = [aws_s3_bucket_policy.findings]
}

# Threat Intelligence Sets
resource "aws_guardduty_threatintelset" "threat_intel" {
  count = length(var.threat_intel_set_urls)

  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = var.threat_intel_set_urls[count.index]
  name        = "${var.project_name}-threat-intel-${count.index}"

  tags = local.common_tags
}

# Trusted IP Sets
resource "aws_guardduty_ipset" "trusted" {
  count = length(var.trusted_ip_list_urls)

  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = var.trusted_ip_list_urls[count.index]
  name        = "${var.project_name}-trusted-ips-${count.index}"

  tags = local.common_tags
}

# GuardDuty Filter for Suppression (Low Severity)
resource "aws_guardduty_filter" "suppress_low_severity" {
  detector_id = aws_guardduty_detector.main.id
  name        = "suppress-low-severity"
  action      = "ARCHIVE"
  rank        = 1

  finding_criteria {
    criterion {
      field  = "severity"
      less_than = "4"  # Low severity
    }
  }

  tags = local.common_tags
}

# CloudWatch Event Rule for High Severity Findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.project_name}-guardduty-findings-${var.environment}"
  description = "Capture GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [
        { numeric = [">=", 7] }  # High and Critical
      ]
    }
  })

  tags = local.common_tags
}

# CloudWatch Event Target - SNS (if provided)
resource "aws_cloudwatch_event_target" "sns" {
  count = var.sns_topic_arn != "" ? 1 : 0

  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "send-to-sns"
  arn       = var.sns_topic_arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      finding     = "$.detail.type"
      description = "$.detail.description"
      account     = "$.detail.accountId"
      region      = "$.detail.region"
      time        = "$.detail.service.eventFirstSeen"
    }
    input_template = <<EOF
{
  "alert": "GuardDuty Finding",
  "severity": <severity>,
  "finding": <finding>,
  "description": <description>,
  "account": <account>,
  "region": <region>,
  "time": <time>
}
EOF
  }
}

# CloudWatch Metric Alarms
resource "aws_cloudwatch_metric_alarm" "high_severity_findings" {
  alarm_name          = "${var.project_name}-guardduty-high-severity-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HighSeverityFindings"
  namespace           = "GuardDuty"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "High severity GuardDuty findings detected"

  dimensions = {
    DetectorId = aws_guardduty_detector.main.id
  }

  alarm_actions = var.sns_topic_arn != "" ? [var.sns_topic_arn] : []

  tags = local.common_tags
}

# Lambda for Custom Finding Processing (optional)
resource "aws_lambda_function" "finding_processor" {
  filename         = "${path.module}/finding_processor.zip"
  function_name    = "${var.project_name}-guardduty-processor-${var.environment}"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  source_code_hash = filebase64sha256("${path.module}/finding_processor.zip")
  runtime          = "python3.11"
  timeout          = 60

  environment {
    variables = {
      ENVIRONMENT = var.environment
      SNS_TOPIC   = var.sns_topic_arn
    }
  }

  tags = local.common_tags
}

resource "aws_iam_role" "lambda" {
  name = "${var.project_name}-guardduty-lambda-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "send-to-lambda"
  arn       = aws_lambda_function.finding_processor.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.finding_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}

# Outputs
output "detector_id" {
  value       = aws_guardduty_detector.main.id
  description = "GuardDuty Detector ID"
}

output "findings_bucket" {
  value       = aws_s3_bucket.findings.bucket
  description = "S3 bucket for GuardDuty findings"
}

output "kms_key_arn" {
  value       = aws_kms_key.guardduty.arn
  description = "KMS key ARN for GuardDuty"
}

output "event_rule_arn" {
  value       = aws_cloudwatch_event_rule.guardduty_findings.arn
  description = "CloudWatch Event Rule ARN for GuardDuty findings"
}
