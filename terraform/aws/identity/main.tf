# AWS IAM Security Configuration
# Identity and Access Management best practices

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

variable "password_policy" {
  type = object({
    minimum_length                   = number
    require_lowercase                = bool
    require_uppercase                = bool
    require_numbers                  = bool
    require_symbols                  = bool
    allow_users_to_change_password   = bool
    max_password_age                 = number
    password_reuse_prevention        = number
    hard_expiry                      = bool
  })
  description = "IAM password policy settings"
  default = {
    minimum_length                   = 14
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    allow_users_to_change_password   = true
    max_password_age                 = 90
    password_reuse_prevention        = 24
    hard_expiry                      = false
  }
}

variable "mfa_required_groups" {
  type        = list(string)
  description = "Groups that require MFA"
  default     = ["Administrators", "Developers", "SecurityTeam"]
}

# Account Password Policy
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = var.password_policy.minimum_length
  require_lowercase_characters   = var.password_policy.require_lowercase
  require_uppercase_characters   = var.password_policy.require_uppercase
  require_numbers                = var.password_policy.require_numbers
  require_symbols                = var.password_policy.require_symbols
  allow_users_to_change_password = var.password_policy.allow_users_to_change_password
  max_password_age               = var.password_policy.max_password_age
  password_reuse_prevention      = var.password_policy.password_reuse_prevention
  hard_expiry                    = var.password_policy.hard_expiry
}

# Security Team Role
resource "aws_iam_role" "security_team" {
  name = "${var.environment}-security-team-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Security Team Policy
resource "aws_iam_role_policy" "security_team" {
  name = "${var.environment}-security-team-policy"
  role = aws_iam_role.security_team.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecurityHubAccess"
        Effect = "Allow"
        Action = [
          "securityhub:*",
          "guardduty:*",
          "inspector2:*",
          "detective:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudTrailAccess"
        Effect = "Allow"
        Action = [
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:LookupEvents",
          "cloudtrail:ListTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "ConfigAccess"
        Effect = "Allow"
        Action = [
          "config:Describe*",
          "config:Get*",
          "config:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMAudit"
        Effect = "Allow"
        Action = [
          "iam:Get*",
          "iam:List*",
          "iam:GenerateCredentialReport",
          "iam:GenerateServiceLastAccessedDetails"
        ]
        Resource = "*"
      },
      {
        Sid    = "LogsAccess"
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:GetLogEvents",
          "logs:FilterLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# Break Glass Emergency Role
resource "aws_iam_role" "break_glass" {
  name = "${var.environment}-break-glass-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
          StringEquals = {
            "aws:PrincipalTag/SecurityClearance" = "break-glass"
          }
        }
      }
    ]
  })

  max_session_duration = 3600

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
    Purpose     = "Emergency access only"
  }
}

# Break Glass Policy - Administrator Access
resource "aws_iam_role_policy_attachment" "break_glass_admin" {
  role       = aws_iam_role.break_glass.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# MFA Enforcement Policy
resource "aws_iam_policy" "mfa_enforcement" {
  name        = "${var.environment}-mfa-enforcement"
  description = "Enforces MFA for all actions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowViewAccountInfo"
        Effect = "Allow"
        Action = [
          "iam:GetAccountPasswordPolicy",
          "iam:ListVirtualMFADevices"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowManageOwnVirtualMFADevice"
        Effect = "Allow"
        Action = [
          "iam:CreateVirtualMFADevice",
          "iam:DeleteVirtualMFADevice"
        ]
        Resource = "arn:aws:iam::*:mfa/$${aws:username}"
      },
      {
        Sid    = "AllowManageOwnUserMFA"
        Effect = "Allow"
        Action = [
          "iam:DeactivateMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ResyncMFADevice"
        ]
        Resource = "arn:aws:iam::*:user/$${aws:username}"
      },
      {
        Sid    = "DenyAllExceptListedIfNoMFA"
        Effect = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken",
          "iam:ChangePassword"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Deny Root Account Usage Policy
resource "aws_iam_policy" "deny_root" {
  name        = "${var.environment}-deny-root-usage"
  description = "Alerts on root account usage"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyRootAccountUsage"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:PrincipalArn" = "arn:aws:iam::*:root"
          }
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Service Control Policy for Organization (if applicable)
locals {
  scp_deny_leave_organization = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyLeaveOrganization"
        Effect   = "Deny"
        Action   = "organizations:LeaveOrganization"
        Resource = "*"
      }
    ]
  })

  scp_require_imdsv2 = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RequireIMDSv2"
        Effect = "Deny"
        Action = "ec2:RunInstances"
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          StringNotEquals = {
            "ec2:MetadataHttpTokens" = "required"
          }
        }
      }
    ]
  })
}

# Data Sources
data "aws_caller_identity" "current" {}

# Outputs
output "security_team_role_arn" {
  description = "ARN of security team role"
  value       = aws_iam_role.security_team.arn
}

output "break_glass_role_arn" {
  description = "ARN of break glass emergency role"
  value       = aws_iam_role.break_glass.arn
}

output "mfa_policy_arn" {
  description = "ARN of MFA enforcement policy"
  value       = aws_iam_policy.mfa_enforcement.arn
}
