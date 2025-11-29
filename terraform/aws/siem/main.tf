# AWS SIEM Integration Configuration
# OpenSearch-based SIEM with log aggregation

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

variable "opensearch_instance_type" {
  type        = string
  description = "OpenSearch instance type"
  default     = "r6g.large.search"
}

variable "opensearch_instance_count" {
  type        = number
  description = "Number of OpenSearch instances"
  default     = 3
}

variable "opensearch_ebs_volume_size" {
  type        = number
  description = "EBS volume size in GB"
  default     = 100
}

variable "opensearch_master_user" {
  type        = string
  description = "OpenSearch master username"
  default     = "admin"
  sensitive   = true
}

variable "opensearch_master_password" {
  type        = string
  description = "OpenSearch master password"
  sensitive   = true
}

variable "vpc_id" {
  type        = string
  description = "VPC ID for OpenSearch"
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnet IDs for OpenSearch"
}

variable "allowed_cidr_blocks" {
  type        = list(string)
  description = "CIDR blocks allowed to access OpenSearch"
  default     = []
}

# KMS Key for OpenSearch Encryption
resource "aws_kms_key" "opensearch" {
  description             = "KMS key for OpenSearch encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "${var.environment}-opensearch-kms"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Security Group for OpenSearch
resource "aws_security_group" "opensearch" {
  name        = "${var.environment}-opensearch-sg"
  description = "Security group for OpenSearch SIEM"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-opensearch-sg"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Service-Linked Role for OpenSearch
resource "aws_iam_service_linked_role" "opensearch" {
  aws_service_name = "opensearchservice.amazonaws.com"
}

# OpenSearch Domain
resource "aws_opensearch_domain" "siem" {
  domain_name    = "${var.environment}-siem"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type            = var.opensearch_instance_type
    instance_count           = var.opensearch_instance_count
    zone_awareness_enabled   = true
    dedicated_master_enabled = true
    dedicated_master_type    = "r6g.large.search"
    dedicated_master_count   = 3

    zone_awareness_config {
      availability_zone_count = 3
    }
  }

  vpc_options {
    subnet_ids         = var.subnet_ids
    security_group_ids = [aws_security_group.opensearch.id]
  }

  ebs_options {
    ebs_enabled = true
    volume_size = var.opensearch_ebs_volume_size
    volume_type = "gp3"
    iops        = 3000
    throughput  = 125
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.opensearch.key_id
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
    master_user_options {
      master_user_name     = var.opensearch_master_user
      master_user_password = var.opensearch_master_password
    }
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch_index_slow.arn
    log_type                 = "INDEX_SLOW_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch_search_slow.arn
    log_type                 = "SEARCH_SLOW_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch_error.arn
    log_type                 = "ES_APPLICATION_LOGS"
  }

  tags = {
    Name        = "${var.environment}-opensearch-siem"
    Environment = var.environment
    ManagedBy   = "terraform"
  }

  depends_on = [aws_iam_service_linked_role.opensearch]
}

# CloudWatch Log Groups for OpenSearch
resource "aws_cloudwatch_log_group" "opensearch_index_slow" {
  name              = "/aws/opensearch/${var.environment}-siem/index-slow-logs"
  retention_in_days = 30

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_cloudwatch_log_group" "opensearch_search_slow" {
  name              = "/aws/opensearch/${var.environment}-siem/search-slow-logs"
  retention_in_days = 30

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_cloudwatch_log_group" "opensearch_error" {
  name              = "/aws/opensearch/${var.environment}-siem/error-logs"
  retention_in_days = 30

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# CloudWatch Log Resource Policy
resource "aws_cloudwatch_log_resource_policy" "opensearch" {
  policy_name = "${var.environment}-opensearch-log-policy"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "es.amazonaws.com"
        }
        Action = [
          "logs:PutLogEvents",
          "logs:PutLogEventsBatch",
          "logs:CreateLogStream"
        ]
        Resource = "arn:aws:logs:*"
      }
    ]
  })
}

# IAM Role for Kinesis Firehose to OpenSearch
resource "aws_iam_role" "firehose_opensearch" {
  name = "${var.environment}-firehose-opensearch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_iam_role_policy" "firehose_opensearch" {
  name = "${var.environment}-firehose-opensearch-policy"
  role = aws_iam_role.firehose_opensearch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "OpenSearchAccess"
        Effect = "Allow"
        Action = [
          "es:DescribeDomain",
          "es:DescribeDomains",
          "es:DescribeDomainConfig",
          "es:ESHttpPost",
          "es:ESHttpPut",
          "es:ESHttpGet"
        ]
        Resource = [
          aws_opensearch_domain.siem.arn,
          "${aws_opensearch_domain.siem.arn}/*"
        ]
      },
      {
        Sid    = "S3Backup"
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.firehose_backup.arn,
          "${aws_s3_bucket.firehose_backup.arn}/*"
        ]
      },
      {
        Sid    = "KMSAccess"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.opensearch.arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# S3 Bucket for Firehose Backup
resource "aws_s3_bucket" "firehose_backup" {
  bucket        = "${var.environment}-siem-firehose-backup-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = {
    Name        = "${var.environment}-firehose-backup"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "firehose_backup" {
  bucket = aws_s3_bucket.firehose_backup.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.opensearch.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "firehose_backup" {
  bucket = aws_s3_bucket.firehose_backup.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Kinesis Firehose Delivery Stream
resource "aws_kinesis_firehose_delivery_stream" "siem" {
  name        = "${var.environment}-siem-delivery"
  destination = "opensearch"

  opensearch_configuration {
    domain_arn            = aws_opensearch_domain.siem.arn
    role_arn              = aws_iam_role.firehose_opensearch.arn
    index_name            = "security-logs"
    index_rotation_period = "OneDay"
    buffering_size        = 5
    buffering_interval    = 60
    retry_duration        = 60

    vpc_config {
      subnet_ids         = var.subnet_ids
      security_group_ids = [aws_security_group.opensearch.id]
      role_arn           = aws_iam_role.firehose_opensearch.arn
    }

    s3_configuration {
      role_arn           = aws_iam_role.firehose_opensearch.arn
      bucket_arn         = aws_s3_bucket.firehose_backup.arn
      buffering_size     = 10
      buffering_interval = 400
      compression_format = "GZIP"
    }

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose.name
      log_stream_name = "DestinationDelivery"
    }
  }

  tags = {
    Name        = "${var.environment}-siem-firehose"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_cloudwatch_log_group" "firehose" {
  name              = "/aws/kinesisfirehose/${var.environment}-siem"
  retention_in_days = 14

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Data Sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Outputs
output "opensearch_endpoint" {
  description = "OpenSearch domain endpoint"
  value       = aws_opensearch_domain.siem.endpoint
}

output "opensearch_dashboard_endpoint" {
  description = "OpenSearch dashboard endpoint"
  value       = aws_opensearch_domain.siem.dashboard_endpoint
}

output "opensearch_arn" {
  description = "OpenSearch domain ARN"
  value       = aws_opensearch_domain.siem.arn
}

output "firehose_arn" {
  description = "Kinesis Firehose ARN"
  value       = aws_kinesis_firehose_delivery_stream.siem.arn
}

output "firehose_backup_bucket" {
  description = "S3 bucket for Firehose backup"
  value       = aws_s3_bucket.firehose_backup.id
}
