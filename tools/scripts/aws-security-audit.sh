#!/bin/bash
#
# AWS Security Audit Script
# Performs comprehensive security checks on AWS infrastructure
#
# Usage: ./aws-security-audit.sh [--profile PROFILE] [--region REGION] [--output FORMAT]
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
PROFILE="${AWS_PROFILE:-default}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
OUTPUT_FORMAT="text"
REPORT_FILE="aws-security-audit-$(date +%Y%m%d-%H%M%S).txt"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--profile PROFILE] [--region REGION] [--output FORMAT]"
            echo ""
            echo "Options:"
            echo "  --profile   AWS profile to use (default: default)"
            echo "  --region    AWS region to audit (default: us-east-1)"
            echo "  --output    Output format: text, json (default: text)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# AWS CLI wrapper
aws_cmd() {
    aws --profile "$PROFILE" --region "$REGION" "$@" 2>/dev/null
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_section() {
    echo ""
    echo "=============================================="
    echo " $1"
    echo "=============================================="
}

# Check AWS credentials
check_credentials() {
    log_section "Checking AWS Credentials"

    if aws_cmd sts get-caller-identity > /dev/null; then
        ACCOUNT_ID=$(aws_cmd sts get-caller-identity --query 'Account' --output text)
        USER_ARN=$(aws_cmd sts get-caller-identity --query 'Arn' --output text)
        log_pass "Authenticated as: $USER_ARN"
        log_info "Account ID: $ACCOUNT_ID"
    else
        log_fail "Unable to authenticate with AWS"
        exit 1
    fi
}

# IAM Audit
audit_iam() {
    log_section "IAM Security Audit"

    # Check for root access keys
    log_info "Checking root account access keys..."
    ROOT_KEYS=$(aws_cmd iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text)
    if [[ "$ROOT_KEYS" -gt 0 ]]; then
        log_fail "Root account has access keys configured - HIGH RISK"
    else
        log_pass "No root access keys found"
    fi

    # Check MFA on root
    log_info "Checking root account MFA..."
    ROOT_MFA=$(aws_cmd iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text)
    if [[ "$ROOT_MFA" -eq 1 ]]; then
        log_pass "Root account has MFA enabled"
    else
        log_fail "Root account does not have MFA enabled - CRITICAL"
    fi

    # Check password policy
    log_info "Checking password policy..."
    if aws_cmd iam get-account-password-policy > /dev/null 2>&1; then
        MIN_LENGTH=$(aws_cmd iam get-account-password-policy --query 'PasswordPolicy.MinimumPasswordLength' --output text)
        if [[ "$MIN_LENGTH" -ge 14 ]]; then
            log_pass "Password minimum length: $MIN_LENGTH characters"
        else
            log_warn "Password minimum length is $MIN_LENGTH (recommended: 14+)"
        fi
    else
        log_fail "No password policy configured"
    fi

    # Check users without MFA
    log_info "Checking users without MFA..."
    USERS_NO_MFA=$(aws_cmd iam list-users --query 'Users[*].UserName' --output text)
    for user in $USERS_NO_MFA; do
        MFA_DEVICES=$(aws_cmd iam list-mfa-devices --user-name "$user" --query 'MFADevices' --output text)
        if [[ -z "$MFA_DEVICES" ]]; then
            log_warn "User '$user' does not have MFA enabled"
        fi
    done

    # Check for old access keys
    log_info "Checking for access keys older than 90 days..."
    for user in $USERS_NO_MFA; do
        KEYS=$(aws_cmd iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[*].[AccessKeyId,CreateDate]' --output text)
        while read -r key_id create_date; do
            if [[ -n "$key_id" ]]; then
                KEY_AGE=$(( ($(date +%s) - $(date -d "$create_date" +%s)) / 86400 ))
                if [[ "$KEY_AGE" -gt 90 ]]; then
                    log_warn "User '$user' has access key '$key_id' that is $KEY_AGE days old"
                fi
            fi
        done <<< "$KEYS"
    done

    # Check for unused credentials
    log_info "Checking for unused credentials (90+ days)..."
    aws_cmd iam generate-credential-report > /dev/null
    sleep 2
    CRED_REPORT=$(aws_cmd iam get-credential-report --query 'Content' --output text | base64 -d)
    echo "$CRED_REPORT" | tail -n +2 | while IFS=, read -r user arn user_creation password_enabled password_last_used password_last_changed password_next_rotation mfa_active access_key_1_active access_key_1_last_rotated access_key_1_last_used_date access_key_1_last_used_region access_key_1_last_used_service access_key_2_active access_key_2_last_rotated access_key_2_last_used_date access_key_2_last_used_region access_key_2_last_used_service cert_1_active cert_1_last_rotated cert_2_active cert_2_last_rotated; do
        if [[ "$password_enabled" == "true" && "$password_last_used" != "N/A" && "$password_last_used" != "no_information" ]]; then
            LAST_USE=$(date -d "$password_last_used" +%s 2>/dev/null || echo 0)
            if [[ "$LAST_USE" -gt 0 ]]; then
                DAYS_AGO=$(( ($(date +%s) - LAST_USE) / 86400 ))
                if [[ "$DAYS_AGO" -gt 90 ]]; then
                    log_warn "User '$user' password not used in $DAYS_AGO days"
                fi
            fi
        fi
    done
}

# S3 Bucket Audit
audit_s3() {
    log_section "S3 Security Audit"

    BUCKETS=$(aws_cmd s3api list-buckets --query 'Buckets[*].Name' --output text)

    for bucket in $BUCKETS; do
        log_info "Checking bucket: $bucket"

        # Check public access block
        if aws_cmd s3api get-public-access-block --bucket "$bucket" > /dev/null 2>&1; then
            BLOCK_CONFIG=$(aws_cmd s3api get-public-access-block --bucket "$bucket" --query 'PublicAccessBlockConfiguration')
            if echo "$BLOCK_CONFIG" | grep -q '"BlockPublicAcls": true' && \
               echo "$BLOCK_CONFIG" | grep -q '"BlockPublicPolicy": true'; then
                log_pass "Bucket '$bucket' has public access blocked"
            else
                log_warn "Bucket '$bucket' may allow public access"
            fi
        else
            log_fail "Bucket '$bucket' has no public access block configured"
        fi

        # Check encryption
        if aws_cmd s3api get-bucket-encryption --bucket "$bucket" > /dev/null 2>&1; then
            log_pass "Bucket '$bucket' has encryption enabled"
        else
            log_warn "Bucket '$bucket' does not have default encryption"
        fi

        # Check versioning
        VERSIONING=$(aws_cmd s3api get-bucket-versioning --bucket "$bucket" --query 'Status' --output text)
        if [[ "$VERSIONING" == "Enabled" ]]; then
            log_pass "Bucket '$bucket' has versioning enabled"
        else
            log_warn "Bucket '$bucket' does not have versioning enabled"
        fi

        # Check logging
        if aws_cmd s3api get-bucket-logging --bucket "$bucket" --query 'LoggingEnabled' --output text | grep -q "TargetBucket"; then
            log_pass "Bucket '$bucket' has logging enabled"
        else
            log_warn "Bucket '$bucket' does not have logging enabled"
        fi
    done
}

# Security Groups Audit
audit_security_groups() {
    log_section "Security Groups Audit"

    # Check for overly permissive security groups
    log_info "Checking for security groups with 0.0.0.0/0 ingress..."

    SG_LIST=$(aws_cmd ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId,GroupName]' --output text)

    while read -r sg_id sg_name; do
        if [[ -n "$sg_id" ]]; then
            # Check for SSH open to world
            SSH_OPEN=$(aws_cmd ec2 describe-security-groups --group-ids "$sg_id" \
                --query 'SecurityGroups[*].IpPermissions[?FromPort==`22` && ToPort==`22`].IpRanges[?CidrIp==`0.0.0.0/0`]' \
                --output text)
            if [[ -n "$SSH_OPEN" ]]; then
                log_fail "Security group '$sg_name' ($sg_id) has SSH open to 0.0.0.0/0"
            fi

            # Check for RDP open to world
            RDP_OPEN=$(aws_cmd ec2 describe-security-groups --group-ids "$sg_id" \
                --query 'SecurityGroups[*].IpPermissions[?FromPort==`3389` && ToPort==`3389`].IpRanges[?CidrIp==`0.0.0.0/0`]' \
                --output text)
            if [[ -n "$RDP_OPEN" ]]; then
                log_fail "Security group '$sg_name' ($sg_id) has RDP open to 0.0.0.0/0"
            fi

            # Check for all ports open
            ALL_PORTS=$(aws_cmd ec2 describe-security-groups --group-ids "$sg_id" \
                --query 'SecurityGroups[*].IpPermissions[?FromPort==`0` && ToPort==`65535`].IpRanges[?CidrIp==`0.0.0.0/0`]' \
                --output text)
            if [[ -n "$ALL_PORTS" ]]; then
                log_fail "Security group '$sg_name' ($sg_id) has all ports open to 0.0.0.0/0 - CRITICAL"
            fi
        fi
    done <<< "$SG_LIST"
}

# CloudTrail Audit
audit_cloudtrail() {
    log_section "CloudTrail Audit"

    TRAILS=$(aws_cmd cloudtrail describe-trails --query 'trailList[*].Name' --output text)

    if [[ -z "$TRAILS" ]]; then
        log_fail "No CloudTrail trails configured - CRITICAL"
        return
    fi

    for trail in $TRAILS; do
        log_info "Checking trail: $trail"

        # Check if trail is logging
        STATUS=$(aws_cmd cloudtrail get-trail-status --name "$trail" --query 'IsLogging' --output text)
        if [[ "$STATUS" == "True" ]]; then
            log_pass "Trail '$trail' is actively logging"
        else
            log_fail "Trail '$trail' is not logging"
        fi

        # Check log file validation
        VALIDATION=$(aws_cmd cloudtrail describe-trails --trail-name-list "$trail" \
            --query 'trailList[0].LogFileValidationEnabled' --output text)
        if [[ "$VALIDATION" == "True" ]]; then
            log_pass "Trail '$trail' has log file validation enabled"
        else
            log_warn "Trail '$trail' does not have log file validation"
        fi

        # Check encryption
        KMS_KEY=$(aws_cmd cloudtrail describe-trails --trail-name-list "$trail" \
            --query 'trailList[0].KmsKeyId' --output text)
        if [[ -n "$KMS_KEY" && "$KMS_KEY" != "None" ]]; then
            log_pass "Trail '$trail' is encrypted with KMS"
        else
            log_warn "Trail '$trail' is not encrypted with KMS"
        fi

        # Check multi-region
        MULTI_REGION=$(aws_cmd cloudtrail describe-trails --trail-name-list "$trail" \
            --query 'trailList[0].IsMultiRegionTrail' --output text)
        if [[ "$MULTI_REGION" == "True" ]]; then
            log_pass "Trail '$trail' is multi-region"
        else
            log_warn "Trail '$trail' is single-region only"
        fi
    done
}

# GuardDuty Audit
audit_guardduty() {
    log_section "GuardDuty Audit"

    DETECTOR_IDS=$(aws_cmd guardduty list-detectors --query 'DetectorIds' --output text)

    if [[ -z "$DETECTOR_IDS" ]]; then
        log_fail "GuardDuty is not enabled - CRITICAL"
        return
    fi

    for detector in $DETECTOR_IDS; do
        STATUS=$(aws_cmd guardduty get-detector --detector-id "$detector" --query 'Status' --output text)
        if [[ "$STATUS" == "ENABLED" ]]; then
            log_pass "GuardDuty detector '$detector' is enabled"
        else
            log_warn "GuardDuty detector '$detector' is not enabled"
        fi

        # Check for high severity findings
        HIGH_FINDINGS=$(aws_cmd guardduty list-findings --detector-id "$detector" \
            --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' \
            --query 'FindingIds' --output text | wc -w)
        if [[ "$HIGH_FINDINGS" -gt 0 ]]; then
            log_warn "GuardDuty has $HIGH_FINDINGS high severity findings"
        else
            log_pass "No high severity GuardDuty findings"
        fi
    done
}

# RDS Audit
audit_rds() {
    log_section "RDS Security Audit"

    DBS=$(aws_cmd rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier' --output text)

    for db in $DBS; do
        log_info "Checking RDS instance: $db"

        # Check encryption
        ENCRYPTED=$(aws_cmd rds describe-db-instances --db-instance-identifier "$db" \
            --query 'DBInstances[0].StorageEncrypted' --output text)
        if [[ "$ENCRYPTED" == "True" ]]; then
            log_pass "RDS '$db' has encryption at rest enabled"
        else
            log_fail "RDS '$db' does not have encryption at rest - HIGH RISK"
        fi

        # Check public accessibility
        PUBLIC=$(aws_cmd rds describe-db-instances --db-instance-identifier "$db" \
            --query 'DBInstances[0].PubliclyAccessible' --output text)
        if [[ "$PUBLIC" == "False" ]]; then
            log_pass "RDS '$db' is not publicly accessible"
        else
            log_fail "RDS '$db' is publicly accessible - HIGH RISK"
        fi

        # Check deletion protection
        DEL_PROTECT=$(aws_cmd rds describe-db-instances --db-instance-identifier "$db" \
            --query 'DBInstances[0].DeletionProtection' --output text)
        if [[ "$DEL_PROTECT" == "True" ]]; then
            log_pass "RDS '$db' has deletion protection enabled"
        else
            log_warn "RDS '$db' does not have deletion protection"
        fi

        # Check backup retention
        BACKUP_DAYS=$(aws_cmd rds describe-db-instances --db-instance-identifier "$db" \
            --query 'DBInstances[0].BackupRetentionPeriod' --output text)
        if [[ "$BACKUP_DAYS" -ge 7 ]]; then
            log_pass "RDS '$db' has $BACKUP_DAYS day backup retention"
        else
            log_warn "RDS '$db' has only $BACKUP_DAYS day backup retention"
        fi
    done
}

# VPC Audit
audit_vpc() {
    log_section "VPC Security Audit"

    # Check for VPC Flow Logs
    VPCS=$(aws_cmd ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text)

    for vpc in $VPCS; do
        log_info "Checking VPC: $vpc"

        FLOW_LOGS=$(aws_cmd ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc" \
            --query 'FlowLogs[*].FlowLogId' --output text)

        if [[ -n "$FLOW_LOGS" ]]; then
            log_pass "VPC '$vpc' has flow logs enabled"
        else
            log_warn "VPC '$vpc' does not have flow logs enabled"
        fi
    done

    # Check for default VPC
    DEFAULT_VPC=$(aws_cmd ec2 describe-vpcs --filters "Name=isDefault,Values=true" \
        --query 'Vpcs[0].VpcId' --output text)

    if [[ -n "$DEFAULT_VPC" && "$DEFAULT_VPC" != "None" ]]; then
        # Check if default VPC is in use
        INSTANCES_IN_DEFAULT=$(aws_cmd ec2 describe-instances \
            --filters "Name=vpc-id,Values=$DEFAULT_VPC" \
            --query 'Reservations[*].Instances[*].InstanceId' --output text | wc -w)

        if [[ "$INSTANCES_IN_DEFAULT" -gt 0 ]]; then
            log_warn "Default VPC has $INSTANCES_IN_DEFAULT instances - consider using custom VPC"
        fi
    fi
}

# Main execution
main() {
    echo ""
    echo "========================================"
    echo "    AWS Security Audit Tool"
    echo "========================================"
    echo ""
    echo "Profile: $PROFILE"
    echo "Region:  $REGION"
    echo "Date:    $(date)"
    echo ""

    check_credentials
    audit_iam
    audit_s3
    audit_security_groups
    audit_cloudtrail
    audit_guardduty
    audit_rds
    audit_vpc

    log_section "Audit Complete"
    echo ""
    echo "Review the findings above and remediate any issues."
    echo ""
}

main "$@"
