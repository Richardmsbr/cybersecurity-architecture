# AWS GuardDuty Security Guide

## Overview

Amazon GuardDuty is a threat detection service that continuously monitors for malicious activity and unauthorized behavior.

---

## Finding Types

### EC2 Findings

| Finding | Severity | Description |
|---------|----------|-------------|
| Backdoor:EC2/C&CActivity | High | EC2 communicating with C2 server |
| CryptoCurrency:EC2/BitcoinTool | High | EC2 mining cryptocurrency |
| Trojan:EC2/DNSDataExfiltration | High | DNS data exfiltration |
| UnauthorizedAccess:EC2/SSHBruteForce | Low-High | SSH brute force |

### IAM Findings

| Finding | Severity | Description |
|---------|----------|-------------|
| UnauthorizedAccess:IAMUser/MaliciousIPCaller | Medium | API call from malicious IP |
| Persistence:IAMUser/UserPermissions | Medium | Unusual permissions change |
| CredentialAccess:IAMUser/AnomalousBehavior | High | Credential compromise |

### S3 Findings

| Finding | Severity | Description |
|---------|----------|-------------|
| Policy:S3/BucketAnonymousAccessGranted | High | Public access granted |
| Exfiltration:S3/MaliciousIPCaller | High | Access from malicious IP |
| Stealth:S3/ServerAccessLoggingDisabled | Low | Logging disabled |

---

## Best Practices

1. Enable in all regions
2. Export findings to S3 for retention
3. Integrate with Security Hub
4. Configure SNS notifications
5. Automate response with Lambda

---

## Terraform Example

```hcl
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes { enable = true }
      }
    }
  }
}
```
