# SOC 2 Type II Compliance Guide

## Overview

SOC 2 (System and Organization Controls 2) is a compliance framework developed by AICPA that specifies how organizations should manage customer data. Type II reports assess the operational effectiveness of controls over a period of time (typically 6-12 months).

---

## Trust Service Criteria (TSC)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SOC 2 TRUST SERVICE CRITERIA                             │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         SECURITY (Required)                          │   │
│  │  Protection against unauthorized access, use, or modification        │   │
│  │  • Logical and physical access controls                              │   │
│  │  • System operations                                                 │   │
│  │  • Change management                                                 │   │
│  │  • Risk mitigation                                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │  AVAILABILITY   │  │ PROCESSING      │  │ CONFIDENTIALITY │             │
│  │                 │  │ INTEGRITY       │  │                 │             │
│  │ System is       │  │                 │  │ Information     │             │
│  │ available for   │  │ Processing is   │  │ designated as   │             │
│  │ operation as    │  │ complete,       │  │ confidential    │             │
│  │ committed       │  │ valid, accurate │  │ is protected    │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                           PRIVACY                                    │   │
│  │  Personal information is collected, used, retained, disclosed,       │   │
│  │  and disposed of in conformity with commitments in privacy notice    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Common Criteria (CC) Series

### CC1 - Control Environment

| Control | Description | Evidence Required |
|---------|-------------|-------------------|
| CC1.1 | COSO Commitment to Integrity | Code of conduct, ethics policy |
| CC1.2 | Board Oversight | Board meeting minutes, audit committee charter |
| CC1.3 | Management Philosophy | Org chart, management policies |
| CC1.4 | Competent Personnel | Job descriptions, training records |
| CC1.5 | Accountability | Performance reviews, disciplinary records |

### CC2 - Communication and Information

| Control | Description | Evidence Required |
|---------|-------------|-------------------|
| CC2.1 | Internal Information | Policy repository, intranet access |
| CC2.2 | Internal Communication | Security awareness program, newsletters |
| CC2.3 | External Communication | Customer notifications, SLAs |

### CC3 - Risk Assessment

| Control | Description | Evidence Required |
|---------|-------------|-------------------|
| CC3.1 | Risk Objectives | Risk management policy |
| CC3.2 | Risk Identification | Risk assessment reports |
| CC3.3 | Fraud Consideration | Fraud risk assessment |
| CC3.4 | Change Identification | Change management procedures |

### CC4 - Monitoring Activities

| Control | Description | Evidence Required |
|---------|-------------|-------------------|
| CC4.1 | Ongoing Monitoring | SIEM dashboards, security metrics |
| CC4.2 | Deficiency Evaluation | Audit findings, remediation tracking |

### CC5 - Control Activities

| Control | Description | Evidence Required |
|---------|-------------|-------------------|
| CC5.1 | Risk Mitigation | Control mapping to risks |
| CC5.2 | Technology Controls | Technical control documentation |
| CC5.3 | Policy Controls | Policy deployment evidence |

---

## Security Criteria - Technical Controls

### CC6 - Logical and Physical Access

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ CC6.1 - LOGICAL ACCESS SECURITY                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  REQUIREMENTS:                                                              │
│  □ Unique user identification                                               │
│  □ Role-based access control (RBAC)                                         │
│  □ Principle of least privilege                                             │
│  □ Segregation of duties                                                    │
│  □ Multi-factor authentication                                              │
│                                                                             │
│  EVIDENCE TO COLLECT:                                                       │
│  • User access list with roles                                              │
│  • Access provisioning/deprovisioning procedures                            │
│  • Quarterly access reviews                                                 │
│  • MFA configuration screenshots                                            │
│  • Privileged access management (PAM) logs                                  │
│                                                                             │
│  AUTOMATED CONTROLS:                                                        │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ # AWS IAM Policy Example                                           │    │
│  │ {                                                                  │    │
│  │   "Version": "2012-10-17",                                         │    │
│  │   "Statement": [{                                                  │    │
│  │     "Effect": "Deny",                                              │    │
│  │     "Action": "*",                                                 │    │
│  │     "Resource": "*",                                               │    │
│  │     "Condition": {                                                 │    │
│  │       "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}      │    │
│  │     }                                                              │    │
│  │   }]                                                               │    │
│  │ }                                                                  │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ CC6.2 - SYSTEM ACCESS RESTRICTIONS                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  REQUIREMENTS:                                                              │
│  □ Network segmentation                                                     │
│  □ Firewall rules documented                                                │
│  □ VPN for remote access                                                    │
│  □ Bastion/jump server usage                                                │
│  □ Production environment restrictions                                      │
│                                                                             │
│  EVIDENCE:                                                                  │
│  • Network diagrams                                                         │
│  • Firewall rule exports                                                    │
│  • VPN access logs                                                          │
│  • Security group configurations                                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ CC6.3 - LOGICAL ACCESS MANAGEMENT                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  REQUIREMENTS:                                                              │
│  □ Onboarding process with access approval                                  │
│  □ Offboarding with timely revocation                                       │
│  □ Access modification workflow                                             │
│  □ Periodic access recertification                                          │
│                                                                             │
│  EVIDENCE:                                                                  │
│  • Access request tickets                                                   │
│  • Termination checklist completion                                         │
│  • Quarterly access review reports                                          │
│  • Access approval emails/workflows                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### CC7 - System Operations

| Control | Description | Evidence Required |
|---------|-------------|-------------------|
| CC7.1 | Detection of Changes | Change management system, deployment logs |
| CC7.2 | Security Event Monitoring | SIEM alerts, incident tickets |
| CC7.3 | Incident Response | IR plan, incident reports, tabletop exercises |
| CC7.4 | Incident Recovery | RTO/RPO metrics, DR test results |

### CC8 - Change Management

| Control | Description | Evidence Required |
|---------|-------------|-------------------|
| CC8.1 | Change Authorization | Change tickets with approvals |
| | Testing | Test results before production |
| | Documentation | Change documentation |
| | Approval Workflow | CAB meeting minutes |

### CC9 - Risk Mitigation

| Control | Description | Evidence Required |
|---------|-------------|-------------------|
| CC9.1 | Risk Identification | Risk register |
| CC9.2 | Vendor Risk | Vendor assessments, contracts |

---

## Evidence Collection Checklist

### Policies and Procedures

```
□ Information Security Policy
□ Acceptable Use Policy
□ Access Control Policy
□ Change Management Policy
□ Incident Response Plan
□ Business Continuity Plan
□ Disaster Recovery Plan
□ Data Classification Policy
□ Encryption Policy
□ Vendor Management Policy
□ Risk Assessment Methodology
□ Privacy Policy
□ Data Retention Policy
```

### Technical Evidence

```
□ Network Architecture Diagram
□ Data Flow Diagrams
□ Firewall Rule Exports
□ Security Group Configurations
□ User Access Lists
□ MFA Configuration Screenshots
□ Encryption Settings (at rest and in transit)
□ Vulnerability Scan Reports
□ Penetration Test Reports
□ SIEM Dashboard Screenshots
□ Backup Configuration and Test Results
□ DR Test Results
□ Patch Management Reports
□ Anti-malware Configuration
□ IDS/IPS Configuration
```

### Administrative Evidence

```
□ Organizational Chart
□ Background Check Procedures
□ Security Awareness Training Records
□ Access Review Documentation
□ Change Management Tickets (sample)
□ Incident Response Reports (sample)
□ Risk Assessment Reports
□ Vendor Assessment Documentation
□ Board/Management Meeting Minutes
□ Internal Audit Reports
□ External Audit Reports
□ SLA Documentation
□ Customer Contracts (relevant sections)
```

---

## Control Matrix Template

```
┌────────────────────────────────────────────────────────────────────────────┐
│ CONTROL ID: CC6.1-01                                                        │
│ CONTROL NAME: Unique User Identification                                    │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│ TRUST SERVICE CRITERIA: Security                                           │
│ SOC 2 CRITERIA: CC6.1                                                      │
│                                                                            │
│ CONTROL DESCRIPTION:                                                       │
│ All users are assigned unique identifiers. Generic/shared accounts are     │
│ prohibited except for documented service accounts.                         │
│                                                                            │
│ CONTROL OWNER: IT Security Manager                                         │
│                                                                            │
│ CONTROL FREQUENCY: Continuous                                              │
│                                                                            │
│ CONTROL TYPE: Preventive                                                   │
│                                                                            │
│ IMPLEMENTATION:                                                            │
│ • Azure AD enforces unique UPN for all users                               │
│ • AWS IAM users have unique identifiers                                    │
│ • Service accounts documented in CMDB                                      │
│                                                                            │
│ TESTING PROCEDURE:                                                         │
│ 1. Export user list from identity provider                                 │
│ 2. Verify no duplicate usernames                                           │
│ 3. Verify all active users are employees/contractors                       │
│ 4. Review service account inventory                                        │
│                                                                            │
│ EVIDENCE:                                                                  │
│ • Azure AD user export                                                     │
│ • AWS IAM user list                                                        │
│ • Service account inventory                                                │
│                                                                            │
│ EXCEPTIONS:                                                                │
│ None                                                                       │
│                                                                            │
│ LAST TESTED: 2024-01-15                                                    │
│ TEST RESULT: Effective                                                     │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Audit Timeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SOC 2 TYPE II AUDIT TIMELINE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  MONTH 1-2: PREPARATION                                                     │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • Engage auditor                                                           │
│  • Determine scope (criteria selection)                                     │
│  • Gap assessment                                                           │
│  • Remediate identified gaps                                                │
│                                                                             │
│  MONTH 3: READINESS                                                         │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • Complete evidence collection                                             │
│  • Internal control testing                                                 │
│  • Prepare system description                                               │
│  • Train control owners                                                     │
│                                                                             │
│  MONTH 4-9: AUDIT PERIOD (Observation Window)                               │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • Controls operating as designed                                           │
│  • Maintain evidence throughout period                                      │
│  • Address any issues promptly                                              │
│  • Interim auditor touchpoints                                              │
│                                                                             │
│  MONTH 10: FIELDWORK                                                        │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • Auditor testing                                                          │
│  • Evidence requests                                                        │
│  • Interviews                                                               │
│  • Walkthroughs                                                             │
│                                                                             │
│  MONTH 11: REPORTING                                                        │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • Draft report review                                                      │
│  • Management response to exceptions                                        │
│  • Final report issuance                                                    │
│                                                                             │
│  MONTH 12: POST-AUDIT                                                       │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • Address any findings                                                     │
│  • Plan for next audit cycle                                                │
│  • Continuous improvement                                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Common Audit Findings

| Finding | Impact | Remediation |
|---------|--------|-------------|
| Incomplete access reviews | High | Implement quarterly reviews with documentation |
| Terminated user access not revoked | Critical | Automate offboarding, same-day revocation |
| Missing MFA | High | Deploy MFA for all users and privileged access |
| Unencrypted data at rest | High | Enable encryption (AES-256) for all data stores |
| Insufficient logging | Medium | Centralize logs, retain 1 year minimum |
| No formal change management | High | Implement ticketing system with approvals |
| Outdated policies | Medium | Annual review and update cycle |
| Missing vendor assessments | Medium | Implement vendor management program |
| No incident response testing | High | Conduct annual tabletop exercises |
| Backup testing not documented | Medium | Monthly backup tests with evidence |

---

## Continuous Compliance

### Automated Monitoring

```hcl
# AWS Config Rules for SOC 2
resource "aws_config_config_rule" "mfa_enabled" {
  name = "iam-user-mfa-enabled"
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }
}

resource "aws_config_config_rule" "encrypted_volumes" {
  name = "encrypted-volumes"
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
}

resource "aws_config_config_rule" "cloudtrail_enabled" {
  name = "cloudtrail-enabled"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }
}

resource "aws_config_config_rule" "s3_bucket_ssl" {
  name = "s3-bucket-ssl-requests-only"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }
}
```

---

## References

- [AICPA SOC 2 Guide](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/sorhome)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustdataintegritytaskforce)
- [AWS SOC 2 Compliance](https://aws.amazon.com/compliance/soc-faqs/)
