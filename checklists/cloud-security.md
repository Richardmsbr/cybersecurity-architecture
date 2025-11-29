# Cloud Security Assessment Checklist

Comprehensive checklist for assessing security posture across AWS, Azure, and GCP cloud environments.

---

## Identity and Access Management

### Account Security

- [ ] Root/global admin accounts have MFA enabled
- [ ] Root/admin accounts are not used for daily operations
- [ ] Strong password policy enforced
- [ ] Service accounts use least privilege
- [ ] Unused accounts are disabled/removed
- [ ] Access keys are rotated regularly
- [ ] Federated identity is used where possible

### IAM Policies

- [ ] Policies follow least privilege principle
- [ ] No wildcard (*) permissions on sensitive resources
- [ ] No inline policies on users (use groups/roles)
- [ ] IAM policies are regularly reviewed
- [ ] Permission boundaries are implemented
- [ ] Conditions are used to restrict access

### Access Reviews

- [ ] Regular access reviews conducted
- [ ] Unused permissions identified and removed
- [ ] Cross-account access is documented
- [ ] Third-party access is monitored

---

## Network Security

### VPC/Virtual Network

- [ ] Network segmentation implemented
- [ ] Default security groups/NSGs are restrictive
- [ ] No 0.0.0.0/0 inbound rules on sensitive ports
- [ ] VPC flow logs enabled
- [ ] Private subnets used for backend resources
- [ ] NAT gateway for outbound internet access
- [ ] VPC peering connections documented

### Firewall and Security Groups

- [ ] Security groups are resource-specific
- [ ] Ingress rules are minimized
- [ ] Egress rules are defined (not allow-all)
- [ ] Unused security groups are removed
- [ ] Network ACLs provide additional filtering

### Remote Access

- [ ] VPN or bastion hosts for admin access
- [ ] Direct SSH/RDP from internet is prohibited
- [ ] Session Manager or equivalent used
- [ ] Jump boxes are hardened

---

## Data Security

### Storage Security

- [ ] Storage buckets are not publicly accessible
- [ ] Server-side encryption enabled
- [ ] Customer-managed keys used for sensitive data
- [ ] Bucket policies restrict access appropriately
- [ ] Versioning enabled for critical buckets
- [ ] Object lock/WORM for compliance data
- [ ] Cross-region replication for DR

### Database Security

- [ ] Databases are not publicly accessible
- [ ] Encryption at rest enabled
- [ ] Encryption in transit enabled
- [ ] Strong authentication required
- [ ] Audit logging enabled
- [ ] Automated backups configured
- [ ] Point-in-time recovery enabled

### Data Classification

- [ ] Data classification scheme implemented
- [ ] Sensitive data is identified
- [ ] Data handling procedures defined
- [ ] Data retention policies enforced
- [ ] Data deletion procedures in place

---

## Compute Security

### Virtual Machines/Instances

- [ ] Latest OS patches applied
- [ ] Endpoint protection installed
- [ ] Instance metadata service protected
- [ ] IMDSv2 enforced (AWS)
- [ ] No sensitive data in user data scripts
- [ ] Instance profiles use least privilege
- [ ] Unused instances are terminated

### Containers

- [ ] Container images scanned for vulnerabilities
- [ ] Base images are from trusted sources
- [ ] Containers run as non-root
- [ ] Resource limits defined
- [ ] Network policies implemented
- [ ] Secrets are not stored in images
- [ ] Image signing/verification enabled

### Serverless

- [ ] Functions have minimal permissions
- [ ] No secrets in environment variables (use secrets manager)
- [ ] Function timeout configured
- [ ] Concurrency limits set
- [ ] VPC integration for sensitive functions
- [ ] Dependencies are scanned

---

## Logging and Monitoring

### Audit Logging

- [ ] Cloud trail/activity logs enabled
- [ ] Logs are centralized
- [ ] Log storage is immutable
- [ ] Log retention meets requirements
- [ ] Multi-region logging enabled
- [ ] Management events logged
- [ ] Data events logged for sensitive resources

### Security Monitoring

- [ ] Security services enabled (GuardDuty, Security Center, SCC)
- [ ] Alerting configured for critical events
- [ ] SIEM integration established
- [ ] Threat detection enabled
- [ ] Anomaly detection configured

### Compliance Monitoring

- [ ] Compliance standards enabled
- [ ] Security benchmarks assessed
- [ ] Drift detection enabled
- [ ] Remediation automation where possible

---

## Incident Response

### Preparation

- [ ] Incident response plan documented
- [ ] Roles and responsibilities defined
- [ ] Contact information current
- [ ] Playbooks created for common incidents
- [ ] Evidence collection procedures defined

### Detection

- [ ] Alerting thresholds defined
- [ ] Escalation procedures documented
- [ ] On-call rotation established
- [ ] Integration with ticketing system

### Response

- [ ] Isolation procedures documented
- [ ] Forensic procedures defined
- [ ] Communication templates ready
- [ ] Regulatory notification requirements known

---

## Backup and Recovery

### Backup Strategy

- [ ] Automated backups configured
- [ ] Backup encryption enabled
- [ ] Cross-region/account backups
- [ ] Backup retention appropriate
- [ ] Backup integrity verification

### Disaster Recovery

- [ ] RTO/RPO defined
- [ ] DR plan documented
- [ ] Multi-region architecture (if required)
- [ ] DR testing performed regularly
- [ ] Failover procedures documented

---

## Compliance

### Configuration Compliance

- [ ] CIS Benchmarks assessed
- [ ] Industry-specific requirements met
- [ ] Organization policies enforced
- [ ] Compliance drift detected

### Documentation

- [ ] Architecture diagrams current
- [ ] Security policies documented
- [ ] Procedures documented
- [ ] Risk assessments current

---

## AWS-Specific

- [ ] AWS Organizations configured
- [ ] SCPs (Service Control Policies) implemented
- [ ] AWS Config enabled
- [ ] AWS Security Hub enabled
- [ ] GuardDuty enabled
- [ ] Macie enabled for sensitive data
- [ ] IAM Access Analyzer enabled
- [ ] CloudTrail in all regions

---

## Azure-Specific

- [ ] Management Groups configured
- [ ] Azure Policy implemented
- [ ] Microsoft Defender for Cloud enabled
- [ ] Azure Sentinel configured
- [ ] Privileged Identity Management enabled
- [ ] Conditional Access policies configured
- [ ] Azure AD security defaults/MFA

---

## GCP-Specific

- [ ] Organization hierarchy configured
- [ ] Organization policies implemented
- [ ] Security Command Center enabled
- [ ] VPC Service Controls configured
- [ ] Binary Authorization enabled
- [ ] Cloud Armor configured
- [ ] Data Loss Prevention API used

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
