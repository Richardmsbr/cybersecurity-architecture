# Security Assessment Checklist

## Overview

Comprehensive security assessment checklist for evaluating an organization's security posture across all domains.

---

## 1. Governance & Risk Management

### Policies and Procedures

```
□ Information Security Policy exists and is current
□ Acceptable Use Policy defined
□ Data Classification Policy implemented
□ Incident Response Plan documented
□ Business Continuity Plan exists
□ Disaster Recovery Plan tested
□ Vendor/Third-Party Security Policy
□ Change Management Policy
□ Access Control Policy
□ Encryption Policy
```

### Risk Management

```
□ Risk assessment performed annually
□ Risk register maintained
□ Risk treatment plans documented
□ Risk appetite defined by leadership
□ Security metrics reported to leadership
□ Compliance requirements identified
□ Regulatory obligations tracked
```

---

## 2. Identity & Access Management

### Authentication

```
□ Multi-factor authentication (MFA) enabled
  □ All users
  □ Privileged accounts
  □ Remote access
  □ Cloud services

□ Password policy enforced
  □ Minimum 12 characters
  □ Complexity requirements
  □ Password history (12+)
  □ Account lockout (5 attempts)

□ Single Sign-On (SSO) implemented
□ FIDO2/Passwordless available for high-value accounts
□ Service accounts use managed identities where possible
```

### Authorization

```
□ Role-based access control (RBAC) implemented
□ Principle of least privilege enforced
□ Segregation of duties for critical functions
□ Access reviews performed quarterly
□ Privileged access management (PAM) in place
□ Just-in-time (JIT) access for admins
□ Break-glass procedures documented
```

### Account Management

```
□ Onboarding process includes security training
□ Offboarding revokes access within 24 hours
□ Dormant accounts disabled (90 days)
□ Generic/shared accounts prohibited or documented
□ Service account inventory maintained
□ Admin accounts separate from user accounts
```

---

## 3. Network Security

### Perimeter Security

```
□ Next-generation firewall deployed
□ Web Application Firewall (WAF) for web apps
□ DDoS protection enabled
□ Intrusion Detection/Prevention (IDS/IPS)
□ Email security gateway configured
□ DNS security implemented
```

### Network Architecture

```
□ Network segmentation implemented
  □ DMZ for public-facing services
  □ Separate management network
  □ Database tier isolated
  □ User segments separated

□ VPN for remote access
  □ Split tunneling disabled (or documented exception)
  □ MFA required

□ Wireless security
  □ WPA3/WPA2-Enterprise
  □ Guest network isolated
  □ Rogue AP detection
```

### Network Monitoring

```
□ Network traffic monitoring
□ NetFlow/IPFIX collection
□ DNS query logging
□ Full packet capture capability
□ Baseline traffic patterns established
```

---

## 4. Endpoint Security

### Endpoint Protection

```
□ Endpoint Detection and Response (EDR) deployed
  □ All workstations
  □ All servers
  □ Automatic updates enabled

□ Anti-malware with current signatures
□ Host-based firewall enabled
□ Full disk encryption (BitLocker/FileVault)
□ USB device control
□ Application whitelisting (critical systems)
```

### Endpoint Management

```
□ Centralized endpoint management (MDM/UEM)
□ Operating system patching
  □ Critical patches within 72 hours
  □ High patches within 30 days
  □ Other patches within 90 days

□ Software inventory maintained
□ Unauthorized software detected
□ Secure baseline configurations
□ Local admin rights restricted
```

### Mobile Devices

```
□ Mobile Device Management (MDM) enrolled
□ Remote wipe capability
□ PIN/biometric required
□ Jailbreak/root detection
□ Corporate data containerization
□ App store restrictions
```

---

## 5. Application Security

### Secure Development

```
□ SDLC includes security requirements
□ Threat modeling performed
□ Secure coding training for developers
□ Code review process includes security
□ Static Application Security Testing (SAST)
□ Dynamic Application Security Testing (DAST)
□ Software Composition Analysis (SCA)
□ Secrets management (no hardcoded credentials)
```

### Application Controls

```
□ Input validation implemented
□ Output encoding for user content
□ Parameterized queries (no SQL injection)
□ CSRF protection enabled
□ Security headers configured
  □ Content-Security-Policy
  □ X-Frame-Options
  □ X-Content-Type-Options
  □ Strict-Transport-Security

□ Session management secure
  □ Secure, HttpOnly, SameSite cookies
  □ Session timeout configured
  □ Session invalidation on logout
```

### API Security

```
□ API authentication required
□ Rate limiting implemented
□ Input validation on all endpoints
□ API versioning strategy
□ API gateway in use
□ API documentation secured
```

---

## 6. Data Security

### Data Protection

```
□ Data classification implemented
□ Encryption at rest
  □ Databases encrypted
  □ File storage encrypted
  □ Backups encrypted

□ Encryption in transit
  □ TLS 1.2+ for all connections
  □ Certificate management process
  □ Internal traffic encrypted

□ Data Loss Prevention (DLP) deployed
□ Rights Management (IRM) for sensitive docs
□ Data masking for non-production
```

### Data Management

```
□ Data inventory/mapping exists
□ Data retention policy implemented
□ Data disposal procedures documented
□ Backup strategy (3-2-1 rule)
  □ Backups tested regularly
  □ Offline/immutable backups exist
  □ Recovery procedures documented
```

---

## 7. Cloud Security

### Cloud Configuration

```
□ Cloud Security Posture Management (CSPM)
□ Identity and access properly configured
□ Network security groups restrictive
□ Storage publicly accessible = NO
□ Logging enabled for all services
□ Multi-region/availability zone deployment
□ Cost monitoring and alerts
```

### AWS Specific

```
□ CloudTrail enabled (all regions)
□ GuardDuty enabled
□ Config enabled with rules
□ SecurityHub enabled
□ S3 Block Public Access
□ Root account MFA enabled
□ IAM Access Analyzer enabled
```

### Azure Specific

```
□ Azure Security Center enabled
□ Azure Sentinel deployed
□ Azure AD Conditional Access
□ Network Security Groups configured
□ Key Vault for secrets
□ Defender for Cloud enabled
```

---

## 8. Security Operations

### Monitoring & Detection

```
□ SIEM deployed and tuned
□ Log sources identified and collected
  □ Authentication logs
  □ Firewall logs
  □ DNS logs
  □ Endpoint logs
  □ Application logs
  □ Cloud logs

□ Detection rules implemented
□ Alert thresholds appropriate
□ 24/7 monitoring coverage
□ Threat intelligence integrated
```

### Incident Response

```
□ IR team identified and trained
□ IR plan tested (tabletop exercise)
□ Escalation procedures documented
□ Communication templates ready
□ Legal/PR contacts established
□ Evidence preservation procedures
□ Lessons learned process exists
```

### Vulnerability Management

```
□ Regular vulnerability scanning
  □ Internal network (weekly)
  □ External perimeter (weekly)
  □ Web applications (monthly)
  □ Cloud infrastructure (continuous)

□ Penetration testing (annual)
□ Bug bounty program (if applicable)
□ Vulnerability prioritization process
□ Remediation SLAs defined and tracked
□ Exceptions documented and approved
```

---

## 9. Physical Security

```
□ Physical access controls at facilities
□ Visitor management process
□ Security cameras at entry points
□ Data center access restricted
□ Server room environmental controls
□ Equipment disposal procedures
□ Clean desk policy enforced
```

---

## 10. Security Awareness

```
□ Security awareness training mandatory
□ Training completion tracked (>95%)
□ Phishing simulations conducted
□ Role-specific training for developers
□ Privileged user training
□ Incident reporting process communicated
□ Security champions program
```

---

## Assessment Scoring

| Category | Weight | Score (0-100) | Weighted Score |
|----------|--------|---------------|----------------|
| Governance & Risk | 10% | | |
| Identity & Access | 15% | | |
| Network Security | 15% | | |
| Endpoint Security | 15% | | |
| Application Security | 15% | | |
| Data Security | 10% | | |
| Cloud Security | 10% | | |
| Security Operations | 10% | | |
| **TOTAL** | **100%** | | |

### Maturity Levels

| Score | Level | Description |
|-------|-------|-------------|
| 0-20 | Initial | Ad-hoc, undocumented |
| 21-40 | Developing | Some controls, inconsistent |
| 41-60 | Defined | Documented, partially implemented |
| 61-80 | Managed | Consistent, measured |
| 81-100 | Optimized | Continuous improvement |

---

## Recommendations Priority

| Priority | Timeframe | Criteria |
|----------|-----------|----------|
| Critical | < 30 days | Immediate exploitation risk |
| High | < 90 days | Significant risk reduction |
| Medium | < 180 days | Important security improvement |
| Low | < 365 days | Best practice enhancement |
