# Data Breach Incident Response Playbook

This playbook provides structured procedures for responding to confirmed or suspected data breach incidents involving unauthorized access, acquisition, or exfiltration of sensitive data.

---

## Severity Classification

| Level | Description | Examples | Response Time |
|-------|-------------|----------|---------------|
| Critical | Large-scale PII/PHI breach, active exfiltration | >10,000 records, regulated data | Immediate |
| High | Confirmed breach of sensitive data | Financial records, credentials | < 1 hour |
| Medium | Potential exposure, limited scope | Single system, encrypted data | < 4 hours |
| Low | Suspected unauthorized access, no exfiltration | Failed attempts, contained | < 24 hours |

---

## Initial Response (0-2 Hours)

### Detection Triggers

```
    DATA BREACH INDICATORS

    Network:
    - Unusual data transfers to external IPs
    - Large volume outbound traffic
    - Connections to known malicious IPs
    - DNS exfiltration patterns

    System:
    - Unauthorized database queries
    - Mass file access/copying
    - Credential harvesting tools
    - Archive creation on sensitive shares

    Application:
    - SQL injection attempts
    - API abuse patterns
    - Bulk data export requests
    - Unauthorized admin access
```

### Immediate Actions

| Step | Action | Owner | Timeline |
|------|--------|-------|----------|
| 1 | Activate incident response team | IR Lead | 0-15 min |
| 2 | Assess scope and severity | Security Analyst | 15-30 min |
| 3 | Preserve volatile evidence | Forensics | 30-60 min |
| 4 | Initiate containment strategy | IR Team | 60-120 min |
| 5 | Notify executive leadership | CISO | Within 2 hours |

### Evidence Collection Checklist

```
[ ] Network flow data
[ ] Firewall logs
[ ] Proxy logs
[ ] DNS query logs
[ ] Database audit logs
[ ] Application logs
[ ] Access control logs
[ ] Endpoint telemetry
[ ] Memory dumps (if applicable)
[ ] Disk images (critical systems)
```

---

## Containment (2-24 Hours)

### Short-term Containment

| Action | Purpose | Risk Consideration |
|--------|---------|-------------------|
| Isolate affected systems | Prevent lateral movement | Service disruption |
| Block malicious IPs/domains | Stop active exfiltration | False positives |
| Disable compromised accounts | Prevent further access | User impact |
| Revoke API keys/tokens | Close access vectors | Integration failures |
| Enable enhanced logging | Capture ongoing activity | Storage capacity |

### Network Segmentation

```
    CONTAINMENT NETWORK DIAGRAM

    [Internet]
         |
    +----+----+ BLOCK
    | Firewall |<-------- Malicious IPs/Domains
    +----+----+
         |
    +----+----+
    |  DMZ    | ISOLATE
    +----+----+<-------- Compromised Web Servers
         |
    +----+----+
    | Internal |
    +----+----+
         |
    +----+----+ SEGMENT
    | Data    |<-------- Enhanced monitoring
    | Tier    |          Restricted access
    +---------+
```

### Long-term Containment

| Action | Implementation |
|--------|---------------|
| Implement network segmentation | VLAN isolation, microsegmentation |
| Deploy additional monitoring | Enhanced logging, packet capture |
| Credential rotation | Force password reset, rotate keys |
| Patch identified vulnerabilities | Emergency patch deployment |
| Harden affected systems | Configuration baseline |

---

## Data Breach Assessment

### Scope Determination

| Question | Investigation Method |
|----------|---------------------|
| What data was accessed? | Database query logs, file access logs |
| How much data was exposed? | Record counts, file sizes |
| Who was affected? | Data subject identification |
| How long did access persist? | Timeline analysis |
| Was data exfiltrated? | Network traffic analysis, DLP logs |

### Data Classification Analysis

| Data Type | Records | Regulatory Impact | Notification Required |
|-----------|---------|-------------------|----------------------|
| PII (Names, SSN) | Count | GDPR, CCPA, State laws | Yes |
| PHI (Health data) | Count | HIPAA | Yes |
| Financial (PCI) | Count | PCI-DSS | Yes |
| Credentials | Count | Various | Yes |
| Intellectual Property | Files | Trade secret laws | Depends |

### Impact Assessment Matrix

```
    BREACH IMPACT ASSESSMENT

                        DATA SENSITIVITY
                    Low     Medium    High    Critical
    RECORDS
    AFFECTED

    >100,000        Medium  High      Critical Critical
    10,000-100,000  Low     Medium    High     Critical
    1,000-10,000    Low     Medium    Medium   High
    <1,000          Low     Low       Medium   High
```

---

## Eradication

### Root Cause Analysis

| Phase | Activities |
|-------|------------|
| Attack Vector | How did attacker gain initial access? |
| Lateral Movement | How did attacker reach data? |
| Data Access | What methods were used to access/extract data? |
| Persistence | Were backdoors or persistence mechanisms installed? |
| Timeline | Complete timeline of attacker activity |

### Eradication Actions

| Action | Verification |
|--------|-------------|
| Remove malware/tools | AV/EDR scans, manual verification |
| Close attack vectors | Penetration testing, vulnerability scanning |
| Rebuild compromised systems | Clean OS installation, hardened config |
| Rotate all credentials | Verify new credentials in use |
| Patch vulnerabilities | Vulnerability scan confirmation |

---

## Recovery

### System Restoration

| Priority | Systems | Validation |
|----------|---------|------------|
| 1 | Authentication systems | Security testing |
| 2 | Database servers | Integrity verification |
| 3 | Application servers | Functional testing |
| 4 | User endpoints | Security baseline |

### Monitoring Enhancement

```
    POST-BREACH MONITORING

    Layer 1: Network
    - Full packet capture (affected segments)
    - Enhanced IDS signatures
    - Threat intelligence feeds

    Layer 2: Host
    - EDR enhanced monitoring
    - File integrity monitoring
    - Process monitoring

    Layer 3: Application
    - Database activity monitoring
    - API access logging
    - User behavior analytics

    Layer 4: Data
    - DLP enforcement
    - Data access alerting
    - Encryption verification
```

---

## Notification Requirements

### Regulatory Notification Matrix

| Regulation | Threshold | Timeline | Authority |
|------------|-----------|----------|-----------|
| GDPR | Any personal data | 72 hours | Supervisory Authority |
| HIPAA | Unsecured PHI | 60 days | HHS OCR |
| CCPA | California residents | Expedient | CA AG |
| PCI-DSS | Cardholder data | Varies | Card brands |
| State Laws | Varies by state | 30-90 days | State AG |

### Notification Workflow

```
    NOTIFICATION PROCESS

    [Breach Confirmed]
          |
          v
    [Legal Assessment]
          |
    +-----+-----+
    |           |
    v           v
    [Regulatory]  [Affected Parties]
    Notification   Notification
          |           |
          v           v
    [72 hrs max]  [Without delay]
          |           |
          v           v
    [Document]    [Support Services]
    Submission    Credit monitoring
```

### Notification Content

| Element | Description |
|---------|-------------|
| Nature of breach | What happened |
| Data involved | What data was affected |
| Timing | When it occurred, when discovered |
| Impact | Potential consequences |
| Actions taken | Response measures |
| Recommended actions | Steps for affected parties |
| Contact information | How to reach organization |

---

## Communication Plan

### Internal Communication

| Audience | Timing | Content | Channel |
|----------|--------|---------|---------|
| Executive Team | Immediate | Full details, business impact | Secure briefing |
| Legal | Immediate | All facts, evidence | Privileged communication |
| IT Teams | Immediate | Technical details, actions | Secure channel |
| All Employees | As appropriate | Need-to-know basis | Official channels |

### External Communication

| Audience | Timing | Content | Channel |
|----------|--------|---------|---------|
| Regulators | Per requirements | Formal notification | Official submission |
| Affected Parties | After legal review | Clear, actionable | Direct communication |
| Media | If required | Prepared statement | PR team |
| Partners | As needed | Relevant impact | Account management |

---

## Post-Incident Activities

### Lessons Learned

| Category | Questions |
|----------|-----------|
| Detection | How was breach discovered? Could we detect sooner? |
| Response | Was response timely and effective? |
| Containment | Were containment measures adequate? |
| Communication | Was communication clear and timely? |
| Recovery | Was recovery efficient? |

### Remediation Tracking

| Finding | Remediation | Owner | Due Date | Status |
|---------|-------------|-------|----------|--------|
| | | | | |

### Security Improvements

| Control Enhancement | Implementation Timeline |
|---------------------|------------------------|
| Data Loss Prevention | 30 days |
| Database Activity Monitoring | 45 days |
| Enhanced access controls | 30 days |
| Encryption expansion | 60 days |
| Security awareness training | 14 days |

---

## Documentation Requirements

### Incident Documentation

```
DATA BREACH INCIDENT REPORT

Incident ID: [DB-YYYY-NNN]
Date Discovered: [Date]
Date Reported: [Date]

EXECUTIVE SUMMARY
[Brief description of incident]

TIMELINE
[Chronological events]

SCOPE
- Records affected: [Number]
- Data types: [List]
- Systems involved: [List]
- Duration: [Timeframe]

ROOT CAUSE
[Technical explanation]

RESPONSE ACTIONS
[Actions taken]

NOTIFICATIONS
- Regulators: [List with dates]
- Affected parties: [Number, date]
- Other: [List]

REMEDIATION
[Security improvements]

LESSONS LEARNED
[Key takeaways]
```

---

## References

- NIST SP 800-61 Computer Security Incident Handling Guide
- SANS Incident Handler's Handbook
- State Breach Notification Laws
- GDPR Article 33-34
- HIPAA Breach Notification Rule

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
