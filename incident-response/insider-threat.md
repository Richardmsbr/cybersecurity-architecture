# Insider Threat Incident Response Playbook

This playbook provides structured procedures for detecting, investigating, and responding to insider threat incidents involving malicious or negligent actions by employees, contractors, or business partners with authorized access.

---

## Insider Threat Classification

### Threat Actor Types

| Type | Description | Motivation | Risk Level |
|------|-------------|------------|------------|
| Malicious Insider | Intentional harm | Financial gain, revenge, ideology | Critical |
| Negligent Insider | Unintentional harm | Carelessness, lack of awareness | High |
| Compromised Insider | Account/credentials stolen | External attacker | Critical |
| Departing Employee | Data theft before leaving | Future employment, competition | High |
| Third-Party | Vendor/contractor abuse | Various | High |

### Threat Categories

```
    INSIDER THREAT CATEGORIES

    Data Theft:
    +----------------------------------+
    | Intellectual property theft      |
    | Customer data exfiltration       |
    | Financial information            |
    | Trade secrets                    |
    | Source code theft                |
    +----------------------------------+

    Sabotage:
    +----------------------------------+
    | System destruction               |
    | Data deletion/modification       |
    | Service disruption               |
    | Logic bombs                      |
    | Backdoor installation            |
    +----------------------------------+

    Fraud:
    +----------------------------------+
    | Financial fraud                  |
    | Expense abuse                    |
    | Procurement fraud                |
    | Time theft                       |
    | Embezzlement                     |
    +----------------------------------+

    Policy Violations:
    +----------------------------------+
    | Unauthorized access              |
    | Shadow IT                        |
    | Data handling violations         |
    | Access sharing                   |
    +----------------------------------+
```

---

## Detection Phase

### Behavioral Indicators

| Category | Indicators |
|----------|------------|
| Technical | Unusual access patterns, large downloads, after-hours activity |
| Behavioral | Disgruntlement, policy violations, conflicts with management |
| Situational | Resignation notice, performance issues, financial problems |
| Organizational | Access to sensitive data, privileged access, key position |

### Technical Indicators

| Source | Indicators |
|--------|------------|
| DLP | Sensitive data uploads, email attachments, USB transfers |
| UEBA | Anomalous behavior, peer group deviation |
| IAM | Privilege escalation, unauthorized access attempts |
| Endpoint | Unauthorized software, data staging |
| Network | Large transfers, unusual destinations |
| Email | Forwarding rules, personal email transfers |
| Cloud | Shadow IT, unauthorized sharing |

### Detection Sources

```
    INSIDER THREAT DETECTION

    User Behavior Analytics (UEBA):
    +----------------------------------+
    | Baseline behavior modeling       |
    | Anomaly detection                |
    | Risk scoring                     |
    | Peer comparison                  |
    +----------------------------------+
              |
              v
    Data Loss Prevention (DLP):
    +----------------------------------+
    | Content inspection               |
    | Policy enforcement               |
    | Exfiltration detection           |
    +----------------------------------+
              |
              v
    Access Monitoring:
    +----------------------------------+
    | Privileged access monitoring     |
    | Access pattern analysis          |
    | Authorization verification       |
    +----------------------------------+
              |
              v
    HR/Management Input:
    +----------------------------------+
    | Termination notices              |
    | Performance concerns             |
    | Reported concerns                |
    +----------------------------------+
```

---

## Investigation Phase

### Investigation Triggers

| Trigger | Response Level | Lead |
|---------|----------------|------|
| DLP alert - high severity | Full investigation | Security |
| UEBA high risk score | Assessment | Security |
| HR escalation | Coordinated investigation | HR + Security |
| Manager report | Assessment | HR + Security |
| Whistleblower | Confidential investigation | Legal + Security |
| Termination (high-risk) | Monitoring | Security + HR |

### Investigation Team

| Role | Responsibility |
|------|----------------|
| Investigation Lead | Overall coordination |
| Security Analyst | Technical investigation |
| HR Representative | Policy, employment law |
| Legal Counsel | Legal guidance, privilege |
| IT Operations | System access, logs |
| Management | Business context |

### Evidence Collection

| Source | Data to Collect |
|--------|-----------------|
| Email | Email content, attachments, forwarding rules |
| Endpoint | File access, USB activity, installed software |
| Network | Traffic logs, destinations, volumes |
| Cloud | File sharing, sync activity |
| Badging | Physical access logs |
| Application | Database queries, file downloads |
| IAM | Access logs, permission changes |

### Chain of Custody

```
    EVIDENCE CHAIN OF CUSTODY

    1. Identification
       - Document what was found
       - Timestamp and location
       - System/source identification

    2. Collection
       - Forensic image creation
       - Hash verification
       - Witness documentation

    3. Preservation
       - Secure storage
       - Access controls
       - Environmental controls

    4. Documentation
       - Evidence log
       - Handling records
       - Analysis notes

    5. Transfer
       - Signed custody transfer
       - Verification of integrity
       - Secure transport
```

---

## Legal Considerations

### Privacy and Legal Framework

| Consideration | Action |
|---------------|--------|
| Employment law | Consult HR, follow policy |
| Privacy regulations | Limit data collection to necessary |
| Legal privilege | Include legal counsel |
| Union agreements | Consider collective bargaining |
| Documentation | Maintain detailed records |

### Investigation Boundaries

| Permitted | Requires Approval | Not Permitted |
|-----------|-------------------|---------------|
| Review business systems | Personal device search | Illegal surveillance |
| Access company accounts | Extended monitoring | Privacy violations |
| Network traffic analysis | Physical surveillance | Discrimination |
| Endpoint forensics | Interview third parties | Entrapment |

---

## Response Phase

### Response Options

| Severity | Response Actions |
|----------|------------------|
| Critical (Active theft) | Immediate containment, access revocation |
| High (Confirmed violation) | Investigation, progressive discipline |
| Medium (Policy violation) | Warning, remediation, monitoring |
| Low (Negligence) | Training, awareness |

### Containment Actions

| Action | When to Use |
|--------|-------------|
| Access revocation | Confirmed malicious activity |
| Account suspension | Investigation in progress |
| Enhanced monitoring | Suspected activity |
| Physical access restriction | Sabotage risk |
| Asset recovery | Company property at risk |
| Network isolation | Active data exfiltration |

### Containment Decision Matrix

```
    CONTAINMENT DECISION

    Is there active
    data exfiltration?
           |
    +------+------+
    | Yes         | No
    v             v
    Immediate     Is the subject
    containment   still employed?
                  |
           +------+------+
           | Yes         | No
           v             v
           Coordinate    Focus on
           with HR       evidence
                         preservation
```

---

## Coordination with HR

### HR Engagement Points

| Phase | HR Role |
|-------|---------|
| Detection | Provide context, personnel records |
| Investigation | Employment law guidance, policy review |
| Response | Disciplinary process, termination |
| Recovery | Communication, policy updates |

### Termination Procedures

| Step | Action | Owner |
|------|--------|-------|
| 1 | Coordinate timing | HR + Security |
| 2 | Prepare access revocation | IT Security |
| 3 | Prepare asset recovery | IT |
| 4 | Conduct termination meeting | HR + Management |
| 5 | Execute access revocation | Security |
| 6 | Recover assets | IT |
| 7 | Exit interview | HR |
| 8 | Monitor for post-employment activity | Security |

---

## Departing Employee Procedures

### High-Risk Departure Indicators

| Indicator | Risk Level |
|-----------|------------|
| Access to sensitive IP | High |
| Going to competitor | High |
| Disgruntled departure | High |
| Privileged access | High |
| Short notice period | Medium |
| Remote worker | Medium |

### Departure Monitoring

```
    DEPARTING EMPLOYEE MONITORING

    Notice Period:
    +----------------------------------+
    | Enhanced DLP monitoring          |
    | UEBA risk score tracking         |
    | Access pattern analysis          |
    | Email/cloud activity review      |
    +----------------------------------+

    Departure Day:
    +----------------------------------+
    | Access revocation                |
    | Device recovery                  |
    | Account termination              |
    | Badge deactivation               |
    +----------------------------------+

    Post-Departure (30 days):
    +----------------------------------+
    | Monitor for access attempts      |
    | Review shared accounts           |
    | Verify data integrity            |
    | Monitor for data appearance      |
    +----------------------------------+
```

---

## Remediation and Recovery

### System Remediation

| Action | Purpose |
|--------|---------|
| Access review | Remove unauthorized access |
| Credential rotation | Address potential compromise |
| System audit | Verify integrity |
| Backdoor sweep | Remove persistence |
| Data audit | Assess data integrity |

### Process Improvements

| Category | Improvements |
|----------|-------------|
| Access control | Least privilege review |
| Monitoring | Enhanced UEBA, DLP |
| Training | Security awareness |
| Policy | Clear acceptable use |
| Off-boarding | Standardized process |

---

## Documentation and Reporting

### Investigation Report Template

```
INSIDER THREAT INVESTIGATION REPORT

Case ID: [IT-YYYY-NNN]
Classification: [Confidential]
Date: [Date]

EXECUTIVE SUMMARY
[Brief description of incident and outcome]

SUBJECT INFORMATION
- Name: [If appropriate]
- Position: [Role]
- Department: [Department]
- Employment dates: [Dates]

INCIDENT DETAILS
- Detection date: [Date]
- Detection method: [Source]
- Incident type: [Classification]

INVESTIGATION TIMELINE
[Chronological events]

EVIDENCE SUMMARY
- Digital evidence: [Summary]
- Physical evidence: [Summary]
- Witness statements: [Summary]

FINDINGS
[Detailed findings]

IMPACT ASSESSMENT
- Data affected: [Description]
- Systems affected: [Description]
- Business impact: [Description]

RESPONSE ACTIONS
[Actions taken]

RECOMMENDATIONS
[Future prevention]

ATTACHMENTS
[List of supporting documents]
```

### Metrics

| Metric | Measurement |
|--------|-------------|
| Detection time | Time from activity to detection |
| Investigation time | Time to complete investigation |
| False positive rate | Alerts vs. confirmed incidents |
| Data loss prevented | Quantity of data saved |
| Policy violations | Trend over time |

---

## Prevention Program

### Insider Threat Program Components

| Component | Description |
|-----------|-------------|
| Policy | Clear acceptable use, consequences |
| Training | Security awareness, reporting |
| Monitoring | UEBA, DLP, access logging |
| Access control | Least privilege, segregation of duties |
| Off-boarding | Standardized termination process |
| Culture | Open communication, reporting channels |

### Continuous Monitoring

| Layer | Monitoring |
|-------|------------|
| Identity | Privileged access, access patterns |
| Endpoint | File access, USB, applications |
| Network | Data transfers, destinations |
| Cloud | Sharing, sync, shadow IT |
| Email | Attachments, forwarding |
| Physical | Badge access, visitor logs |

---

## References

- NIST SP 800-53 Personnel Security Controls
- CERT Insider Threat Center Resources
- CISA Insider Threat Mitigation Guide

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
