# Security Monitoring Operations

Security monitoring provides continuous visibility into security events, enabling detection, investigation, and response to threats across the enterprise environment.

---

## Monitoring Architecture

```
    SECURITY MONITORING ARCHITECTURE

    DATA SOURCES                    PROCESSING               ANALYSIS
    +-----------+                  +------------+           +----------+
    | Endpoints |----------------->|            |---------->| SIEM     |
    +-----------+                  |            |           +----------+
                                   |   Log      |
    +-----------+                  |   Mgmt     |           +----------+
    | Network   |----------------->|   Platform |---------->| UEBA     |
    +-----------+                  |            |           +----------+
                                   |            |
    +-----------+                  |            |           +----------+
    | Cloud     |----------------->|            |---------->| NDR      |
    +-----------+                  |            |           +----------+
                                   |            |
    +-----------+                  +------------+           +----------+
    | Identity  |---------------------------------->------->| SOC      |
    +-----------+                                           | Analysts |
                                                            +----------+
```

---

## Log Collection

### Critical Log Sources

| Source | Log Type | Priority |
|--------|----------|----------|
| Domain Controllers | Security events | Critical |
| Firewalls | Traffic, connections | Critical |
| VPN | Authentication | Critical |
| Web Servers | Access, error | High |
| DNS | Query logs | High |
| Proxy | Web access | High |
| Email Gateway | Mail flow | High |
| Database | Audit logs | High |
| Cloud (AWS/Azure/GCP) | Activity logs | Critical |
| EDR | Endpoint telemetry | Critical |

### Log Requirements

| Requirement | Specification |
|-------------|---------------|
| Retention | 90 days hot, 1 year cold |
| Timestamp | UTC, NTP synchronized |
| Format | Structured (JSON, CEF) |
| Integrity | Hash verification |
| Transport | Encrypted (TLS) |
| Availability | 99.9% uptime |

### Collection Methods

```
    LOG COLLECTION METHODS

    Agent-Based:
    +----------------------------------+
    | Lightweight agent on system      |
    | Reliable delivery                |
    | Filtering at source              |
    +----------------------------------+

    Agentless:
    +----------------------------------+
    | Syslog, WMI, API                 |
    | No installation required         |
    | Network-dependent                |
    +----------------------------------+

    Network Tap:
    +----------------------------------+
    | Full packet capture              |
    | No system impact                 |
    | High storage requirements        |
    +----------------------------------+
```

---

## Detection Strategy

### Detection Types

| Type | Description | Example |
|------|-------------|---------|
| Signature | Known patterns | YARA, Snort rules |
| Anomaly | Deviation from baseline | UEBA |
| Behavioral | Activity patterns | MITRE ATT&CK |
| Threshold | Volume-based | Failed logins > 10 |
| Correlation | Multi-event patterns | Attack chain |

### Detection Coverage

```
    MITRE ATT&CK COVERAGE

    Tactic                  Detection Rules
    Initial Access          [####----] 50%
    Execution               [######--] 75%
    Persistence             [#####---] 62%
    Privilege Escalation    [####----] 50%
    Defense Evasion         [###-----] 37%
    Credential Access       [######--] 75%
    Discovery               [###-----] 37%
    Lateral Movement        [#####---] 62%
    Collection              [####----] 50%
    Command & Control       [######--] 75%
    Exfiltration            [####----] 50%

    Target: >70% coverage for all tactics
```

### Alert Prioritization

| Severity | Criteria | Response |
|----------|----------|----------|
| Critical | Active compromise, data loss | Immediate |
| High | Confirmed attack, high risk | < 1 hour |
| Medium | Suspicious activity | < 4 hours |
| Low | Policy violation, noise | < 24 hours |
| Info | Awareness only | Review in batch |

---

## SOC Operations

### SOC Tiers

| Tier | Role | Responsibilities |
|------|------|------------------|
| L1 | Alert Analyst | Triage, initial investigation |
| L2 | Incident Analyst | Deep investigation, containment |
| L3 | Threat Hunter | Proactive hunting, advanced analysis |
| L4 | SOC Engineer | Tool development, tuning |

### Shift Coverage

```
    SOC COVERAGE MODEL

    24/7 Coverage:
    +---+---+---+---+---+---+---+---+
    | S | S | S | S | S | S | S | S |
    +---+---+---+---+---+---+---+---+
    |   Day Shift   |  Night Shift  |
    |   (8hr)       |    (8hr)      |
    +---------------+---------------+

    Follow-the-Sun:
    Americas  -->  Europe  -->  Asia Pacific
       |            |              |
    +--+--+      +--+--+       +--+--+
    |06-14|      |14-22|       |22-06|
    +-----+      +-----+       +-----+
```

### Alert Handling Process

```
    ALERT TRIAGE WORKFLOW

    [Alert Triggered]
          |
          v
    [Initial Triage]
    - Validate alert
    - Check duplicates
    - Gather context
          |
          v
    [Severity Assessment]
          |
    +-----+-----+-----+
    |     |     |     |
    v     v     v     v
    [Crit][High][Med][Low]
    |     |     |
    v     v     v
    [Escalate][Investigate][Queue]
          |
          v
    [Document & Close]
```

---

## Use Case Development

### Use Case Categories

| Category | Examples |
|----------|----------|
| Authentication | Brute force, impossible travel |
| Malware | Execution patterns, C2 |
| Data Loss | Large transfers, unauthorized access |
| Insider Threat | Policy violations, data hoarding |
| Compliance | PCI, HIPAA violations |

### Use Case Template

```
USE CASE DOCUMENTATION

Name: Brute Force Authentication Attack
ID: UC-AUTH-001

Description:
Detect multiple failed authentication attempts
indicating potential brute force attack.

Data Sources:
- Domain Controller security logs
- VPN authentication logs
- Cloud identity logs

Detection Logic:
- >10 failed logins in 5 minutes
- From single source IP
- To single or multiple accounts

Response:
1. Validate alert accuracy
2. Block source IP if external
3. Reset password if successful login
4. Investigate for compromise

Tuning History:
- v1: 5 attempts, high FP rate
- v2: 10 attempts, acceptable FP rate
```

---

## Threat Hunting

### Hunt Types

| Type | Trigger | Method |
|------|---------|--------|
| Intelligence-Driven | Threat intel | IOC search |
| Hypothesis-Driven | TTP analysis | Behavioral search |
| Anomaly-Driven | Baseline deviation | Statistical analysis |
| Compliance-Driven | Policy requirements | Audit queries |

### Hunt Process

```
    THREAT HUNTING PROCESS

    1. HYPOTHESIS
    +----------------------------------+
    | What threat are we hunting?      |
    | Based on: Intel, TTPs, Anomalies |
    +----------------------------------+
              |
              v
    2. DATA COLLECTION
    +----------------------------------+
    | What data do we need?            |
    | Logs, NetFlow, Endpoint, etc.    |
    +----------------------------------+
              |
              v
    3. INVESTIGATION
    +----------------------------------+
    | Execute hunt queries             |
    | Analyze results                  |
    | Iterate and refine               |
    +----------------------------------+
              |
              v
    4. FINDINGS
    +----------------------------------+
    | Document discoveries             |
    | Create detections                |
    | Report to stakeholders           |
    +----------------------------------+
```

### Hunt Queries Examples

| Hunt | Query Focus |
|------|-------------|
| Persistence | New scheduled tasks, services, run keys |
| Lateral Movement | PsExec, WMI, RDP anomalies |
| Credential Access | LSASS access, DCSync |
| Exfiltration | Large outbound transfers |
| C2 | Beacon patterns, DNS anomalies |

---

## Performance Metrics

### Operational Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| MTTD | < 1 hour | Detection time |
| MTTR | < 4 hours | Response time |
| Alert Volume | Track trend | Daily count |
| False Positive Rate | < 20% | Alerts/Incidents |
| Escalation Rate | Track trend | L1 to L2 |

### Coverage Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Log Source Coverage | 100% critical | Sources collecting |
| Detection Coverage | >70% ATT&CK | Techniques covered |
| Asset Coverage | 100% | Systems monitored |
| Uptime | 99.9% | Platform availability |

### Reporting

```
    MONITORING DASHBOARD

    +------------------+------------------+
    |   ALERT VOLUME   |   INCIDENT       |
    |   (24 Hours)     |   SEVERITY       |
    |                  |                  |
    |   Total: ####    | Critical: #      |
    |   FP: ###        | High: ###        |
    |   Incidents: ##  | Medium: #####    |
    +------------------+------------------+
    |   MEAN TIME TO   |   TOP ALERT      |
    |   DETECT/RESPOND |   TYPES          |
    |                  |                  |
    |   MTTD: ##min    | 1. Auth Failures |
    |   MTTR: ##hr     | 2. Malware       |
    |                  | 3. Policy Viol   |
    +------------------+------------------+
```

---

## Continuous Improvement

### Improvement Areas

| Area | Activities |
|------|------------|
| Detection | New rules, coverage gaps |
| Tuning | False positive reduction |
| Automation | Playbook enhancement |
| Training | Analyst skill development |
| Tools | Platform optimization |

### Review Cadence

| Review | Frequency | Focus |
|--------|-----------|-------|
| Alert Tuning | Weekly | FP reduction |
| Use Case Review | Monthly | Effectiveness |
| Coverage Analysis | Quarterly | Gap identification |
| Tool Assessment | Annual | Platform evaluation |

---

## References

- NIST SP 800-92 Log Management Guide
- MITRE ATT&CK Framework
- SANS Security Operations

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
