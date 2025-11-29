# EDR/XDR Architecture and Operations

Endpoint Detection and Response (EDR) and Extended Detection and Response (XDR) provide visibility, detection, and response capabilities across endpoints and extended enterprise infrastructure.

---

## Architecture Overview

```
    EDR/XDR ARCHITECTURE

    DATA SOURCES                    PLATFORM                    OUTPUTS
    +-----------+                  +----------+                +----------+
    | Endpoints |----------------->|          |--------------->| Alerts   |
    +-----------+                  |          |                +----------+
                                   |          |
    +-----------+                  |   XDR    |                +----------+
    | Network   |----------------->|  Platform|--------------->| Dashboards|
    +-----------+                  |          |                +----------+
                                   |          |
    +-----------+                  |          |                +----------+
    | Cloud     |----------------->|          |--------------->| Reports  |
    +-----------+                  |          |                +----------+
                                   |          |
    +-----------+                  |          |                +----------+
    | Identity  |----------------->|          |--------------->| Response |
    +-----------+                  +----------+                +----------+

    EDR Focus: Endpoints only
    XDR Focus: Cross-domain correlation (Endpoint + Network + Cloud + Identity)
```

---

## EDR Capabilities

### Core Functions

| Function | Description | Use Case |
|----------|-------------|----------|
| Telemetry Collection | Continuous endpoint data gathering | Baseline, investigation |
| Threat Detection | Signature and behavioral detection | Real-time alerting |
| Incident Response | Remote containment and remediation | Threat neutralization |
| Forensic Analysis | Historical data analysis | Investigation |
| Threat Hunting | Proactive threat search | Advanced threat discovery |

### Data Collection

| Data Type | Description | Retention |
|-----------|-------------|-----------|
| Process execution | Process creation, termination, lineage | 30-90 days |
| File operations | Create, modify, delete, rename | 30-90 days |
| Registry changes | Key creation, modification, deletion | 30-90 days |
| Network connections | Local and remote connections | 30-90 days |
| User activity | Logon, logoff, privilege use | 30-90 days |
| Module loads | DLL, driver loading | 30-90 days |

### Detection Methods

```
    EDR DETECTION LAYERS

    Layer 1: Signature-Based
    +----------------------------------+
    | Known malware hashes             |
    | YARA rules                       |
    | IOC matching                     |
    +----------------------------------+

    Layer 2: Behavioral
    +----------------------------------+
    | Process behavior patterns        |
    | MITRE ATT&CK mapping             |
    | Anomaly detection                |
    | Machine learning models          |
    +----------------------------------+

    Layer 3: Threat Intelligence
    +----------------------------------+
    | External threat feeds            |
    | Community intelligence           |
    | Vendor research                  |
    +----------------------------------+
```

---

## XDR Architecture

### Integration Points

| Domain | Data Sources | Integration Method |
|--------|--------------|-------------------|
| Endpoint | EDR agents | Native integration |
| Network | Firewall, IDS/IPS, NDR | Syslog, API |
| Email | Email gateway, O365, Google | API |
| Cloud | AWS, Azure, GCP | API, CloudTrail |
| Identity | AD, Azure AD, Okta | API, logs |

### Correlation Engine

```
    XDR CORRELATION

    Input Streams:
    [Endpoint] + [Network] + [Email] + [Cloud] + [Identity]
                              |
                              v
                    +-------------------+
                    | Normalization     |
                    | - Data mapping    |
                    | - Time sync       |
                    | - Entity enrichment|
                    +-------------------+
                              |
                              v
                    +-------------------+
                    | Correlation       |
                    | - Rule-based      |
                    | - ML-based        |
                    | - Graph analysis  |
                    +-------------------+
                              |
                              v
                    +-------------------+
                    | Detection         |
                    | - Single-domain   |
                    | - Cross-domain    |
                    | - Attack chain    |
                    +-------------------+
```

### XDR Use Cases

| Use Case | Domains | Detection Logic |
|----------|---------|-----------------|
| Phishing to compromise | Email + Endpoint | Malicious email followed by execution |
| Lateral movement | Endpoint + Network + Identity | Auth anomaly + network scan + process execution |
| Data exfiltration | Endpoint + Network + Cloud | File staging + large transfer + cloud upload |
| Account takeover | Identity + Email + Cloud | Auth anomaly + email rule + cloud access |
| Ransomware | Endpoint + Network | Encryption behavior + C2 communication |

---

## Deployment Architecture

### Agent Deployment

| Environment | Deployment Method | Considerations |
|-------------|------------------|----------------|
| Windows | GPO, SCCM, Intune | Coverage, performance |
| macOS | Jamf, MDM | User approval for extensions |
| Linux | Ansible, Puppet | Kernel compatibility |
| Virtual | Golden image, automation | Clone detection |
| Container | Sidecar, host-based | Resource constraints |

### High Availability

```
    EDR/XDR HIGH AVAILABILITY

    Cloud-Based:
    +----------------------------------+
    | Multi-region deployment          |
    | Automatic failover               |
    | Data replication                 |
    +----------------------------------+

    On-Premise:
    +----------------------------------+
    | Primary + Secondary servers      |
    | Database clustering              |
    | Load balancing                   |
    +----------------------------------+

    Hybrid:
    +----------------------------------+
    | Local collection/caching         |
    | Cloud analysis/storage           |
    | Resilient connectivity           |
    +----------------------------------+
```

---

## Detection Engineering

### Custom Detection Rules

| Rule Type | Use Case | Example |
|-----------|----------|---------|
| Process | Suspicious execution | LOLBIN abuse |
| File | Malicious artifacts | Ransomware extensions |
| Network | C2 communication | Beacon patterns |
| Behavior | Attack patterns | Credential dumping |
| Cross-domain | Attack chain | Phishing to lateral movement |

### MITRE ATT&CK Mapping

| Tactic | Key Techniques | Detection Priority |
|--------|----------------|-------------------|
| Initial Access | T1566 Phishing | High |
| Execution | T1059 Command and Script | High |
| Persistence | T1547 Boot/Logon Autostart | High |
| Privilege Escalation | T1548 Abuse Elevation | High |
| Defense Evasion | T1562 Impair Defenses | Critical |
| Credential Access | T1003 OS Credential Dumping | Critical |
| Discovery | T1087 Account Discovery | Medium |
| Lateral Movement | T1021 Remote Services | High |
| Collection | T1005 Data from Local System | Medium |
| Exfiltration | T1041 Exfiltration Over C2 | High |

### Detection Coverage Analysis

```
    ATT&CK COVERAGE HEAT MAP

    Tactic                  Coverage
    Initial Access          [####----] 50%
    Execution               [######--] 75%
    Persistence             [#####---] 62%
    Privilege Escalation    [####----] 50%
    Defense Evasion         [###-----] 37%
    Credential Access       [######--] 75%
    Discovery               [###-----] 37%
    Lateral Movement        [#####---] 62%
    Collection              [####----] 50%
    Exfiltration            [####----] 50%
    Command and Control     [######--] 75%
    Impact                  [#####---] 62%

    Priority: Improve Defense Evasion, Discovery coverage
```

---

## Response Capabilities

### Automated Response

| Trigger | Action | Risk |
|---------|--------|------|
| Confirmed malware | Isolate host | Service disruption |
| Credential theft | Disable account | User impact |
| C2 communication | Block network | False positive |
| Ransomware behavior | Kill process, isolate | Data loss if false |

### Manual Response Actions

| Action | Use Case | Execution |
|--------|----------|-----------|
| Network isolation | Contain threat | Console command |
| Process termination | Stop malware | Remote kill |
| File quarantine | Preserve evidence | Automatic/manual |
| Memory collection | Forensic analysis | Remote acquisition |
| Live terminal | Investigation | Remote shell |

### Response Playbook Integration

```
    EDR RESPONSE AUTOMATION

    Detection
        |
        v
    [Severity Assessment]
        |
        +---> Critical --> Auto-Isolate + Alert SOC
        |
        +---> High -----> Alert SOC + Collect Artifacts
        |
        +---> Medium ---> Queue for Investigation
        |
        +---> Low ------> Log and Monitor
```

---

## Threat Hunting

### Hunt Hypothesis Types

| Type | Description | Example |
|------|-------------|---------|
| Intelligence-driven | Based on threat intel | APT group TTPs |
| Behavior-driven | Based on suspicious patterns | Unusual PowerShell |
| Anomaly-driven | Based on deviations | New persistence |
| Compliance-driven | Based on policy | Unauthorized software |

### Hunt Queries

```
    COMMON HUNT QUERIES

    Credential Access:
    - LSASS access by non-system processes
    - Mimikatz-like behavior
    - DCSync activity

    Persistence:
    - New scheduled tasks
    - Run key modifications
    - New services

    Lateral Movement:
    - PsExec-like activity
    - WMI remote execution
    - RDP from unusual sources

    Defense Evasion:
    - Process injection
    - AMSI bypass
    - Log clearing
```

---

## Performance and Tuning

### Agent Performance

| Metric | Target | Threshold |
|--------|--------|-----------|
| CPU usage | < 2% average | < 5% peak |
| Memory usage | < 200MB | < 500MB |
| Disk I/O | Minimal impact | < 5% increase |
| Network bandwidth | < 1MB/hr | < 5MB/hr |

### Alert Tuning

| Issue | Solution |
|-------|----------|
| False positives | Exclusion rules, ML tuning |
| Alert fatigue | Severity adjustment, correlation |
| Missed detections | Rule enhancement, coverage analysis |
| Performance impact | Scan scheduling, exclusions |

---

## Metrics and KPIs

| Metric | Target | Measurement |
|--------|--------|-------------|
| Endpoint coverage | >98% | Agent deployment rate |
| Detection rate | >95% | Known threat detection |
| MTTD | < 1 hour | Time to detect |
| MTTR | < 4 hours | Time to respond |
| False positive rate | < 5% | Alerts/confirmed incidents |

---

## References

- MITRE ATT&CK Framework
- NIST SP 800-83 Malware Incident Prevention
- Gartner EDR/XDR Market Guide

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
