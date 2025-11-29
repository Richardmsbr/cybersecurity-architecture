# Diamond Model of Intrusion Analysis

The Diamond Model is an analytic framework used to describe and track cyber intrusion activity. It establishes a formal method for correlating intrusion events and supports both tactical and strategic intelligence analysis.

---

## Overview

Developed by Sergio Caltagirone, Andrew Pendergast, and Christopher Betz, the Diamond Model describes the atomic element of any intrusion activity as a relationship between four core features: Adversary, Capability, Infrastructure, and Victim.

```
    THE DIAMOND MODEL

                        ADVERSARY
                            *
                           /|\
                          / | \
                         /  |  \
                        /   |   \
                       /    |    \
            CAPABILITY *----+----* INFRASTRUCTURE
                       \    |    /
                        \   |   /
                         \  |  /
                          \ | /
                           \|/
                            *
                         VICTIM

    The diamond shape represents the core relationships
    in any intrusion event.
```

---

## Core Features

### Adversary

The adversary is the actor/organization responsible for utilizing a capability against the victim to achieve their intent.

| Attribute | Description | Example |
|-----------|-------------|---------|
| Operator | Individual executing the attack | APT29 Operator |
| Customer | Entity directing the operation | Russian Intelligence |
| Intent | Goal of the intrusion | Espionage, Financial Gain |
| Attribution | Confidence level | Confirmed, Suspected, Unknown |

### Capability

The capability describes the tools, techniques, and procedures (TTPs) employed by the adversary.

| Attribute | Description | Example |
|-----------|-------------|---------|
| Capability | Tool or technique used | Cobalt Strike, Mimikatz |
| Arsenal | Full set of capabilities | Custom malware suite |
| Capacity | Ability to use capability | Zero-day vs. known exploit |

### Infrastructure

Infrastructure describes the physical and logical communication structures used by the adversary.

| Attribute | Description | Example |
|-----------|-------------|---------|
| Type 1 | Fully controlled by adversary | Owned C2 server |
| Type 2 | Compromised third-party | Hacked web server |
| Service Provider | Infrastructure provider | Cloud hosting, DNS |

### Victim

The victim is the target of the adversary's activities.

| Attribute | Description | Example |
|-----------|-------------|---------|
| Persona | Target identity | Organization, Individual |
| Assets | Targeted resources | Credentials, Data, Systems |
| Network | Victim's infrastructure | IP ranges, Domains |

---

## Meta-Features

Meta-features provide context to the core diamond and extend analytical capabilities.

### Timestamp

```
    EVENT TIMELINE

    T0          T1          T2          T3          T4
    |           |           |           |           |
    v           v           v           v           v
    [Recon]---->[Delivery]-->[Exploit]-->[C2]------>[Exfil]

    Time analysis reveals:
    - Attack duration
    - Operational tempo
    - Working hours (timezone)
    - Campaign patterns
```

### Phase

| Phase | Description | Diamond Focus |
|-------|-------------|---------------|
| Reconnaissance | Target identification | Victim profiling |
| Weaponization | Capability development | Capability creation |
| Delivery | Transport to victim | Infrastructure use |
| Exploitation | Vulnerability trigger | Capability execution |
| Installation | Persistence establishment | Victim compromise |
| Command & Control | Communication channel | Infrastructure use |
| Actions on Objectives | Goal achievement | Adversary intent |

### Result

| Result Type | Description | Example |
|-------------|-------------|---------|
| Success | Attack achieved goal | Data exfiltrated |
| Failure | Attack did not succeed | Blocked by firewall |
| Unknown | Outcome undetermined | Incomplete investigation |

### Direction

```
    ATTACK DIRECTION ANALYSIS

    Adversary-to-Infrastructure:
    [Adversary] ---------> [C2 Server]

    Infrastructure-to-Victim:
    [C2 Server] ---------> [Target Network]

    Victim-to-Infrastructure:
    [Compromised Host] --> [Exfil Server]

    Bidirectional:
    [Beacon] <-----------> [C2 Server]
```

### Methodology

| Methodology | Description |
|-------------|-------------|
| Phishing | Social engineering via email |
| Watering Hole | Compromise of trusted sites |
| Supply Chain | Third-party compromise |
| Direct Exploitation | Network service exploitation |

### Resources

| Resource Type | Description |
|---------------|-------------|
| Software | Malware, tools |
| Knowledge | Vulnerabilities, TTPs |
| Hardware | Physical devices |
| Funds | Financial resources |
| Access | Credentials, insider |

---

## Activity Threads

Activity threads connect multiple diamond events to reveal adversary operations over time.

### Activity Thread Visualization

```
    ACTIVITY THREAD: APT CAMPAIGN

    Event 1 (T0)              Event 2 (T1)              Event 3 (T2)
    +-------------+           +-------------+           +-------------+
    |  Adversary  |           |  Adversary  |           |  Adversary  |
    |   APT-X     |           |   APT-X     |           |   APT-X     |
    +------+------+           +------+------+           +------+------+
           |                         |                         |
    +------+------+           +------+------+           +------+------+
    | Capability  |           | Capability  |           | Capability  |
    | Spearphish  |---------->|  Backdoor   |---------->|  Mimikatz   |
    +------+------+           +------+------+           +------+------+
           |                         |                         |
    +------+------+           +------+------+           +------+------+
    |Infrastructure|          |Infrastructure|          |Infrastructure|
    | Malicious   |           |   C2 Server  |          |  Exfil      |
    | Domain      |           |              |          |  Server     |
    +------+------+           +------+------+           +------+------+
           |                         |                         |
    +------+------+           +------+------+           +------+------+
    |   Victim    |           |   Victim    |           |   Victim    |
    | User Email  |---------->| Workstation |---------->| Domain Ctrl |
    +-------------+           +-------------+           +-------------+
```

### Thread Analysis Benefits

| Analysis Type | Insight Gained |
|---------------|----------------|
| Temporal | Attack timeline and duration |
| Behavioral | Adversary TTPs and patterns |
| Pivoting | Lateral movement paths |
| Attribution | Consistent adversary indicators |

---

## Activity Groups

Activity groups cluster related diamonds that share features, indicating common adversary operations.

### Grouping Criteria

```
    ACTIVITY GROUP CLUSTERING

    +-----------------------------------------------------------+
    |                     ACTIVITY GROUP: APT-X                  |
    |                                                            |
    |  Shared Adversary Features:                                |
    |  - Working hours: UTC+3                                    |
    |  - Target sector: Defense                                  |
    |  - Language artifacts: Russian                             |
    |                                                            |
    |  +-------------+  +-------------+  +-------------+         |
    |  | Diamond 1   |  | Diamond 2   |  | Diamond 3   |         |
    |  | Campaign A  |  | Campaign B  |  | Campaign C  |         |
    |  +-------------+  +-------------+  +-------------+         |
    |                                                            |
    |  Shared Infrastructure:                                    |
    |  - C2: 192.168.x.x/24 range                               |
    |  - Hosting: Bulletproof provider Y                         |
    |  - DNS: Fast-flux network                                  |
    |                                                            |
    |  Shared Capabilities:                                      |
    |  - Custom RAT variant                                      |
    |  - Same encryption algorithm                               |
    |  - Identical infection chain                               |
    +-----------------------------------------------------------+
```

---

## Analytical Pivoting

The Diamond Model enables systematic pivoting between features to expand intelligence.

### Pivot Strategies

```
    PIVOTING METHODOLOGY

    Starting Point: Known Malicious IP (Infrastructure)

    [Infrastructure]
         |
         +---> Pivot to Capability
         |     "What malware uses this C2?"
         |
         +---> Pivot to Adversary
         |     "Who registered this IP?"
         |
         +---> Pivot to Victim
               "What organizations were targeted?"

    Each pivot expands the intelligence picture:

    Infrastructure    Capability      Adversary       Victim
    192.168.1.1  -->  CustomRAT  -->  APT-X      -->  Defense Co.
         |                |               |               |
         v                v               v               v
    192.168.1.2      Mimikatz        APT-X Ops      Energy Co.
    192.168.1.3      Cobalt Strike   APT-X Intel    Finance Co.
```

### Pivot Matrix

| From | To Adversary | To Capability | To Infrastructure | To Victim |
|------|--------------|---------------|-------------------|-----------|
| Adversary | - | Known TTPs | Known C2s | Target profile |
| Capability | Attribution | - | Delivery infra | Vulnerable systems |
| Infrastructure | Registration data | Hosted tools | - | Connection logs |
| Victim | Industry targeting | Exploited vulns | Observed connections | - |

---

## Intelligence Products

### Tactical Intelligence

| Product | Diamond Focus | Use Case |
|---------|---------------|----------|
| IOC Feed | Infrastructure | Detection rules |
| Malware Report | Capability | Reverse engineering |
| Victim Notification | Victim | Incident response |
| TTPs Documentation | Capability | Hunt operations |

### Operational Intelligence

| Product | Diamond Focus | Use Case |
|---------|---------------|----------|
| Activity Thread | All | Campaign tracking |
| Infrastructure Mapping | Infrastructure | Blocking/takedown |
| Adversary Profile | Adversary | Attribution |
| Target Assessment | Victim | Risk assessment |

### Strategic Intelligence

| Product | Diamond Focus | Use Case |
|---------|---------------|----------|
| Threat Landscape | All | Executive briefing |
| Sector Analysis | Victim | Industry alerts |
| Adversary Assessment | Adversary | Policy decisions |
| Trend Analysis | Capability | Resource planning |

---

## Integration with Other Frameworks

### MITRE ATT&CK Mapping

| Diamond Feature | ATT&CK Component |
|-----------------|------------------|
| Adversary | Groups |
| Capability | Techniques, Software |
| Infrastructure | - (Not directly mapped) |
| Victim | - (Not directly mapped) |

### Kill Chain Integration

```
    DIAMOND + KILL CHAIN

    Kill Chain Phase     Diamond Emphasis
    ----------------     ----------------
    Reconnaissance   --> Adversary planning, Victim profiling
    Weaponization    --> Capability development
    Delivery         --> Infrastructure (delivery)
    Exploitation     --> Capability execution
    Installation     --> Capability (persistence)
    C2               --> Infrastructure (C2)
    Actions          --> Adversary intent achieved
```

---

## Practical Application

### Incident Analysis Template

```
DIAMOND MODEL INCIDENT REPORT
=============================

Incident ID: INC-2024-001
Date: 2024-01-15
Analyst: [Name]

ADVERSARY
---------
Identity: Unknown (Suspected APT-X)
Attribution Confidence: Medium
Intent: Espionage
Target Sector: Defense

CAPABILITY
----------
Initial Access: Spearphishing (T1566.001)
Execution: PowerShell (T1059.001)
Persistence: Registry Run Keys (T1547.001)
C2: HTTP Beacon (T1071.001)
Malware: Custom RAT (hash: abc123...)

INFRASTRUCTURE
--------------
Delivery: phishing-domain[.]com
C2 Primary: 192.168.1.100
C2 Backup: compromised-site[.]org
Exfiltration: cloud-storage[.]io

VICTIM
------
Organization: Target Corp
Assets: Email accounts, File servers
Network: 10.0.0.0/8
Impact: 500 user credentials compromised

META-FEATURES
-------------
Timestamp: 2024-01-15 09:00 - 2024-01-16 18:00 UTC
Phase: Actions on Objectives
Result: Partial Success (contained before exfil)
Direction: Adversary -> Infrastructure -> Victim
```

---

## Tools and Resources

| Tool | Purpose |
|------|---------|
| MISP | Threat intelligence platform with Diamond support |
| OpenCTI | Structured threat intelligence |
| Maltego | Entity relationship visualization |
| ThreatConnect | Threat intelligence platform |

---

## References

- Caltagirone, S., Pendergast, A., & Betz, C. (2013). The Diamond Model of Intrusion Analysis
- MITRE ATT&CK Framework
- Lockheed Martin Cyber Kill Chain

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
