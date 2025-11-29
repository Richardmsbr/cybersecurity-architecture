# Threat Intelligence Operations

Threat Intelligence provides actionable information about threats, adversaries, and their tactics, techniques, and procedures (TTPs) to inform security decisions and enhance defensive capabilities.

---

## Intelligence Types

### Strategic Intelligence

| Aspect | Description | Consumers |
|--------|-------------|-----------|
| Focus | Long-term trends, threat landscape | Executive leadership |
| Timeframe | Months to years | CISO, Board |
| Format | Reports, briefings | Risk management |
| Use Case | Budget, strategy, risk decisions | Business planning |

### Operational Intelligence

| Aspect | Description | Consumers |
|--------|-------------|-----------|
| Focus | Threat actor campaigns, TTPs | Security managers |
| Timeframe | Days to weeks | Hunt teams |
| Format | Campaign reports, TTP analysis | IR teams |
| Use Case | Hunt operations, detection tuning | Defense planning |

### Tactical Intelligence

| Aspect | Description | Consumers |
|--------|-------------|-----------|
| Focus | Specific indicators, signatures | SOC analysts |
| Timeframe | Hours to days | Security engineers |
| Format | IOCs, detection rules | Automated systems |
| Use Case | Detection, blocking, investigation | Operations |

---

## Intelligence Lifecycle

```
    THREAT INTELLIGENCE LIFECYCLE

    1. PLANNING & DIRECTION
    +----------------------------------+
    | Define requirements              |
    | Prioritize intelligence needs    |
    | Identify stakeholders            |
    +----------------------------------+
              |
              v
    2. COLLECTION
    +----------------------------------+
    | Open source (OSINT)              |
    | Commercial feeds                 |
    | Internal telemetry               |
    | Information sharing              |
    +----------------------------------+
              |
              v
    3. PROCESSING
    +----------------------------------+
    | Data normalization               |
    | Deduplication                    |
    | Translation                      |
    +----------------------------------+
              |
              v
    4. ANALYSIS
    +----------------------------------+
    | Correlation                      |
    | Attribution                      |
    | TTP extraction                   |
    | Confidence assessment            |
    +----------------------------------+
              |
              v
    5. DISSEMINATION
    +----------------------------------+
    | Reports and briefings            |
    | Automated feeds                  |
    | Detection rules                  |
    +----------------------------------+
              |
              v
    6. FEEDBACK
    +----------------------------------+
    | Effectiveness measurement        |
    | Requirement refinement           |
    | Process improvement              |
    +----------------------------------+
```

---

## Collection Sources

### Source Categories

| Category | Sources | Reliability |
|----------|---------|-------------|
| Open Source | News, blogs, social media, paste sites | Variable |
| Commercial | Vendor feeds, threat reports | High |
| Government | CISA, FBI, NCSC advisories | High |
| Industry | ISACs, sharing communities | High |
| Internal | SIEM, EDR, incident data | High |
| Technical | Honeypots, malware analysis | High |

### Collection Methods

```
    INTELLIGENCE COLLECTION

    Passive Collection:
    +----------------------------------+
    | News and blog monitoring         |
    | Social media tracking            |
    | Dark web monitoring              |
    | Paste site monitoring            |
    +----------------------------------+

    Active Collection:
    +----------------------------------+
    | Honeypots and sensors            |
    | Malware sandbox analysis         |
    | Indicator enrichment             |
    | Threat actor tracking            |
    +----------------------------------+

    Sharing/Exchange:
    +----------------------------------+
    | ISAC membership                  |
    | Vendor partnerships              |
    | Government programs              |
    | Peer relationships               |
    +----------------------------------+
```

---

## Indicator Types

### IOC Categories

| Type | Description | Example | TTL |
|------|-------------|---------|-----|
| IP Address | Malicious infrastructure | 192.168.1.1 | Days-Weeks |
| Domain | C2, phishing domains | evil.com | Days-Weeks |
| URL | Malicious URLs | http://evil.com/mal | Hours-Days |
| File Hash | Malware, tools | SHA256:abc123... | Weeks-Months |
| Email | Phishing indicators | sender@evil.com | Days-Weeks |
| Certificate | Malicious certificates | Serial, thumbprint | Weeks-Months |
| User Agent | Bot/tool signatures | CustomBot/1.0 | Weeks |
| YARA | Pattern signatures | rule malware {...} | Months |

### IOC Quality Assessment

| Factor | Assessment |
|--------|------------|
| Confidence | How certain is this IOC malicious? |
| Relevance | Does this apply to our environment? |
| Timeliness | Is this IOC still valid? |
| Context | Do we understand the threat? |
| Actionability | Can we use this IOC? |

---

## TTP Analysis

### MITRE ATT&CK Mapping

| Component | Description | Use Case |
|-----------|-------------|----------|
| Tactics | Adversary goals | Understand objectives |
| Techniques | How tactics achieved | Detection rules |
| Sub-techniques | Specific methods | Granular detection |
| Procedures | Exact implementation | Hunt operations |

### TTP Intelligence Products

```
    TTP ANALYSIS OUTPUT

    Threat Actor Profile:
    +----------------------------------+
    | Name: APT-X                      |
    | Attribution: Nation-State        |
    | Motivation: Espionage            |
    | Target Sectors: Defense, Tech    |
    | Active Since: 2018               |
    +----------------------------------+

    Common TTPs:
    +----------------------------------+
    | Initial Access: Spearphishing    |
    | Execution: PowerShell            |
    | Persistence: Scheduled Tasks     |
    | C2: HTTP over 443                |
    | Exfiltration: Cloud services     |
    +----------------------------------+

    Detection Opportunities:
    +----------------------------------+
    | YARA rules for malware           |
    | Network signatures               |
    | Behavioral detections            |
    | Hunt queries                     |
    +----------------------------------+
```

---

## Threat Intelligence Platform

### Platform Architecture

```
    TIP ARCHITECTURE

    COLLECTION                     PLATFORM                    OUTPUT
    +-----------+                 +----------+                +-----------+
    | Feeds     |---------------->|          |--------------->| SIEM      |
    +-----------+                 |   TIP    |                +-----------+
                                  |          |
    +-----------+                 | +------+ |                +-----------+
    | Internal  |---------------->| |Store | |--------------->| EDR       |
    +-----------+                 | +------+ |                +-----------+
                                  |          |
    +-----------+                 | +------+ |                +-----------+
    | Partners  |---------------->| |Enrich| |--------------->| Firewall  |
    +-----------+                 | +------+ |                +-----------+
                                  |          |
    +-----------+                 | +------+ |                +-----------+
    | Manual    |---------------->| |Analyze||--------------->| Reports   |
    +-----------+                 | +------+ |                +-----------+
                                  +----------+
```

### Key Functions

| Function | Description |
|----------|-------------|
| Aggregation | Collect from multiple sources |
| Normalization | Standardize formats (STIX) |
| Deduplication | Remove duplicate indicators |
| Enrichment | Add context and metadata |
| Scoring | Assess confidence and relevance |
| Distribution | Push to security tools |
| Workflow | Track analysis and actions |

---

## Intelligence Sharing

### Sharing Frameworks

| Framework | Description | Format |
|-----------|-------------|--------|
| STIX | Structured threat information | JSON/XML |
| TAXII | Transport mechanism | API |
| OpenIOC | IOC format | XML |
| MISP | Sharing platform | Multiple |

### Sharing Communities

| Community | Focus | Membership |
|-----------|-------|------------|
| ISACs | Industry-specific | Sector organizations |
| CERTs | National/regional | Government-backed |
| Vendor communities | Product-specific | Customers |
| Private sharing | Trusted peers | Invitation |

### Traffic Light Protocol

| Color | Sharing | Description |
|-------|---------|-------------|
| TLP:RED | Named recipients only | Highly sensitive |
| TLP:AMBER | Organization only | Limited distribution |
| TLP:AMBER+STRICT | Organization only, no further | Restricted |
| TLP:GREEN | Community | Limited public |
| TLP:CLEAR | Public | No restrictions |

---

## Operationalization

### Detection Rule Creation

| Source | Detection Type | Destination |
|--------|---------------|-------------|
| IP IOCs | Network rules | Firewall, IDS |
| Domain IOCs | DNS rules | DNS security |
| Hash IOCs | File rules | EDR, AV |
| URL IOCs | Web rules | Proxy, WAF |
| TTP IOCs | Behavioral rules | SIEM, EDR |

### Integration Points

```
    TI OPERATIONALIZATION

    Intelligence --> SIEM
    - Correlation rules
    - Alert enrichment
    - Dashboards

    Intelligence --> EDR
    - IOC watchlists
    - Custom detections
    - Threat hunting

    Intelligence --> Firewall
    - Block lists
    - Reputation feeds
    - Geographic rules

    Intelligence --> Email
    - Sender reputation
    - URL filtering
    - Attachment analysis

    Intelligence --> SOC
    - Playbook enrichment
    - Context for analysts
    - Investigation support
```

---

## Metrics and Measurement

### Intelligence Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| Collection coverage | Sources monitored | Comprehensive |
| Processing latency | Time to process | < 1 hour |
| Detection rate | IOCs detecting threats | Track trend |
| False positive rate | Bad IOCs | < 5% |
| Time to operationalize | IOC to detection | < 4 hours |

### Program Metrics

| Metric | Description |
|--------|-------------|
| Threats prevented | Blocked based on TI |
| Detection improvement | New detections from TI |
| Hunt success | Findings from TI-driven hunts |
| Stakeholder satisfaction | Consumer feedback |

---

## References

- NIST SP 800-150 Cyber Threat Intelligence Sharing
- MITRE ATT&CK Framework
- FIRST Traffic Light Protocol
- OASIS STIX/TAXII Standards

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
