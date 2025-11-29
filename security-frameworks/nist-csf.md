# NIST Cybersecurity Framework

The NIST Cybersecurity Framework (CSF) provides a policy framework of computer security guidance for how private sector organizations can assess and improve their ability to prevent, detect, and respond to cyber attacks.

---

## Framework Overview

```
    NIST CSF CORE FUNCTIONS

    +----------+----------+----------+----------+----------+
    | IDENTIFY | PROTECT  |  DETECT  | RESPOND  | RECOVER  |
    +----------+----------+----------+----------+----------+
    |          |          |          |          |          |
    | Asset    | Access   | Anomaly  | Response | Recovery |
    | Mgmt     | Control  | Events   | Planning | Planning |
    |          |          |          |          |          |
    | Business | Security | Security | Communic | Improve  |
    | Environ  | Training | Monitor  | ations   | ments    |
    |          |          |          |          |          |
    | Govern   | Data     | Detect   | Analysis | Communic |
    | ance     | Security | Process  |          | ations   |
    |          |          |          |          |          |
    | Risk     | Info     |          | Mitigat  |          |
    | Assess   | Protect  |          | ion      |          |
    |          |          |          |          |          |
    | Risk     | Mainten  |          | Improve  |          |
    | Mgmt     | ance     |          | ments    |          |
    |          |          |          |          |          |
    | Supply   | Protect  |          |          |          |
    | Chain    | Tech     |          |          |          |
    +----------+----------+----------+----------+----------+
```

---

## Core Functions

### IDENTIFY (ID)

Develop organizational understanding to manage cybersecurity risk to systems, people, assets, data, and capabilities.

| Category | ID | Description |
|----------|-----|-------------|
| Asset Management | ID.AM | Physical and software assets inventoried |
| Business Environment | ID.BE | Organization mission and objectives understood |
| Governance | ID.GV | Policies and procedures established |
| Risk Assessment | ID.RA | Threats and vulnerabilities identified |
| Risk Management Strategy | ID.RM | Risk tolerance established |
| Supply Chain Risk Management | ID.SC | Third-party risks managed |

#### ID.AM - Asset Management

| Subcategory | Control Description | Implementation |
|-------------|---------------------|----------------|
| ID.AM-1 | Physical devices inventoried | CMDB, asset discovery tools |
| ID.AM-2 | Software platforms inventoried | Software inventory system |
| ID.AM-3 | Data flows mapped | Data flow diagrams |
| ID.AM-4 | External systems catalogued | Third-party inventory |
| ID.AM-5 | Resources prioritized | Asset classification |
| ID.AM-6 | Cybersecurity roles defined | RACI matrix |

#### ID.RA - Risk Assessment

| Subcategory | Control Description | Implementation |
|-------------|---------------------|----------------|
| ID.RA-1 | Asset vulnerabilities identified | Vulnerability scanning |
| ID.RA-2 | Threat intelligence received | Threat feeds, ISACs |
| ID.RA-3 | Threats identified | Threat modeling |
| ID.RA-4 | Business impacts identified | BIA |
| ID.RA-5 | Risk determined | Risk assessment |
| ID.RA-6 | Risk responses identified | Risk treatment plan |

---

### PROTECT (PR)

Develop and implement appropriate safeguards to ensure delivery of critical services.

| Category | ID | Description |
|----------|-----|-------------|
| Identity Management | PR.AC | Access control implemented |
| Awareness and Training | PR.AT | Personnel trained |
| Data Security | PR.DS | Data protected |
| Information Protection | PR.IP | Security policies maintained |
| Maintenance | PR.MA | System maintenance performed |
| Protective Technology | PR.PT | Technical controls deployed |

#### PR.AC - Access Control

| Subcategory | Control Description | Implementation |
|-------------|---------------------|----------------|
| PR.AC-1 | Identities managed | IAM system |
| PR.AC-2 | Physical access controlled | Badge systems, cameras |
| PR.AC-3 | Remote access managed | VPN, zero trust |
| PR.AC-4 | Access permissions managed | RBAC/ABAC |
| PR.AC-5 | Network integrity protected | Segmentation |
| PR.AC-6 | Identities proofed | Identity verification |
| PR.AC-7 | Authentication enforced | MFA, SSO |

#### PR.DS - Data Security

| Subcategory | Control Description | Implementation |
|-------------|---------------------|----------------|
| PR.DS-1 | Data-at-rest protected | Encryption (AES-256) |
| PR.DS-2 | Data-in-transit protected | TLS 1.3 |
| PR.DS-3 | Assets managed through lifecycle | Data retention |
| PR.DS-4 | Availability maintained | Redundancy, backups |
| PR.DS-5 | Data leakage prevented | DLP |
| PR.DS-6 | Integrity verified | Hash verification |
| PR.DS-7 | Development environment separated | Env isolation |
| PR.DS-8 | Hardware integrity verified | TPM, secure boot |

---

### DETECT (DE)

Develop and implement appropriate activities to identify the occurrence of a cybersecurity event.

| Category | ID | Description |
|----------|-----|-------------|
| Anomalies and Events | DE.AE | Anomalous activity detected |
| Security Continuous Monitoring | DE.CM | Systems monitored |
| Detection Processes | DE.DP | Detection processes maintained |

#### DE.CM - Security Continuous Monitoring

| Subcategory | Control Description | Implementation |
|-------------|---------------------|----------------|
| DE.CM-1 | Network monitored | IDS/IPS, NDR |
| DE.CM-2 | Physical environment monitored | Environmental sensors |
| DE.CM-3 | Personnel activity monitored | UEBA |
| DE.CM-4 | Malicious code detected | EDR, antimalware |
| DE.CM-5 | Unauthorized mobile code detected | Application control |
| DE.CM-6 | External service provider monitored | Vendor assessments |
| DE.CM-7 | Unauthorized personnel monitored | Access reviews |
| DE.CM-8 | Vulnerability scans performed | Vulnerability management |

---

### RESPOND (RS)

Develop and implement appropriate activities to take action regarding a detected cybersecurity incident.

| Category | ID | Description |
|----------|-----|-------------|
| Response Planning | RS.RP | Response processes executed |
| Communications | RS.CO | Stakeholders coordinated |
| Analysis | RS.AN | Incidents analyzed |
| Mitigation | RS.MI | Incidents mitigated |
| Improvements | RS.IM | Response improved |

#### RS.AN - Analysis

| Subcategory | Control Description | Implementation |
|-------------|---------------------|----------------|
| RS.AN-1 | Notifications investigated | SIEM alerts |
| RS.AN-2 | Incident impact understood | Impact assessment |
| RS.AN-3 | Forensics performed | Forensic analysis |
| RS.AN-4 | Incidents categorized | Incident taxonomy |
| RS.AN-5 | Processes for receiving information | Threat intel integration |

---

### RECOVER (RC)

Develop and implement appropriate activities to maintain plans for resilience and to restore capabilities impaired due to a cybersecurity incident.

| Category | ID | Description |
|----------|-----|-------------|
| Recovery Planning | RC.RP | Recovery processes executed |
| Improvements | RC.IM | Recovery improved |
| Communications | RC.CO | Restoration coordinated |

#### RC.RP - Recovery Planning

| Subcategory | Control Description | Implementation |
|-------------|---------------------|----------------|
| RC.RP-1 | Recovery plan executed | DRP execution |

---

## Implementation Tiers

| Tier | Name | Risk Management | Integration |
|------|------|-----------------|-------------|
| 1 | Partial | Ad hoc, reactive | Limited awareness |
| 2 | Risk Informed | Risk aware, not org-wide | Some integration |
| 3 | Repeatable | Formal policy, org-wide | Regular updates |
| 4 | Adaptive | Continuous improvement | Full integration |

### Tier Progression

```
    IMPLEMENTATION TIER MATURITY

    Tier 1          Tier 2          Tier 3          Tier 4
    Partial         Risk Informed   Repeatable      Adaptive
       |               |               |               |
       v               v               v               v
    +-------+       +-------+       +-------+       +-------+
    |Ad hoc |  -->  |Aware  |  -->  |Formal |  -->  |Contin |
    |React  |       |Some   |       |Policy |       |Improve|
    |Limited|       |Integr |       |OrgWide|       |Full   |
    +-------+       +-------+       +-------+       +-------+

    Key Indicators:
    - Policy formalization
    - Resource allocation
    - External participation
    - Risk-informed decisions
```

---

## Framework Profile

### Current State Profile Template

| Function | Category | Current State | Target State | Gap |
|----------|----------|---------------|--------------|-----|
| Identify | ID.AM | Tier 2 | Tier 3 | Asset discovery |
| Identify | ID.RA | Tier 2 | Tier 4 | Continuous assessment |
| Protect | PR.AC | Tier 3 | Tier 4 | Zero trust |
| Protect | PR.DS | Tier 2 | Tier 3 | Encryption |
| Detect | DE.CM | Tier 2 | Tier 3 | SIEM coverage |
| Respond | RS.AN | Tier 2 | Tier 3 | Forensics capability |
| Recover | RC.RP | Tier 1 | Tier 3 | DR automation |

---

## Control Mapping

### NIST CSF to Other Frameworks

| NIST CSF | ISO 27001 | CIS Controls | NIST 800-53 |
|----------|-----------|--------------|-------------|
| ID.AM-1 | A.8.1.1 | CIS 1 | CM-8 |
| ID.RA-1 | A.12.6.1 | CIS 7 | RA-5 |
| PR.AC-1 | A.9.2.1 | CIS 5 | AC-2 |
| PR.DS-1 | A.10.1.1 | CIS 3 | SC-28 |
| DE.CM-1 | A.12.4.1 | CIS 8 | SI-4 |
| RS.RP-1 | A.16.1.5 | CIS 17 | IR-8 |
| RC.RP-1 | A.17.1.2 | CIS 11 | CP-10 |

---

## Implementation Guide

### Phase 1: Scope and Prioritize

1. Identify business objectives
2. Determine critical assets
3. Define organizational risk tolerance
4. Prioritize CSF functions

### Phase 2: Orient

1. Identify related systems
2. Determine applicable regulations
3. Establish risk management approach
4. Identify existing security measures

### Phase 3: Current Profile

1. Assess current state per category
2. Document existing controls
3. Identify gaps
4. Determine tier level

### Phase 4: Risk Assessment

1. Identify threats
2. Assess likelihood and impact
3. Determine risk levels
4. Prioritize risks

### Phase 5: Target Profile

1. Define desired outcomes
2. Set target tier levels
3. Align with risk tolerance
4. Document target state

### Phase 6: Gap Analysis

1. Compare current vs target
2. Identify resource requirements
3. Prioritize gaps
4. Develop remediation plan

### Phase 7: Implementation

1. Execute remediation plan
2. Deploy controls
3. Train personnel
4. Monitor progress

---

## Metrics and Measurement

### Key Performance Indicators

| Category | KPI | Target | Measurement |
|----------|-----|--------|-------------|
| Identify | Asset coverage | 100% | % of assets inventoried |
| Protect | MFA adoption | 100% | % of accounts with MFA |
| Detect | MTTD | < 1 hour | Average detection time |
| Respond | MTTR | < 4 hours | Average response time |
| Recover | RTO achieved | 100% | % within target RTO |

---

## References

- NIST Cybersecurity Framework Version 1.1
- NIST SP 800-53 Rev. 5
- NIST SP 800-37 Risk Management Framework

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
