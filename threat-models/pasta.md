# PASTA Threat Modeling Framework

Process for Attack Simulation and Threat Analysis (PASTA) is a risk-centric threat modeling methodology that aligns business objectives with technical requirements.

---

## Overview

PASTA is a seven-stage methodology that provides a structured approach to threat modeling by combining business impact analysis with technical risk assessment.

```
    PASTA METHODOLOGY - SEVEN STAGES

    Stage 1: Define Objectives
         |
         v
    Stage 2: Define Technical Scope
         |
         v
    Stage 3: Application Decomposition
         |
         v
    Stage 4: Threat Analysis
         |
         v
    Stage 5: Vulnerability Analysis
         |
         v
    Stage 6: Attack Modeling
         |
         v
    Stage 7: Risk & Impact Analysis
```

---

## Stage 1: Define Business Objectives

### Business Impact Analysis

| Asset Category | Business Value | Confidentiality | Integrity | Availability |
|----------------|----------------|-----------------|-----------|--------------|
| Customer Data | Critical | High | High | Medium |
| Financial Records | Critical | High | High | High |
| Intellectual Property | High | High | High | Medium |
| Authentication Systems | Critical | High | High | High |
| Public Website | Medium | Low | Medium | High |

### Risk Appetite Definition

```
Risk Tolerance Matrix:

                    IMPACT
                    Low    Medium    High    Critical
    LIKELIHOOD
    High            Accept  Mitigate  Mitigate  Avoid
    Medium          Accept  Accept    Mitigate  Mitigate
    Low             Accept  Accept    Accept    Mitigate
    Rare            Accept  Accept    Accept    Accept
```

### Compliance Requirements

| Regulation | Applicable Data | Key Controls |
|------------|-----------------|--------------|
| PCI-DSS | Payment card data | Encryption, access control, logging |
| GDPR | EU personal data | Consent, right to erasure, breach notification |
| HIPAA | Protected health info | Access controls, audit trails, encryption |
| SOC 2 | Service organization | Security, availability, confidentiality |

---

## Stage 2: Define Technical Scope

### System Architecture Overview

```
                        TECHNICAL SCOPE BOUNDARY
    +------------------------------------------------------------------+
    |                                                                  |
    |   +-------------+      +-------------+      +-------------+      |
    |   |   Web Tier  |----->|   App Tier  |----->|   Data Tier |      |
    |   |             |      |             |      |             |      |
    |   | - WAF       |      | - API GW    |      | - Database  |      |
    |   | - CDN       |      | - Services  |      | - Cache     |      |
    |   | - Load Bal  |      | - Auth      |      | - Storage   |      |
    |   +-------------+      +-------------+      +-------------+      |
    |         |                    |                    |              |
    |         v                    v                    v              |
    |   +----------------------------------------------------------+   |
    |   |              SECURITY CONTROLS LAYER                     |   |
    |   | SIEM | IDS/IPS | DLP | Encryption | IAM | Logging       |   |
    |   +----------------------------------------------------------+   |
    |                                                                  |
    +------------------------------------------------------------------+
```

### Asset Inventory

| Asset ID | Asset Name | Type | Owner | Classification |
|----------|------------|------|-------|----------------|
| A001 | Production Database | Data Store | DBA Team | Confidential |
| A002 | API Gateway | Infrastructure | Platform Team | Internal |
| A003 | Authentication Service | Application | Security Team | Critical |
| A004 | Customer Portal | Application | Product Team | Public |
| A005 | Admin Dashboard | Application | IT Team | Restricted |

### Data Flow Identification

| Flow ID | Source | Destination | Data Type | Protocol | Encryption |
|---------|--------|-------------|-----------|----------|------------|
| DF001 | Browser | Web Server | User Input | HTTPS | TLS 1.3 |
| DF002 | Web Server | API Gateway | API Calls | HTTPS | TLS 1.3 |
| DF003 | API Gateway | Database | Queries | TCP | TLS + AES-256 |
| DF004 | Services | Log Aggregator | Logs | TCP | TLS 1.2 |

---

## Stage 3: Application Decomposition

### Component Analysis

```
    APPLICATION DECOMPOSITION

    +------------------+
    |   Entry Points   |
    +------------------+
    | - Web Interface  |
    | - REST API       |
    | - Admin Portal   |
    | - Mobile API     |
    +--------+---------+
             |
             v
    +------------------+
    |   Trust Zones    |
    +------------------+
    | - Public Zone    |
    | - DMZ            |
    | - Internal Zone  |
    | - Restricted     |
    +--------+---------+
             |
             v
    +------------------+
    |   Data Stores    |
    +------------------+
    | - User Database  |
    | - Session Store  |
    | - File Storage   |
    | - Audit Logs     |
    +------------------+
```

### Trust Boundary Matrix

| Boundary | From Zone | To Zone | Controls Required |
|----------|-----------|---------|-------------------|
| TB-001 | Internet | DMZ | WAF, Rate Limiting, Input Validation |
| TB-002 | DMZ | Internal | API Authentication, Authorization |
| TB-003 | Internal | Restricted | MFA, Role-Based Access, Encryption |
| TB-004 | Any | Data Store | Parameterized Queries, Access Logging |

### Authentication Mechanisms

| Mechanism | Use Case | Strength | Vulnerabilities |
|-----------|----------|----------|-----------------|
| OAuth 2.0 + OIDC | User Authentication | High | Token theft, misconfiguration |
| API Keys | Service-to-Service | Medium | Key exposure, no rotation |
| mTLS | Internal Services | High | Certificate management |
| SAML | Enterprise SSO | High | XML signature wrapping |

---

## Stage 4: Threat Analysis

### Threat Actor Profiles

| Actor Type | Motivation | Capability | Targeting | TTPs |
|------------|------------|------------|-----------|------|
| Nation-State | Espionage, Disruption | Advanced | Targeted | APT, Zero-days |
| Cybercriminal | Financial Gain | Moderate-High | Opportunistic | Ransomware, BEC |
| Hacktivist | Ideology | Low-Moderate | Targeted | DDoS, Defacement |
| Insider | Financial, Revenge | Varies | Targeted | Data Theft, Sabotage |
| Script Kiddie | Notoriety | Low | Opportunistic | Known exploits |

### Threat Scenarios

| Scenario ID | Threat Actor | Attack Vector | Target Asset | Business Impact |
|-------------|--------------|---------------|--------------|-----------------|
| TS-001 | Cybercriminal | Phishing | User Credentials | Account Takeover |
| TS-002 | Cybercriminal | SQL Injection | Customer Database | Data Breach |
| TS-003 | Nation-State | Supply Chain | CI/CD Pipeline | Code Compromise |
| TS-004 | Insider | Privilege Abuse | Financial Data | Fraud |
| TS-005 | Hacktivist | DDoS | Public Website | Service Disruption |

### Attack Library Reference

| Attack Type | MITRE ATT&CK | CAPEC | CWE |
|-------------|--------------|-------|-----|
| Credential Stuffing | T1110.004 | CAPEC-600 | CWE-307 |
| SQL Injection | T1190 | CAPEC-66 | CWE-89 |
| Cross-Site Scripting | T1189 | CAPEC-86 | CWE-79 |
| Server-Side Request Forgery | T1090 | CAPEC-664 | CWE-918 |
| Insecure Deserialization | T1059 | CAPEC-586 | CWE-502 |

---

## Stage 5: Vulnerability Analysis

### Vulnerability Assessment Results

| Vuln ID | Component | Vulnerability | CVSS | Exploitability |
|---------|-----------|---------------|------|----------------|
| V-001 | Web Server | Outdated TLS Config | 5.3 | Medium |
| V-002 | API Gateway | Missing Rate Limiting | 6.5 | High |
| V-003 | Database | Default Credentials | 9.8 | Critical |
| V-004 | Auth Service | Session Fixation | 7.1 | Medium |
| V-005 | File Upload | Unrestricted Types | 8.8 | High |

### Vulnerability-to-Threat Mapping

```
    VULNERABILITY CORRELATION MATRIX

                          VULNERABILITIES
                    V-001  V-002  V-003  V-004  V-005
    THREATS
    TS-001            -      -      X      X      -
    TS-002            -      -      X      -      -
    TS-003            -      -      -      -      X
    TS-004            -      -      X      X      -
    TS-005            -      X      -      -      -

    X = Direct correlation exists
```

### Security Control Gap Analysis

| Control Domain | Required | Implemented | Gap |
|----------------|----------|-------------|-----|
| Input Validation | All entry points | 70% coverage | 30% |
| Access Control | Role-based | Partial RBAC | Need ABAC |
| Encryption | At-rest and in-transit | In-transit only | At-rest encryption |
| Logging | All security events | Authentication only | Expand coverage |
| Monitoring | Real-time alerting | Basic monitoring | SIEM integration |

---

## Stage 6: Attack Modeling

### Attack Trees

```
    ATTACK TREE: DATA EXFILTRATION

    [Goal: Exfiltrate Customer Data]
              |
    +---------+---------+
    |                   |
    [Direct Access]     [Indirect Access]
    |                   |
    +----+----+         +----+----+
    |         |         |         |
    [SQL      [API      [Supply   [Social
    Injection] Abuse]   Chain]    Engineering]
    |         |         |         |
    V-002     V-001     V-003     TS-001
    V-003     V-004
```

### Attack Simulation Scenarios

| Simulation ID | Attack Path | Entry Point | Pivot Points | Target |
|---------------|-------------|-------------|--------------|--------|
| SIM-001 | Phishing > Credential Theft > Lateral Movement | Email | Workstation > AD | Database |
| SIM-002 | SQLi > Data Access | Web Form | Database | Customer Records |
| SIM-003 | Supply Chain > Code Injection | Dependency | CI/CD > Production | All Systems |
| SIM-004 | Insider > Privilege Escalation | VPN | Internal Network | Financial Data |

### Kill Chain Mapping

| Phase | Technique | Detection Opportunity | Prevention Control |
|-------|-----------|----------------------|-------------------|
| Reconnaissance | Port Scanning | Network IDS | Firewall Rules |
| Weaponization | Payload Creation | N/A (External) | N/A |
| Delivery | Phishing Email | Email Gateway | Security Awareness |
| Exploitation | Vulnerability Exploit | EDR, WAF | Patching, WAF Rules |
| Installation | Malware Deployment | EDR, AV | Application Whitelisting |
| Command & Control | Beaconing | Network Monitoring | Egress Filtering |
| Actions on Objectives | Data Exfiltration | DLP, SIEM | Data Classification |

---

## Stage 7: Risk and Impact Analysis

### Risk Quantification

| Risk ID | Threat Scenario | Likelihood | Impact | Inherent Risk | Residual Risk |
|---------|-----------------|------------|--------|---------------|---------------|
| R-001 | Customer Data Breach | Medium | Critical | High | Medium |
| R-002 | Service Disruption | High | High | High | Low |
| R-003 | Ransomware Attack | Medium | Critical | High | Medium |
| R-004 | Insider Data Theft | Low | High | Medium | Low |
| R-005 | Supply Chain Compromise | Low | Critical | Medium | Medium |

### Risk Calculation Formula

```
Risk Score = (Likelihood x Impact) - (Control Effectiveness x Coverage)

Where:
- Likelihood: 1 (Rare) to 5 (Almost Certain)
- Impact: 1 (Negligible) to 5 (Catastrophic)
- Control Effectiveness: 0% to 100%
- Coverage: 0% to 100%

Example:
R-001 = (3 x 5) - (0.7 x 0.8) = 15 - 0.56 = 14.44 (High)
```

### Risk Treatment Plan

| Risk ID | Treatment | Control Enhancement | Owner | Timeline | Cost Estimate |
|---------|-----------|---------------------|-------|----------|---------------|
| R-001 | Mitigate | Implement encryption at rest | Security | Q1 | $50,000 |
| R-002 | Mitigate | Deploy DDoS protection | Infrastructure | Q1 | $30,000 |
| R-003 | Mitigate | EDR + backup enhancement | Security | Q2 | $80,000 |
| R-004 | Mitigate | DLP + access reviews | Security | Q2 | $40,000 |
| R-005 | Accept | Enhanced vendor assessment | Procurement | Ongoing | $10,000 |

### Countermeasure Prioritization

| Priority | Control | Risk Reduction | Cost | ROI |
|----------|---------|----------------|------|-----|
| 1 | Multi-Factor Authentication | High | Low | High |
| 2 | Web Application Firewall | High | Medium | High |
| 3 | Database Encryption | High | Medium | Medium |
| 4 | SIEM Implementation | Medium | High | Medium |
| 5 | Security Awareness Training | Medium | Low | High |

---

## PASTA Deliverables

### Executive Summary Template

```
THREAT MODEL EXECUTIVE SUMMARY
==============================

Application: [Name]
Assessment Date: [Date]
Risk Level: [Critical/High/Medium/Low]

KEY FINDINGS:
- [Number] critical vulnerabilities identified
- [Number] high-risk threat scenarios modeled
- [Number] security control gaps documented

TOP RISKS:
1. [Risk Description] - [Risk Level]
2. [Risk Description] - [Risk Level]
3. [Risk Description] - [Risk Level]

RECOMMENDED ACTIONS:
1. [Action] - [Timeline] - [Cost]
2. [Action] - [Timeline] - [Cost]
3. [Action] - [Timeline] - [Cost]

BUSINESS IMPACT:
- Potential financial loss: $[Amount]
- Regulatory exposure: [Description]
- Reputational impact: [Description]
```

### Risk Register Template

| ID | Date | Risk | Category | Likelihood | Impact | Score | Owner | Status | Treatment |
|----|------|------|----------|------------|--------|-------|-------|--------|-----------|
| | | | | | | | | | |

---

## References

- OWASP Threat Modeling
- NIST SP 800-30 Risk Assessment
- ISO 27005 Information Security Risk Management
- FAIR (Factor Analysis of Information Risk)

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
