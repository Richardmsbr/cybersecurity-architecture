# Cybersecurity Architecture & Defense Strategies

A comprehensive collection of production-grade security architectures, threat models, incident response playbooks, and defensive strategies. Built from real-world experience securing enterprise systems and responding to advanced persistent threats.

---

## Overview

This repository provides battle-tested security patterns, threat modeling frameworks, and infrastructure-as-code for building secure systems. Each component includes attack vectors, detection strategies, mitigation controls, and compliance mappings.

**Target Audience**: Security Engineers, SOC Analysts, Penetration Testers, Security Architects, CISOs, and DevSecOps Engineers building or defending production systems.

---

## Table of Contents

1. [Threat Modeling](#threat-modeling)
2. [Security Frameworks](#security-frameworks)
3. [Incident Response](#incident-response)
4. [Offensive Security](#offensive-security)
5. [Defensive Security](#defensive-security)
6. [Cloud Security](#cloud-security)
7. [Infrastructure as Code](#infrastructure-as-code)
8. [Compliance](#compliance)

---

## Threat Modeling

Systematic approaches to identifying, quantifying, and addressing security threats.

| Model | Use Case | Documentation |
|-------|----------|---------------|
| [STRIDE](threat-models/stride.md) | Application threat modeling | [Docs](threat-models/stride.md) |
| [PASTA](threat-models/pasta.md) | Risk-centric threat modeling | [Docs](threat-models/pasta.md) |
| [Attack Trees](threat-models/attack-trees.md) | Hierarchical attack analysis | [Docs](threat-models/attack-trees.md) |
| [MITRE ATT&CK Mapping](threat-models/mitre-attack.md) | Adversary tactics & techniques | [Docs](threat-models/mitre-attack.md) |
| [Kill Chain Analysis](threat-models/kill-chain.md) | Attack phase identification | [Docs](threat-models/kill-chain.md) |
| [Diamond Model](threat-models/diamond-model.md) | Intrusion analysis framework | [Docs](threat-models/diamond-model.md) |

### MITRE ATT&CK Coverage Matrix

```
                              TACTICS
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │ Initial   │ Execution │ Persistence │ Privilege  │ Defense   │ Credential  │
    │ Access    │           │             │ Escalation │ Evasion   │ Access      │
    ├───────────┼───────────┼─────────────┼────────────┼───────────┼─────────────┤
    │ T1566     │ T1059     │ T1547       │ T1548      │ T1562     │ T1003       │
    │ Phishing  │ Command   │ Boot/Logon  │ Abuse      │ Impair    │ OS Cred     │
    │           │ Script    │ Autostart   │ Elevation  │ Defenses  │ Dumping     │
    ├───────────┼───────────┼─────────────┼────────────┼───────────┼─────────────┤
    │ T1190     │ T1204     │ T1053       │ T1134      │ T1070     │ T1110       │
    │ Exploit   │ User      │ Scheduled   │ Access     │ Indicator │ Brute       │
    │ Public    │ Execution │ Task        │ Token      │ Removal   │ Force       │
    ├───────────┼───────────┼─────────────┼────────────┼───────────┼─────────────┤
    │ T1133     │ T1047     │ T1136       │ T1068      │ T1027     │ T1555       │
    │ External  │ WMI       │ Create      │ Exploit    │ Obfusc    │ Creds from  │
    │ Services  │           │ Account     │ Vuln       │ Files     │ Password    │
    └───────────┴───────────┴─────────────┴────────────┴───────────┴─────────────┘

    │ Discovery │ Lateral   │ Collection  │ Command    │ Exfil     │ Impact      │
    │           │ Movement  │             │ & Control  │           │             │
    ├───────────┼───────────┼─────────────┼────────────┼───────────┼─────────────┤
    │ T1087     │ T1021     │ T1005       │ T1071      │ T1041     │ T1486       │
    │ Account   │ Remote    │ Data from   │ App Layer  │ Exfil C2  │ Data        │
    │ Discovery │ Services  │ Local Sys   │ Protocol   │ Channel   │ Encrypted   │
    ├───────────┼───────────┼─────────────┼────────────┼───────────┼─────────────┤
    │ T1046     │ T1080     │ T1114       │ T1105      │ T1048     │ T1490       │
    │ Network   │ Taint     │ Email       │ Ingress    │ Exfil Alt │ Inhibit     │
    │ Scan      │ Content   │ Collection  │ Tool Xfer  │ Protocol  │ Recovery    │
    └───────────┴───────────┴─────────────┴────────────┴───────────┴─────────────┘
```

---

## Security Frameworks

### Framework Comparison Matrix

| Framework | Focus | Compliance | Documentation |
|-----------|-------|------------|---------------|
| [NIST CSF](security-frameworks/nist-csf.md) | Risk Management | Federal | [Docs](security-frameworks/nist-csf.md) |
| [CIS Controls](security-frameworks/cis-controls.md) | Technical Controls | Industry | [Docs](security-frameworks/cis-controls.md) |
| [OWASP Top 10](security-frameworks/owasp-top10.md) | Web Application | Development | [Docs](security-frameworks/owasp-top10.md) |
| [OWASP ASVS](security-frameworks/owasp-asvs.md) | App Verification | Development | [Docs](security-frameworks/owasp-asvs.md) |
| [ISO 27001](security-frameworks/iso27001.md) | ISMS | International | [Docs](security-frameworks/iso27001.md) |
| [Zero Trust](security-frameworks/zero-trust.md) | Network Architecture | Modern | [Docs](security-frameworks/zero-trust.md) |

### NIST Cybersecurity Framework

```
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                     NIST CYBERSECURITY FRAMEWORK                            │
    │                                                                             │
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
    │  │  IDENTIFY   │  │   PROTECT   │  │   DETECT    │  │   RESPOND   │  │   RECOVER   │
    │  │             │  │             │  │             │  │             │  │             │
    │  │ Asset Mgmt  │  │ Access Ctrl │  │ Anomalies   │  │ Response    │  │ Recovery    │
    │  │ Business    │  │ Awareness   │  │ Continuous  │  │ Planning    │  │ Planning    │
    │  │ Environment │  │ Data Sec    │  │ Monitoring  │  │ Comms       │  │ Improve-    │
    │  │ Governance  │  │ Info Prot   │  │ Detection   │  │ Analysis    │  │ ments       │
    │  │ Risk Assess │  │ Maintenance │  │ Processes   │  │ Mitigation  │  │ Comms       │
    │  │ Risk Mgmt   │  │ Protective  │  │             │  │ Improve-    │  │             │
    │  │ Supply      │  │ Tech        │  │             │  │ ments       │  │             │
    │  │ Chain       │  │             │  │             │  │             │  │             │
    │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘
    │        │                │                │                │                │
    │        v                v                v                v                v
    │  ┌─────────────────────────────────────────────────────────────────────────┐
    │  │                         IMPLEMENTATION TIERS                            │
    │  │   Tier 1: Partial  │  Tier 2: Risk Informed  │  Tier 3: Repeatable  │  │
    │  │                    │  Tier 4: Adaptive                                  │
    │  └─────────────────────────────────────────────────────────────────────────┘
    │                                                                             │
    └─────────────────────────────────────────────────────────────────────────────┘
```

---

## Incident Response

### IR Playbooks

| Incident Type | Severity | Playbook | MTTR Target |
|---------------|----------|----------|-------------|
| [Ransomware](incident-response/ransomware.md) | Critical | [Playbook](incident-response/ransomware.md) | < 4 hours |
| [Data Breach](incident-response/data-breach.md) | Critical | [Playbook](incident-response/data-breach.md) | < 2 hours |
| [Phishing](incident-response/phishing.md) | High | [Playbook](incident-response/phishing.md) | < 1 hour |
| [Malware](incident-response/malware.md) | High | [Playbook](incident-response/malware.md) | < 2 hours |
| [DDoS](incident-response/ddos.md) | High | [Playbook](incident-response/ddos.md) | < 30 min |
| [Insider Threat](incident-response/insider-threat.md) | Critical | [Playbook](incident-response/insider-threat.md) | < 1 hour |
| [Account Compromise](incident-response/account-compromise.md) | High | [Playbook](incident-response/account-compromise.md) | < 30 min |
| [Supply Chain](incident-response/supply-chain.md) | Critical | [Playbook](incident-response/supply-chain.md) | < 4 hours |

### Incident Response Lifecycle

```
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                    INCIDENT RESPONSE LIFECYCLE                              │
    │                                                                             │
    │     ┌──────────────┐                                                        │
    │     │ PREPARATION  │◄─────────────────────────────────────────────┐         │
    │     │              │                                              │         │
    │     │ • IR Plan    │                                              │         │
    │     │ • Team       │                                              │         │
    │     │ • Tools      │                                              │         │
    │     │ • Training   │                                              │         │
    │     └──────┬───────┘                                              │         │
    │            │                                                      │         │
    │            v                                                      │         │
    │     ┌──────────────┐      ┌──────────────┐      ┌──────────────┐ │         │
    │     │IDENTIFICATION│─────>│ CONTAINMENT  │─────>│ ERADICATION  │ │         │
    │     │              │      │              │      │              │ │         │
    │     │ • Detection  │      │ • Short-term │      │ • Remove     │ │         │
    │     │ • Analysis   │      │ • Long-term  │      │   malware    │ │         │
    │     │ • Scoping    │      │ • Evidence   │      │ • Patch      │ │         │
    │     │ • Notifica-  │      │   preserva-  │      │ • Harden     │ │         │
    │     │   tion       │      │   tion       │      │              │ │         │
    │     └──────────────┘      └──────────────┘      └──────┬───────┘ │         │
    │                                                        │         │         │
    │                                                        v         │         │
    │                          ┌──────────────┐      ┌──────────────┐  │         │
    │                          │   LESSONS    │◄─────│   RECOVERY   │  │         │
    │                          │   LEARNED    │      │              │──┘         │
    │                          │              │      │ • Restore    │            │
    │                          │ • Root cause │      │ • Validate   │            │
    │                          │ • Improve    │      │ • Monitor    │            │
    │                          │ • Document   │      │ • Return to  │            │
    │                          │              │      │   normal     │            │
    │                          └──────────────┘      └──────────────┘            │
    │                                                                             │
    └─────────────────────────────────────────────────────────────────────────────┘
```

---

## Offensive Security

### Penetration Testing Methodology

| Phase | Techniques | Documentation |
|-------|------------|---------------|
| [Reconnaissance](offensive-security/reconnaissance.md) | OSINT, Footprinting | [Docs](offensive-security/reconnaissance.md) |
| [Scanning](offensive-security/scanning.md) | Port/Vuln Scanning | [Docs](offensive-security/scanning.md) |
| [Exploitation](offensive-security/exploitation.md) | CVE, 0-day, Misconfig | [Docs](offensive-security/exploitation.md) |
| [Post-Exploitation](offensive-security/post-exploitation.md) | Lateral Movement, Persistence | [Docs](offensive-security/post-exploitation.md) |
| [Privilege Escalation](offensive-security/privilege-escalation.md) | Linux/Windows PrivEsc | [Docs](offensive-security/privilege-escalation.md) |
| [Web Application](offensive-security/web-attacks.md) | SQLi, XSS, SSRF, RCE | [Docs](offensive-security/web-attacks.md) |
| [Active Directory](offensive-security/active-directory.md) | Kerberoasting, DCSync | [Docs](offensive-security/active-directory.md) |
| [Cloud Attacks](offensive-security/cloud-attacks.md) | AWS/Azure/GCP Exploitation | [Docs](offensive-security/cloud-attacks.md) |

### Attack Chain Visualization

```
                               CYBER KILL CHAIN
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                                                                             │
    │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
    │  │  RECON  │─>│WEAPONIZ │─>│DELIVERY │─>│EXPLOITA │─>│INSTALLA │           │
    │  │         │  │  ATION  │  │         │  │  TION   │  │  TION   │           │
    │  │ Target  │  │ Craft   │  │ Phish   │  │ Trigger │  │ RAT     │           │
    │  │ Research│  │ Payload │  │ Watering│  │ Vuln    │  │ Webshell│           │
    │  │ OSINT   │  │ Exploit │  │ USB     │  │ Execute │  │ Implant │           │
    │  └─────────┘  └─────────┘  └─────────┘  └─────────┘  └────┬────┘           │
    │                                                           │                 │
    │                                                           v                 │
    │                          ┌─────────┐           ┌─────────────────┐          │
    │                          │ ACTIONS │◄──────────│   COMMAND &     │          │
    │                          │   ON    │           │    CONTROL      │          │
    │                          │OBJECTIVES│           │                 │          │
    │                          │         │           │ Beaconing       │          │
    │                          │ Exfil   │           │ Tunneling       │          │
    │                          │ Destroy │           │ C2 Frameworks   │          │
    │                          │ Encrypt │           │                 │          │
    │                          └─────────┘           └─────────────────┘          │
    │                                                                             │
    │  DEFENDER OPPORTUNITIES:                                                    │
    │  ─────────────────────────                                                  │
    │  DETECT    DENY    DISRUPT    DEGRADE    DECEIVE    DESTROY                │
    │                                                                             │
    └─────────────────────────────────────────────────────────────────────────────┘
```

---

## Defensive Security

### SOC Architecture

| Component | Purpose | Documentation |
|-----------|---------|---------------|
| [SIEM Architecture](defensive-security/siem.md) | Log aggregation & correlation | [Docs](defensive-security/siem.md) |
| [EDR/XDR](defensive-security/edr-xdr.md) | Endpoint detection & response | [Docs](defensive-security/edr-xdr.md) |
| [SOAR](defensive-security/soar.md) | Security orchestration | [Docs](defensive-security/soar.md) |
| [Threat Intelligence](defensive-security/threat-intel.md) | IOC management | [Docs](defensive-security/threat-intel.md) |
| [Network Security](defensive-security/network-security.md) | IDS/IPS, NDR, Firewall | [Docs](defensive-security/network-security.md) |
| [Detection Engineering](defensive-security/detection-engineering.md) | SIGMA rules, YARA | [Docs](defensive-security/detection-engineering.md) |
| [Vulnerability Management](defensive-security/vuln-management.md) | Scanning, prioritization | [Docs](defensive-security/vuln-management.md) |
| [Security Monitoring](defensive-security/monitoring.md) | 24/7 SOC operations | [Docs](defensive-security/monitoring.md) |

### Defense in Depth Architecture

```
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                       DEFENSE IN DEPTH                                      │
    │                                                                             │
    │  ┌─────────────────────────────────────────────────────────────────────┐   │
    │  │                      PERIMETER SECURITY                              │   │
    │  │  WAF │ DDoS Protection │ CDN │ DNS Security │ Email Gateway         │   │
    │  └─────────────────────────────────────────────────────────────────────┘   │
    │                                    │                                        │
    │  ┌─────────────────────────────────▼───────────────────────────────────┐   │
    │  │                      NETWORK SECURITY                                │   │
    │  │  Firewall │ IDS/IPS │ NDR │ Network Segmentation │ VPN │ Zero Trust │   │
    │  └─────────────────────────────────────────────────────────────────────┘   │
    │                                    │                                        │
    │  ┌─────────────────────────────────▼───────────────────────────────────┐   │
    │  │                      ENDPOINT SECURITY                               │   │
    │  │  EDR │ AV │ Host Firewall │ DLP │ Device Control │ Patch Mgmt       │   │
    │  └─────────────────────────────────────────────────────────────────────┘   │
    │                                    │                                        │
    │  ┌─────────────────────────────────▼───────────────────────────────────┐   │
    │  │                      APPLICATION SECURITY                            │   │
    │  │  SAST │ DAST │ IAST │ SCA │ Container Security │ API Security       │   │
    │  └─────────────────────────────────────────────────────────────────────┘   │
    │                                    │                                        │
    │  ┌─────────────────────────────────▼───────────────────────────────────┐   │
    │  │                      DATA SECURITY                                   │   │
    │  │  Encryption │ DLP │ CASB │ Rights Management │ Backup │ Key Mgmt    │   │
    │  └─────────────────────────────────────────────────────────────────────┘   │
    │                                    │                                        │
    │  ┌─────────────────────────────────▼───────────────────────────────────┐   │
    │  │                      IDENTITY SECURITY                               │   │
    │  │  IAM │ MFA │ PAM │ SSO │ Identity Governance │ CIEM                 │   │
    │  └─────────────────────────────────────────────────────────────────────┘   │
    │                                                                             │
    │  ┌─────────────────────────────────────────────────────────────────────┐   │
    │  │                 SECURITY OPERATIONS (SOC)                            │   │
    │  │  SIEM │ SOAR │ Threat Intel │ Threat Hunting │ IR │ Forensics       │   │
    │  └─────────────────────────────────────────────────────────────────────┘   │
    │                                                                             │
    └─────────────────────────────────────────────────────────────────────────────┘
```

---

## Cloud Security

### AWS Security Architecture

| Component | Purpose | Documentation | Terraform |
|-----------|---------|---------------|-----------|
| [AWS Security Hub](cloud-security/aws/security-hub.md) | Central security view | [Docs](cloud-security/aws/security-hub.md) | [Code](terraform/aws/security-hub/) |
| [GuardDuty](cloud-security/aws/guardduty.md) | Threat detection | [Docs](cloud-security/aws/guardduty.md) | [Code](terraform/aws/guardduty/) |
| [WAF & Shield](cloud-security/aws/waf-shield.md) | Web & DDoS protection | [Docs](cloud-security/aws/waf-shield.md) | [Code](terraform/aws/waf/) |
| [IAM & Organizations](cloud-security/aws/iam.md) | Identity management | [Docs](cloud-security/aws/iam.md) | [Code](terraform/aws/identity/) |
| [CloudTrail & Config](cloud-security/aws/audit.md) | Audit & compliance | [Docs](cloud-security/aws/audit.md) | [Code](terraform/aws/logging/) |
| [KMS & Secrets](cloud-security/aws/encryption.md) | Data protection | [Docs](cloud-security/aws/encryption.md) | [Code](terraform/aws/secrets/) |
| [VPC Security](cloud-security/aws/vpc.md) | Network security | [Docs](cloud-security/aws/vpc.md) | [Code](terraform/aws/network/) |
| [Container Security](cloud-security/aws/container.md) | EKS/ECS security | [Docs](cloud-security/aws/container.md) | [Code](terraform/aws/container/) |

### AWS Security Reference Architecture

```
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                    AWS SECURITY REFERENCE ARCHITECTURE                      │
    │                                                                             │
    │  ┌─────────────────────────────────────────────────────────────────────┐   │
    │  │                         MANAGEMENT ACCOUNT                           │   │
    │  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐         │   │
    │  │  │    AWS    │  │   AWS     │  │ Control   │  │  Service  │         │   │
    │  │  │   Orgs    │  │  Config   │  │  Tower    │  │  Catalog  │         │   │
    │  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘         │   │
    │  └─────────────────────────────────────────────────────────────────────┘   │
    │                                    │                                        │
    │                    ┌───────────────┼───────────────┐                        │
    │                    │               │               │                        │
    │                    v               v               v                        │
    │  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐ │
    │  │   SECURITY ACCOUNT  │  │    LOG ARCHIVE      │  │   SHARED SERVICES   │ │
    │  │                     │  │                     │  │                     │ │
    │  │  ┌───────────────┐  │  │  ┌───────────────┐  │  │  ┌───────────────┐  │ │
    │  │  │ Security Hub  │  │  │  │  CloudTrail   │  │  │  │  Transit GW   │  │ │
    │  │  │ GuardDuty     │  │  │  │  S3 Logs      │  │  │  │  DNS          │  │ │
    │  │  │ Detective     │  │  │  │  VPC Flow     │  │  │  │  Directory    │  │ │
    │  │  │ IAM Analyzer  │  │  │  │  Config       │  │  │  │  PKI          │  │ │
    │  │  │ Macie         │  │  │  │  GuardDuty    │  │  │  │               │  │ │
    │  │  └───────────────┘  │  │  └───────────────┘  │  │  └───────────────┘  │ │
    │  └─────────────────────┘  └─────────────────────┘  └─────────────────────┘ │
    │                                    │                                        │
    │           ┌────────────────────────┴────────────────────────┐               │
    │           │                        │                        │               │
    │           v                        v                        v               │
    │  ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐     │
    │  │   PRODUCTION    │      │    STAGING      │      │   DEVELOPMENT   │     │
    │  │                 │      │                 │      │                 │     │
    │  │  ┌───────────┐  │      │  ┌───────────┐  │      │  ┌───────────┐  │     │
    │  │  │    VPC    │  │      │  │    VPC    │  │      │  │    VPC    │  │     │
    │  │  │   WAF     │  │      │  │   WAF     │  │      │  │   WAF     │  │     │
    │  │  │   KMS     │  │      │  │   KMS     │  │      │  │   KMS     │  │     │
    │  │  │ Secrets   │  │      │  │ Secrets   │  │      │  │ Secrets   │  │     │
    │  │  └───────────┘  │      │  └───────────┘  │      │  └───────────┘  │     │
    │  └─────────────────┘      └─────────────────┘      └─────────────────┘     │
    │                                                                             │
    └─────────────────────────────────────────────────────────────────────────────┘
```

---

## Infrastructure as Code

### Terraform Security Modules

```
terraform/
├── aws/
│   ├── security-hub/          # Centralized security management
│   ├── guardduty/             # Threat detection
│   ├── waf/                   # Web application firewall
│   ├── identity/              # IAM, SSO, Organizations
│   ├── network/               # VPC, Security Groups, NACLs
│   ├── secrets/               # Secrets Manager, KMS
│   ├── logging/               # CloudTrail, Config, VPC Flow
│   ├── compliance/            # Config Rules, Security Hub Standards
│   ├── container/             # EKS security, ECR scanning
│   └── siem/                  # SIEM integration, log forwarding
│
├── azure/
│   ├── sentinel/              # Azure Sentinel SIEM
│   ├── defender/              # Microsoft Defender
│   ├── identity/              # Azure AD, PIM
│   └── network/               # NSG, Azure Firewall
│
└── shared/
    ├── detection-rules/       # SIGMA rules
    ├── response-playbooks/    # SOAR playbooks
    └── compliance-policies/   # OPA policies
```

---

## Compliance

### Compliance Framework Mapping

| Standard | Focus | Documentation |
|----------|-------|---------------|
| [SOC 2 Type II](compliance/soc2.md) | Service Organizations | [Docs](compliance/soc2.md) |
| [PCI-DSS v4.0](compliance/pci-dss.md) | Payment Card Industry | [Docs](compliance/pci-dss.md) |
| [HIPAA](compliance/hipaa.md) | Healthcare | [Docs](compliance/hipaa.md) |
| [GDPR](compliance/gdpr.md) | EU Data Protection | [Docs](compliance/gdpr.md) |
| [ISO 27001](compliance/iso27001.md) | Information Security | [Docs](compliance/iso27001.md) |
| [FedRAMP](compliance/fedramp.md) | Federal Cloud | [Docs](compliance/fedramp.md) |
| [NIST 800-53](compliance/nist-800-53.md) | Federal Systems | [Docs](compliance/nist-800-53.md) |
| [CIS Benchmarks](compliance/cis-benchmarks.md) | Configuration Standards | [Docs](compliance/cis-benchmarks.md) |

---

## Security Metrics

### Key Security Indicators

| Category | Metric | Target | Alert |
|----------|--------|--------|-------|
| Detection | MTTD (Mean Time to Detect) | < 1 hour | > 4 hours |
| Response | MTTR (Mean Time to Respond) | < 4 hours | > 24 hours |
| Vulnerability | Critical Vulns Open | 0 | > 0 |
| Vulnerability | High Vulns Open > 30 days | < 5 | > 10 |
| Compliance | Control Coverage | > 95% | < 90% |
| Phishing | Click Rate | < 3% | > 5% |
| Patching | Critical Patch SLA | < 72 hours | > 7 days |
| Identity | MFA Coverage | 100% | < 95% |

---

## Checklists

| Checklist | Use Case | Documentation |
|-----------|----------|---------------|
| [Security Assessment](checklists/security-assessment.md) | Initial security review | [Docs](checklists/security-assessment.md) |
| [Cloud Security](checklists/cloud-security.md) | AWS/Azure/GCP audit | [Docs](checklists/cloud-security.md) |
| [Web Application](checklists/web-app.md) | OWASP-based review | [Docs](checklists/web-app.md) |
| [Kubernetes](checklists/kubernetes.md) | K8s security hardening | [Docs](checklists/kubernetes.md) |
| [Incident Response](checklists/incident-response.md) | IR readiness | [Docs](checklists/incident-response.md) |
| [Vendor Security](checklists/vendor-security.md) | Third-party assessment | [Docs](checklists/vendor-security.md) |

---

## Tools Reference

### Security Tool Categories

| Category | Open Source | Commercial |
|----------|-------------|------------|
| SIEM | Wazuh, Graylog, ELK | Splunk, QRadar, Sentinel |
| EDR | Velociraptor, OSSEC | CrowdStrike, SentinelOne |
| Vuln Scan | OpenVAS, Nuclei | Nessus, Qualys |
| DAST | ZAP, Nikto | Burp Suite, Acunetix |
| SAST | Semgrep, SonarQube | Checkmarx, Veracode |
| Container | Trivy, Falco | Aqua, Prisma Cloud |

---

## Contributing

Contributions are welcome. Please review the [contribution guidelines](CONTRIBUTING.md) before submitting.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

Maintained by [Richard](https://github.com/Richardmsbr)
