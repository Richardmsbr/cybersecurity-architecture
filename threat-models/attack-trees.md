# Attack Trees

Attack trees provide a formal, methodical way of describing the security of systems based on varying attacks. They represent attacks against a system in a tree structure, with the goal as the root node and different ways of achieving that goal as leaf nodes.

---

## Overview

Attack trees were introduced by Bruce Schneier and have become a fundamental tool in security analysis. They help security teams understand potential attack paths and prioritize defensive measures.

```
    ATTACK TREE STRUCTURE

                    [GOAL]
                      |
           +----+----+----+----+
           |         |         |
        [AND]     [OR]      [OR]
           |         |         |
        +--+--+      |      +--+--+
        |     |      |      |     |
      [Sub]  [Sub] [Sub]  [Sub] [Sub]
      Goal   Goal  Goal   Goal  Goal
```

---

## Attack Tree Notation

### Node Types

| Symbol | Type | Description |
|--------|------|-------------|
| Rectangle | Goal/Sub-goal | Attack objective |
| AND | Conjunction | All child nodes required |
| OR | Disjunction | Any child node sufficient |
| Leaf | Action | Atomic attack step |

### Attribute Types

| Attribute | Description | Values |
|-----------|-------------|--------|
| Possible (P) | Is attack feasible? | Yes/No |
| Cost ($) | Resources required | Low/Medium/High |
| Time (T) | Duration to execute | Hours/Days/Weeks |
| Skill (S) | Technical expertise | Novice/Intermediate/Expert |
| Detection (D) | Likelihood of detection | Low/Medium/High |

---

## Attack Tree: Unauthorized Data Access

```
                     [Access Confidential Data]
                              |
            +-----------------+-----------------+
            |                 |                 |
         [OR]              [OR]              [OR]
            |                 |                 |
    [Exploit App        [Compromise       [Physical
     Vulnerability]      Credentials]       Access]
            |                 |                 |
    +-------+-------+    +----+----+      +----+----+
    |       |       |    |    |    |      |    |    |
  [SQLi] [RCE]  [SSRF] [Phish][BF][Leak] [Theft][Tail]

    Legend:
    SQLi = SQL Injection
    RCE = Remote Code Execution
    SSRF = Server-Side Request Forgery
    Phish = Phishing Attack
    BF = Brute Force
    Leak = Credential Leak
    Theft = Device Theft
    Tail = Tailgating
```

### Detailed Node Analysis

| Node | Cost | Time | Skill | Detection | Possible |
|------|------|------|-------|-----------|----------|
| SQL Injection | Low | Hours | Intermediate | Medium | Yes |
| Remote Code Execution | Medium | Days | Expert | Medium | Yes |
| SSRF | Low | Hours | Intermediate | Low | Yes |
| Phishing | Low | Days | Novice | Medium | Yes |
| Brute Force | Low | Days | Novice | High | Yes |
| Credential Leak | Low | Hours | Novice | Low | Yes |
| Device Theft | Medium | Hours | Novice | High | Yes |
| Tailgating | Low | Hours | Novice | Medium | Yes |

---

## Attack Tree: Account Takeover

```
                        [Account Takeover]
                               |
              +----------------+----------------+
              |                |                |
           [OR]             [OR]             [OR]
              |                |                |
      [Credential          [Session         [Identity
       Compromise]          Hijacking]       Fraud]
              |                |                |
      +-------+-------+   +----+----+     +----+----+
      |       |       |   |    |    |     |    |    |
              |           |              |    |
    [Phishing]          [XSS]          [Social
     |                   |              Engineering]
     +--+--+          +--+--+           |
     |     |          |     |        +--+--+
   [Spear][Mass]  [Stored][Refl]   [Help][Fake]
                                   [Desk][ID]

    +-------+-------+   +----+----+
    |       |       |   |    |    |
  [Cred  [Pass   [Key  [MITM][Cookie
   Stuff] Spray] logger]     Theft]
```

### Risk Scoring

| Attack Path | Likelihood | Impact | Risk Score |
|-------------|------------|--------|------------|
| Phishing > Credential Theft | High | High | Critical |
| XSS > Session Hijacking | Medium | High | High |
| Credential Stuffing | High | Medium | High |
| Social Engineering | Medium | High | High |
| MITM Attack | Low | High | Medium |
| Keylogger | Low | Critical | High |

---

## Attack Tree: Ransomware Deployment

```
                    [Deploy Ransomware]
                           |
          +----------------+----------------+
          |                |                |
       [AND]            [AND]            [OR]
          |                |                |
    [Initial         [Establish      [Execute
     Access]          Persistence]    Payload]
          |                |                |
    +-----+-----+    +-----+-----+    +-----+-----+
    |     |     |    |     |     |    |     |     |
  [Phish][RDP] [VPN][Sched][Reg] [Svc][Manual][Auto]
         Brute  Vuln Task  Key  Acct  Trigger Spread

    Initial Access Methods:
    - Phishing with malicious attachment
    - RDP brute force (exposed port 3389)
    - VPN vulnerability exploitation

    Persistence Mechanisms:
    - Scheduled task creation
    - Registry run key modification
    - Service account creation

    Execution Methods:
    - Manual trigger by attacker
    - Automated lateral spread
```

### Attack Path Probabilities

| Path | Probability | Controls Required |
|------|-------------|-------------------|
| Phishing > Scheduled Task > Auto Spread | 35% | Email Security, EDR, Segmentation |
| RDP Brute > Registry Key > Manual | 25% | MFA, Account Lockout, PAM |
| VPN Vuln > Service Account > Auto Spread | 15% | Patch Management, PAM, Segmentation |

---

## Attack Tree: Privilege Escalation

```
                   [Gain Admin Privileges]
                            |
           +----------------+----------------+
           |                |                |
        [OR]             [OR]             [OR]
           |                |                |
    [Exploit Local    [Abuse            [Credential
     Vulnerability]    Misconfig]         Theft]
           |                |                |
    +------+------+   +-----+-----+    +-----+-----+
    |      |      |   |     |     |    |     |     |
  [Kernel][App]      [SUID][Sudo] [Pass[Kerb] [Hash
   Exploit Vuln       Bit  Misconf  File roast  Dump]
           |
    +------+------+
    |      |      |
  [Buffer][Use   [Race
   Over]  After  Cond]
          Free]
```

### Linux Privilege Escalation Paths

| Technique | MITRE ID | Difficulty | Detection |
|-----------|----------|------------|-----------|
| SUID Binary Exploitation | T1548.001 | Medium | Low |
| Sudo Misconfiguration | T1548.003 | Low | Medium |
| Kernel Exploit | T1068 | High | Low |
| Cron Job Abuse | T1053.003 | Medium | Medium |
| PATH Hijacking | T1574.007 | Medium | Low |

### Windows Privilege Escalation Paths

| Technique | MITRE ID | Difficulty | Detection |
|-----------|----------|------------|-----------|
| Unquoted Service Path | T1574.009 | Low | Medium |
| DLL Hijacking | T1574.001 | Medium | Low |
| Token Impersonation | T1134.001 | Medium | Medium |
| UAC Bypass | T1548.002 | Medium | Medium |
| Kerberoasting | T1558.003 | Low | High |

---

## Attack Tree: Data Exfiltration

```
                    [Exfiltrate Data]
                           |
          +----------------+----------------+
          |                |                |
       [AND]            [OR]             [OR]
          |                |                |
    [Identify         [Transfer        [Evade
     Target Data]      Method]          Detection]
          |                |                |
    +-----+-----+    +-----+-----+    +-----+-----+
    |     |     |    |     |     |    |     |     |
  [Query][File][API][HTTP][DNS] [USB][Encrypt][Chunk]
   DB    Search      Tunnel Tunnel     Data   Data

    Data Identification:
    - Database queries for PII
    - File system search for sensitive docs
    - API enumeration for data access

    Transfer Methods:
    - HTTP/HTTPS to external server
    - DNS tunneling (slow but stealthy)
    - Physical USB exfiltration

    Evasion Techniques:
    - Encrypt data before transfer
    - Chunk data into small pieces
```

### Exfiltration Channel Analysis

| Channel | Bandwidth | Stealth | Complexity |
|---------|-----------|---------|------------|
| HTTPS (Port 443) | High | Medium | Low |
| DNS Tunneling | Low | High | High |
| ICMP Tunneling | Low | High | High |
| Steganography | Low | Very High | High |
| Cloud Storage | High | Medium | Low |
| Email | Medium | Low | Low |

---

## Attack Tree: Supply Chain Attack

```
                  [Compromise Supply Chain]
                            |
           +----------------+----------------+
           |                |                |
        [OR]             [OR]             [OR]
           |                |                |
    [Compromise       [Inject         [Compromise
     Vendor]           Malicious       Distribution]
           |           Code]                |
    +------+------+      |           +------+------+
    |      |      |   +--+--+        |      |      |
  [Breach][BEC] [Cred|Open |Closed  [CDN]  [Repo] [PKI]
   Vendor  Attack Theft|Source|Source Poison Poison Compro
                      |Lib   |Lib
                      |      |
                   +--+--+ +--+--+
                   |     | |     |
                 [Typo][Dep][Build][Code
                  squat]Conf Inject Review
                              Bypass
```

### Supply Chain Attack Vectors

| Vector | Example | Impact | Detection Difficulty |
|--------|---------|--------|---------------------|
| Dependency Confusion | Private package name collision | High | Medium |
| Typosquatting | Malicious npm package | High | Low |
| Compromised Build System | SolarWinds | Critical | Very High |
| Malicious Update | NotPetya | Critical | High |
| Compromised Code Signing | Stolen certificates | Critical | High |

---

## Attack Tree Metrics

### DREAD Risk Assessment

| Factor | Description | Score Range |
|--------|-------------|-------------|
| Damage | Potential harm | 1-10 |
| Reproducibility | Ease of reproduction | 1-10 |
| Exploitability | Skill required | 1-10 |
| Affected Users | Scope of impact | 1-10 |
| Discoverability | Ease of finding | 1-10 |

### Calculation Formula

```
DREAD Score = (D + R + E + A + D) / 5

Risk Levels:
- 1-3: Low Risk
- 4-6: Medium Risk
- 7-8: High Risk
- 9-10: Critical Risk
```

---

## Creating Attack Trees

### Process

1. **Define the Root Goal**: What is the attacker trying to achieve?
2. **Decompose into Sub-goals**: Break down into smaller objectives
3. **Identify Attack Methods**: List ways to achieve each sub-goal
4. **Apply AND/OR Logic**: Determine relationships between nodes
5. **Assign Attributes**: Cost, time, skill, detection likelihood
6. **Calculate Risk**: Aggregate scores up the tree
7. **Identify Mitigations**: Map controls to attack paths

### Best Practices

| Practice | Description |
|----------|-------------|
| Start with known attacks | Base trees on real-world incidents |
| Involve diverse teams | Include developers, ops, security |
| Keep trees focused | One root goal per tree |
| Update regularly | Refresh as threats evolve |
| Validate with testing | Verify attack paths through pentesting |

---

## Tool Support

| Tool | Type | Features |
|------|------|----------|
| ADTool | Open Source | AND/OR trees, attribute calculation |
| SecuriTree | Commercial | Enterprise attack tree modeling |
| AttackTree+ | Commercial | Quantitative risk analysis |
| Draw.io | Open Source | Manual diagramming |
| PlantUML | Open Source | Text-based diagrams |

---

## References

- Bruce Schneier, "Attack Trees" (1999)
- NIST SP 800-154, "Guide to Data-Centric System Threat Modeling"
- OWASP Attack Tree Methodology
- MITRE ATT&CK Framework

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
