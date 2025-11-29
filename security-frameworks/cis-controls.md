# CIS Critical Security Controls

The CIS Critical Security Controls (CIS Controls) are a prioritized set of actions that collectively form a defense-in-depth set of best practices that mitigate the most common attacks against systems and networks.

---

## Overview

The CIS Controls v8 consists of 18 controls organized into three Implementation Groups (IGs) based on organizational risk profile and resources.

```
    CIS CONTROLS STRUCTURE

    Implementation Group 1 (IG1) - Essential Cyber Hygiene
    +-----------------------------------------------------------+
    | Basic controls for all organizations                       |
    | 56 Safeguards                                              |
    +-----------------------------------------------------------+

    Implementation Group 2 (IG2) - Foundational
    +-----------------------------------------------------------+
    | IG1 + additional controls for sensitive data               |
    | 74 additional Safeguards (130 total)                       |
    +-----------------------------------------------------------+

    Implementation Group 3 (IG3) - Organizational
    +-----------------------------------------------------------+
    | IG1 + IG2 + advanced controls for critical assets          |
    | 23 additional Safeguards (153 total)                       |
    +-----------------------------------------------------------+
```

---

## Control 1: Inventory and Control of Enterprise Assets

Actively manage all enterprise assets connected to the infrastructure physically, virtually, remotely, and in cloud environments.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 1.1 | Establish asset inventory | X | X | X |
| 1.2 | Address unauthorized assets | X | X | X |
| 1.3 | Utilize DHCP logging | | X | X |
| 1.4 | Use dynamic host discovery | | X | X |
| 1.5 | Use passive asset discovery | | | X |

### Implementation

```
Asset Management Architecture:

    +------------------+
    |  Discovery Tools |
    +--------+---------+
             |
    +--------v---------+
    |      CMDB        |
    +--------+---------+
             |
    +--------v---------+
    | Asset Inventory  |
    | - Hardware       |
    | - Software       |
    | - Cloud          |
    | - Virtual        |
    +------------------+
```

---

## Control 2: Inventory and Control of Software Assets

Actively manage all software on the network so only authorized software is installed and can execute.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 2.1 | Establish software inventory | X | X | X |
| 2.2 | Ensure authorized software | X | X | X |
| 2.3 | Address unauthorized software | X | X | X |
| 2.4 | Utilize automated inventory | | X | X |
| 2.5 | Allowlist authorized software | | X | X |
| 2.6 | Allowlist authorized libraries | | X | X |
| 2.7 | Allowlist authorized scripts | | | X |

---

## Control 3: Data Protection

Develop processes and technical controls to identify, classify, handle, retain, and dispose of data.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 3.1 | Establish data management process | X | X | X |
| 3.2 | Establish data inventory | X | X | X |
| 3.3 | Configure data access control | X | X | X |
| 3.4 | Enforce data retention | X | X | X |
| 3.5 | Securely dispose of data | X | X | X |
| 3.6 | Encrypt data on end-user devices | X | X | X |
| 3.7 | Establish data classification | | X | X |
| 3.8 | Document data flows | | X | X |
| 3.9 | Encrypt data on removable media | | X | X |
| 3.10 | Encrypt sensitive data in transit | | X | X |
| 3.11 | Encrypt sensitive data at rest | | X | X |
| 3.12 | Segment data processing | | X | X |
| 3.13 | Deploy DLP solution | | | X |
| 3.14 | Log sensitive data access | | | X |

### Data Classification Matrix

| Level | Description | Examples | Controls |
|-------|-------------|----------|----------|
| Public | No restrictions | Marketing materials | None |
| Internal | Business use only | Internal docs | Access control |
| Confidential | Restricted access | Financial data | Encryption, DLP |
| Restricted | Highly sensitive | PII, PHI | Encryption, MFA, audit |

---

## Control 4: Secure Configuration of Enterprise Assets and Software

Establish and maintain secure configurations for enterprise assets and software.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 4.1 | Establish secure configuration process | X | X | X |
| 4.2 | Establish secure configuration for network | X | X | X |
| 4.3 | Configure automatic session locking | X | X | X |
| 4.4 | Implement and manage firewall | X | X | X |
| 4.5 | Implement and manage anti-malware | X | X | X |
| 4.6 | Securely manage assets and software | X | X | X |
| 4.7 | Manage default accounts | X | X | X |
| 4.8 | Uninstall unused services | | X | X |
| 4.9 | Configure DNS-over-HTTPS | | X | X |
| 4.10 | Enforce automatic device lockout | | X | X |
| 4.11 | Enforce remote wipe capability | | X | X |
| 4.12 | Separate enterprise workspaces | | X | X |

---

## Control 5: Account Management

Use processes and tools to assign and manage authorization to credentials and assets.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 5.1 | Establish account inventory | X | X | X |
| 5.2 | Use unique passwords | X | X | X |
| 5.3 | Disable dormant accounts | X | X | X |
| 5.4 | Restrict administrator privileges | X | X | X |
| 5.5 | Establish account management process | | X | X |
| 5.6 | Centralize account management | | X | X |

---

## Control 6: Access Control Management

Use processes and tools to create, assign, manage, and revoke access credentials and privileges.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 6.1 | Establish access granting process | X | X | X |
| 6.2 | Establish access revoking process | X | X | X |
| 6.3 | Require MFA for externally-exposed apps | X | X | X |
| 6.4 | Require MFA for remote access | X | X | X |
| 6.5 | Require MFA for admin access | X | X | X |
| 6.6 | Establish access review process | | X | X |
| 6.7 | Centralize access control | | X | X |
| 6.8 | Define role-based access control | | X | X |

### Access Control Architecture

```
    ACCESS MANAGEMENT FLOW

    User Request
         |
         v
    +----------+     +----------+     +----------+
    | Identity |---->| AuthN    |---->| AuthZ    |
    | Verify   |     | (MFA)    |     | (RBAC)   |
    +----------+     +----------+     +----------+
                                           |
                                           v
                                    +----------+
                                    | Access   |
                                    | Granted/ |
                                    | Denied   |
                                    +----------+
```

---

## Control 7: Continuous Vulnerability Management

Develop a plan to continuously assess and track vulnerabilities on all enterprise assets.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 7.1 | Establish vulnerability management process | X | X | X |
| 7.2 | Establish remediation process | X | X | X |
| 7.3 | Perform automated OS patching | X | X | X |
| 7.4 | Perform automated application patching | X | X | X |
| 7.5 | Perform automated vulnerability scans | | X | X |
| 7.6 | Perform automated vulnerability scans (authenticated) | | X | X |
| 7.7 | Remediate detected vulnerabilities | | X | X |

### Vulnerability SLAs

| Severity | CVSS | Remediation SLA |
|----------|------|-----------------|
| Critical | 9.0-10.0 | 24-72 hours |
| High | 7.0-8.9 | 7 days |
| Medium | 4.0-6.9 | 30 days |
| Low | 0.1-3.9 | 90 days |

---

## Control 8: Audit Log Management

Collect, alert, review, and retain audit logs of events.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 8.1 | Establish audit log management process | X | X | X |
| 8.2 | Collect audit logs | X | X | X |
| 8.3 | Ensure adequate storage | X | X | X |
| 8.4 | Standardize time synchronization | | X | X |
| 8.5 | Collect detailed audit logs | | X | X |
| 8.6 | Collect DNS query logs | | X | X |
| 8.7 | Collect URL request logs | | X | X |
| 8.8 | Collect command-line audit logs | | X | X |
| 8.9 | Centralize audit logs | | X | X |
| 8.10 | Retain audit logs | | X | X |
| 8.11 | Conduct audit log reviews | | X | X |
| 8.12 | Collect service provider logs | | | X |

---

## Control 9: Email and Web Browser Protections

Improve protections and detections of threats from email and web vectors.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 9.1 | Ensure use of only fully supported browsers | X | X | X |
| 9.2 | Use DNS filtering services | X | X | X |
| 9.3 | Maintain URL filters | | X | X |
| 9.4 | Restrict browser extensions | | X | X |
| 9.5 | Implement DMARC | | X | X |
| 9.6 | Block unnecessary file types | | X | X |
| 9.7 | Deploy email server anti-malware | | X | X |

---

## Control 10: Malware Defenses

Prevent or control installation, spread, and execution of malicious applications.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 10.1 | Deploy anti-malware software | X | X | X |
| 10.2 | Configure automatic updates | X | X | X |
| 10.3 | Disable autorun | X | X | X |
| 10.4 | Configure automatic scanning | | X | X |
| 10.5 | Enable anti-exploitation features | | X | X |
| 10.6 | Centrally manage anti-malware | | X | X |
| 10.7 | Use behavior-based anti-malware | | | X |

---

## Control 11: Data Recovery

Establish and maintain data recovery practices.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 11.1 | Establish data recovery process | X | X | X |
| 11.2 | Perform automated backups | X | X | X |
| 11.3 | Protect recovery data | X | X | X |
| 11.4 | Establish isolated recovery environment | X | X | X |
| 11.5 | Test data recovery | | X | X |

---

## Control 12: Network Infrastructure Management

Establish and maintain management of network infrastructure.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 12.1 | Ensure network infrastructure is up-to-date | X | X | X |
| 12.2 | Establish secure network architecture | | X | X |
| 12.3 | Securely manage network infrastructure | | X | X |
| 12.4 | Establish private wireless networks | | X | X |
| 12.5 | Centralize network AAA | | X | X |
| 12.6 | Use dedicated admin workstations | | | X |
| 12.7 | Establish compute network segmentation | | | X |
| 12.8 | Establish application layer traffic filtering | | | X |

---

## Control 13: Network Monitoring and Defense

Operate processes and tooling to monitor and defend against network threats.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 13.1 | Centralize security event alerting | X | X | X |
| 13.2 | Deploy host-based IDS | | X | X |
| 13.3 | Deploy network-based IDS | | X | X |
| 13.4 | Perform traffic filtering at segment boundaries | | X | X |
| 13.5 | Manage access control for remote assets | | X | X |
| 13.6 | Collect network traffic flow logs | | X | X |
| 13.7 | Deploy host-based IPS | | | X |
| 13.8 | Deploy network-based IPS | | | X |
| 13.9 | Deploy port-level access control | | | X |
| 13.10 | Perform application layer filtering | | | X |
| 13.11 | Tune security event alerting thresholds | | | X |

---

## Control 14: Security Awareness and Skills Training

Establish and maintain a security awareness program.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 14.1 | Establish security awareness program | X | X | X |
| 14.2 | Train workforce on authentication | X | X | X |
| 14.3 | Train workforce on data handling | X | X | X |
| 14.4 | Train workforce to recognize attacks | X | X | X |
| 14.5 | Train workforce on causes of data exposure | X | X | X |
| 14.6 | Train workforce on recognizing social engineering | X | X | X |
| 14.7 | Train workforce on sensitive data handling | | X | X |
| 14.8 | Train workforce on reporting incidents | | X | X |
| 14.9 | Conduct role-specific security training | | X | X |

---

## Control 15: Service Provider Management

Develop a process to evaluate service providers.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 15.1 | Establish service provider inventory | X | X | X |
| 15.2 | Establish service provider management policy | | X | X |
| 15.3 | Classify service providers | | X | X |
| 15.4 | Ensure service provider contracts include security | | X | X |
| 15.5 | Assess service providers | | X | X |
| 15.6 | Monitor service providers | | | X |
| 15.7 | Securely decommission service providers | | | X |

---

## Control 16: Application Software Security

Manage the security life cycle of developed software.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 16.1 | Establish secure application development process | | X | X |
| 16.2 | Establish software security testing | | X | X |
| 16.3 | Perform root cause analysis | | X | X |
| 16.4 | Establish software component inventory | | X | X |
| 16.5 | Use current, trusted components | | X | X |
| 16.6 | Establish dedicated development environment | | X | X |
| 16.7 | Use secure coding standards | | X | X |
| 16.8 | Separate production and development | | X | X |
| 16.9 | Train developers in security | | X | X |
| 16.10 | Apply secure design principles | | X | X |
| 16.11 | Leverage vetted modules or services | | | X |
| 16.12 | Implement code-level security checks | | | X |
| 16.13 | Conduct application penetration testing | | | X |
| 16.14 | Conduct threat modeling | | | X |

---

## Control 17: Incident Response Management

Establish a program to develop and maintain incident response capability.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 17.1 | Designate personnel for incident handling | X | X | X |
| 17.2 | Establish incident reporting process | X | X | X |
| 17.3 | Establish incident response process | X | X | X |
| 17.4 | Establish incident response roles | | X | X |
| 17.5 | Assign key roles and responsibilities | | X | X |
| 17.6 | Define communication mechanisms | | X | X |
| 17.7 | Conduct routine incident response exercises | | X | X |
| 17.8 | Conduct post-incident reviews | | X | X |
| 17.9 | Establish security incident thresholds | | | X |

---

## Control 18: Penetration Testing

Test the effectiveness and resiliency of enterprise assets through penetration testing.

| Safeguard | Description | IG1 | IG2 | IG3 |
|-----------|-------------|-----|-----|-----|
| 18.1 | Establish penetration testing program | | | X |
| 18.2 | Perform periodic external penetration tests | | | X |
| 18.3 | Remediate penetration test findings | | | X |
| 18.4 | Validate security measures | | | X |
| 18.5 | Perform periodic internal penetration tests | | | X |

---

## Implementation Prioritization

```
IMPLEMENTATION PRIORITY MATRIX

    Priority 1 (Quick Wins):
    - Control 1: Asset Inventory
    - Control 2: Software Inventory
    - Control 4: Secure Configuration
    - Control 5: Account Management
    - Control 6: Access Control

    Priority 2 (Foundational):
    - Control 3: Data Protection
    - Control 7: Vulnerability Management
    - Control 8: Audit Logging
    - Control 10: Malware Defenses
    - Control 11: Data Recovery

    Priority 3 (Organizational):
    - Control 9: Email/Web Protections
    - Control 12: Network Management
    - Control 13: Network Monitoring
    - Control 14: Security Awareness
    - Control 17: Incident Response

    Priority 4 (Advanced):
    - Control 15: Service Provider Management
    - Control 16: Application Security
    - Control 18: Penetration Testing
```

---

## References

- CIS Controls v8
- CIS Benchmarks
- NIST Cybersecurity Framework Mapping

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
