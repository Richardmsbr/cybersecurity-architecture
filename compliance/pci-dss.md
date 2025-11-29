# PCI-DSS v4.0 Compliance Guide

## Overview

PCI-DSS (Payment Card Industry Data Security Standard) applies to any organization that handles credit card data.

---

## 12 Requirements Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PCI-DSS REQUIREMENTS                                 │
│                                                                             │
│  BUILD & MAINTAIN SECURE NETWORK                                            │
│  1. Install and maintain network security controls                          │
│  2. Apply secure configurations to all system components                    │
│                                                                             │
│  PROTECT ACCOUNT DATA                                                       │
│  3. Protect stored account data                                             │
│  4. Protect cardholder data with strong cryptography during transmission    │
│                                                                             │
│  MAINTAIN VULNERABILITY MANAGEMENT PROGRAM                                  │
│  5. Protect all systems and networks from malicious software                │
│  6. Develop and maintain secure systems and software                        │
│                                                                             │
│  IMPLEMENT STRONG ACCESS CONTROL                                            │
│  7. Restrict access to system components by business need to know           │
│  8. Identify users and authenticate access to system components             │
│  9. Restrict physical access to cardholder data                             │
│                                                                             │
│  REGULARLY MONITOR AND TEST NETWORKS                                        │
│  10. Log and monitor all access to system components and cardholder data    │
│  11. Test security of systems and networks regularly                        │
│                                                                             │
│  MAINTAIN INFORMATION SECURITY POLICY                                       │
│  12. Support information security with organizational policies/programs     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Requirements

### Requirement 3: Protect Stored Data

| Control | Description |
|---------|-------------|
| 3.3.1 | SAD not stored after authorization |
| 3.4.1 | PAN rendered unreadable (encryption, hashing, truncation) |
| 3.5.1 | Encryption key management documented |
| 3.6.1 | Key encryption keys stored securely |

### Requirement 8: Authentication

| Control | Description |
|---------|-------------|
| 8.2.1 | Unique user IDs |
| 8.3.1 | MFA for admin access to CDE |
| 8.3.2 | MFA for remote access |
| 8.3.6 | Password requirements (12+ characters) |

### Requirement 11: Testing

| Control | Description | Frequency |
|---------|-------------|-----------|
| 11.3.1 | Internal vulnerability scans | Quarterly |
| 11.3.2 | External ASV scans | Quarterly |
| 11.4.1 | External penetration testing | Annual |
| 11.4.2 | Internal penetration testing | Annual |

---

## Scope Reduction

### Segmentation
- Isolate CDE from rest of network
- Use firewalls/ACLs to restrict access
- Document all connections

### Tokenization
- Replace PAN with token
- Token cannot be reversed
- Reduces systems in scope

### P2PE
- Point-to-Point Encryption
- Hardware-based encryption at terminal
- Reduces merchant scope significantly

---

## Evidence Checklist

```
NETWORK SECURITY:
□ Network diagrams (current within 6 months)
□ Firewall ruleset documentation
□ Firewall change management records

DATA PROTECTION:
□ Data flow diagrams
□ Encryption key management procedures
□ Key rotation records

ACCESS CONTROL:
□ User access list
□ Access review documentation
□ MFA configuration evidence

MONITORING:
□ Audit log samples
□ Log review procedures
□ Alerting configuration

TESTING:
□ ASV scan reports (4 quarters)
□ Penetration test report
□ Vulnerability scan reports

POLICIES:
□ Information security policy
□ Acceptable use policy
□ Incident response plan
```

---

## References

- [PCI SSC](https://www.pcisecuritystandards.org/)
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library/)
